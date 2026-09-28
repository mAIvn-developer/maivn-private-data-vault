use std::{
    collections::BTreeMap,
    io::{ErrorKind, Read, Write},
    time::SystemTime,
};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    ContentKind, KeyVersion, Keyring, PurgeKeys, RecordIdentity, ReencryptCursor, ReencryptOutcome,
    StorageBackend, StorageError, VaultError, keyring::DerivedKeyring,
};

const VALUE_MAP_MAGIC_V1: &[u8; 8] = b"PDVMAP01";
const VALUE_MAP_MAGIC_V2: &[u8; 8] = b"PDVMAP02";
const DOCUMENT_MAGIC_V1: &[u8; 8] = b"PDVDOC01";
const DOCUMENT_MAGIC_V2: &[u8; 8] = b"PDVDOC02";
const NONCE_PREFIX_BYTES: usize = 19;
const KEY_VERSION_BYTES: usize = size_of::<u32>();
const GENERATION_BYTES: usize = size_of::<u64>();
const INITIAL_GENERATION: u64 = 1;
const VALUE_MAP_NONCE_DOMAIN: u8 = 2;
const DOCUMENT_CHUNK_BYTES: usize = 64 * 1024;
const TAG_BYTES: usize = 16;
const DATA_FRAME: u8 = 0;
const FINAL_FRAME: u8 = 1;
const CURSOR_MAC_DOMAIN: &[u8] = b"maivn-private-data-vault:reencrypt-cursor:v2";

/// Seals private material before handing it to a storage backend.
pub struct Vault<B> {
    backend: B,
    keys: DerivedKeyring,
    cursor_scope: [u8; 16],
}

impl<B> Vault<B> {
    /// Returns the storage backend this vault seals into.
    ///
    /// Exists for the managed exchange flow, where the caller hydrates a
    /// [`crate::MemoryBackend`] with previously exported sealed objects and
    /// extracts new ones for external persistence. The backend only ever
    /// holds ciphertext, so exposing it exposes nothing a database dump
    /// would not.
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

struct LoadedValueMap {
    values: SensitiveValueMap,
    version: KeyVersion,
}

struct SensitiveValueMap(BTreeMap<String, String>);

impl Drop for SensitiveValueMap {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

impl<B: StorageBackend> Vault<B> {
    /// Derives this process's encryption key from a caller-owned secret.
    ///
    /// Argon2id is used because it is memory-hard and balances side-channel
    /// resistance with resistance to GPU cracking. The configured 19 MiB,
    /// two-pass, single-lane cost follows the OWASP Argon2id baseline. This
    /// method does not own the caller's `secret`, so the caller remains
    /// responsible for zeroing that input buffer.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::InvalidSecret`] when `secret` is empty,
    /// [`VaultError::KeyDerivation`] when `Argon2id` derivation fails, or
    /// [`VaultError::Storage`] when backend metadata cannot be loaded.
    pub fn open(backend: B, secret: &[u8]) -> Result<Self, VaultError> {
        let version_one = KeyVersion::new(1)?;
        Self::open_keyring(backend, Keyring::new(version_one, secret)?)
    }

    /// Derives every configured encryption key and selects the active write key.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Storage`] when backend metadata cannot be read or
    /// [`VaultError::KeyDerivation`] when any configured secret cannot be
    /// derived.
    pub fn open_keyring(backend: B, keyring: Keyring) -> Result<Self, VaultError> {
        let salt = backend.key_derivation_salt()?;
        let keys = keyring.derive(&salt)?;
        Ok(Self {
            backend,
            keys,
            cursor_scope: salt,
        })
    }

    /// Encrypts and stores a small structured placeholder-to-value map.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when serialization, nonce reservation,
    /// encryption, or durable ciphertext storage fails.
    pub fn store_value_map(
        &self,
        identity: &RecordIdentity,
        values: &BTreeMap<String, String>,
    ) -> Result<(), VaultError> {
        let transaction = self
            .backend
            .begin_generation_transaction(&identity.record_key())?;
        if transaction.generation().is_some() {
            return Err(VaultError::AtomicWriteRequired);
        }
        self.store_legacy_value_map(identity, values)
    }

    /// Atomically merges caller-owned pairs into a standalone value-map record.
    ///
    /// The backend's exclusive record lock spans load, merge and durable save,
    /// including independent vault instances and processes. Existing record bundles
    /// require `store_record` and cannot be partially changed by this operation.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when authentication, sealing, storage or locking
    /// fails, or [`VaultError::AtomicWriteRequired`] for a versioned record bundle.
    pub fn merge_value_map(
        &self,
        identity: &RecordIdentity,
        values: &BTreeMap<String, String>,
    ) -> Result<(), VaultError> {
        let transaction = self
            .backend
            .begin_generation_transaction(&identity.record_key())?;
        if transaction.generation().is_some() {
            return Err(VaultError::AtomicWriteRequired);
        }
        let mut merged =
            SensitiveValueMap(match self.load_value_map_at_generation(identity, None) {
                Ok(stored) => stored,
                Err(VaultError::Storage(StorageError::NotFound)) => BTreeMap::new(),
                Err(error) => return Err(error),
            });
        for (key, value) in values {
            if let Some(mut previous) = merged.0.insert(key.clone(), value.clone()) {
                previous.zeroize();
            }
        }
        self.store_legacy_value_map(identity, &merged.0)
    }

    fn store_legacy_value_map(
        &self,
        identity: &RecordIdentity,
        values: &BTreeMap<String, String>,
    ) -> Result<(), VaultError> {
        let sealed = self.seal_value_map(
            &identity.record_key(),
            values,
            INITIAL_GENERATION,
            self.keys.active_version(),
        )?;
        self.backend
            .store_value_map(&identity.storage_key(ContentKind::ValueMap), &sealed)?;
        Ok(())
    }

    fn seal_value_map(
        &self,
        record_key: &[u8; 32],
        values: &BTreeMap<String, String>,
        generation: u64,
        version: KeyVersion,
    ) -> Result<Vec<u8>, VaultError> {
        let plaintext = Zeroizing::new(serde_json::to_vec(values)?);
        let prefix = self.backend.reserve_nonce_prefix()?;
        let nonce = value_map_nonce(&prefix);
        let aad = versioned_aad(record_key, ContentKind::ValueMap, version, generation);
        // XChaCha20-Poly1305 is a well-reviewed AEAD with a 192-bit nonce and
        // strong software performance on machines without AES acceleration.
        // Authentication covers both ciphertext and the canonical identity.
        let cipher = XChaCha20Poly1305::new(self.keys.key(version)?.as_bytes().into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::AuthenticationFailed)?;
        let mut sealed =
            Vec::with_capacity(VALUE_MAP_MAGIC_V2.len() + 12 + prefix.len() + ciphertext.len());
        sealed.extend_from_slice(VALUE_MAP_MAGIC_V2);
        sealed.extend_from_slice(&version.get().to_be_bytes());
        sealed.extend_from_slice(&generation.to_be_bytes());
        sealed.extend_from_slice(&prefix);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Loads, authenticates, and decodes a placeholder-to-value map.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::AuthenticationFailed`] for a wrong key, modified
    /// ciphertext, or identity mismatch. Storage, format, and decoding failures
    /// retain their other typed variants.
    pub fn load_value_map(
        &self,
        identity: &RecordIdentity,
    ) -> Result<BTreeMap<String, String>, VaultError> {
        let generation_guard = self.backend.begin_generation_read(&identity.record_key())?;
        let trusted_generation = generation_guard.generation();
        self.load_value_map_at_generation(identity, trusted_generation)
    }

    fn load_value_map_at_generation(
        &self,
        identity: &RecordIdentity,
        trusted_generation: Option<u64>,
    ) -> Result<BTreeMap<String, String>, VaultError> {
        let sealed = match trusted_generation {
            Some(generation) => self.backend.load_versioned_value_map(
                &identity.versioned_storage_key(ContentKind::ValueMap),
                generation,
            )?,
            None => self
                .backend
                .load_value_map(&identity.storage_key(ContentKind::ValueMap))?,
        };
        let envelope = parse_value_map(&sealed)?;
        verify_generation(trusted_generation, envelope.generation, envelope.legacy)?;
        let nonce = value_map_nonce(envelope.prefix);
        let aad = envelope_aad(identity, ContentKind::ValueMap, &envelope);
        let key = self.keys.key(envelope.version)?;
        let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: envelope.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| VaultError::AuthenticationFailed)?,
        );
        Ok(serde_json::from_slice(&plaintext)?)
    }

    fn ensure_compatibility_write(&self, identity: &RecordIdentity) -> Result<(), VaultError> {
        if self
            .backend
            .begin_generation_read(&identity.record_key())?
            .generation()
            .is_some()
        {
            return Err(VaultError::AtomicWriteRequired);
        }
        Ok(())
    }

    /// Encrypts a document incrementally in 64 KiB authenticated chunks.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the source cannot be read, a nonce cannot be
    /// reserved, encryption fails, the chunk counter is exhausted, or the
    /// backend cannot atomically commit the ciphertext stream.
    pub fn store_document<R: Read>(
        &self,
        identity: &RecordIdentity,
        source: &mut R,
    ) -> Result<(), VaultError> {
        self.ensure_compatibility_write(identity)?;
        self.store_streamed_content(
            identity,
            source,
            ContentKind::Document,
            None,
            self.keys.active_version(),
        )
    }

    /// Encrypts and stores an unredacted original as authenticated chunks.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] under the same conditions as
    /// [`Self::store_document`].
    pub fn store_original<R: Read>(
        &self,
        identity: &RecordIdentity,
        source: &mut R,
    ) -> Result<(), VaultError> {
        self.ensure_compatibility_write(identity)?;
        self.store_streamed_content(
            identity,
            source,
            ContentKind::Original,
            None,
            self.keys.active_version(),
        )
    }

    /// Atomically publishes an original, redacted document, and value map as
    /// one monotonically versioned record generation.
    ///
    /// Ciphertext objects are staged under the next generation while an
    /// exclusive backend transaction is held. The prior generation remains
    /// authoritative until the final compare-and-swap succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when reading, sealing, staging, or generation
    /// publication fails. A failed publication never changes the trusted
    /// generation.
    pub fn store_record<RO: Read, RD: Read>(
        &self,
        identity: &RecordIdentity,
        original: &mut RO,
        document: &mut RD,
        values: &BTreeMap<String, String>,
    ) -> Result<(), VaultError> {
        let record_key = identity.record_key();
        self.store_record_by_key(
            &record_key,
            original,
            document,
            values,
            self.keys.active_version(),
            false,
        )
    }

    /// Atomically replaces an existing complete record generation.
    ///
    /// Unlike [`Self::store_record`], this operation refuses while holding the
    /// exclusive generation transaction when the trusted generation is absent.
    /// No ciphertext is staged on that path, so a purge that commits first can
    /// never be followed by record recreation.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Storage`] wrapping [`StorageError::NotFound`] when
    /// no trusted generation exists. Other sealing, staging, and publication
    /// failures retain their typed variants.
    pub fn replace_record<RO: Read, RD: Read>(
        &self,
        identity: &RecordIdentity,
        original: &mut RO,
        document: &mut RD,
        values: &BTreeMap<String, String>,
    ) -> Result<(), VaultError> {
        let record_key = identity.record_key();
        self.store_record_by_key(
            &record_key,
            original,
            document,
            values,
            self.keys.active_version(),
            true,
        )
    }

    fn store_record_by_key<RO: Read, RD: Read>(
        &self,
        record_key: &[u8; 32],
        original: &mut RO,
        document: &mut RD,
        values: &BTreeMap<String, String>,
        version: KeyVersion,
        require_existing: bool,
    ) -> Result<(), VaultError> {
        let mut transaction = self.backend.begin_generation_transaction(record_key)?;
        let expected = transaction.generation();
        if require_existing && expected.is_none() {
            return Err(StorageError::NotFound.into());
        }
        let next = expected
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(VaultError::GenerationExhausted)?;
        self.stage_record_bundle(record_key, original, document, values, next, version)?;

        match transaction.compare_and_swap(expected, next) {
            Ok(()) => Ok(()),
            Err(StorageError::GenerationConflict) => Err(VaultError::GenerationConflict),
            Err(error) => Err(error.into()),
        }
    }

    fn stage_record_bundle<RO: Read, RD: Read>(
        &self,
        record_key: &[u8; 32],
        original: &mut RO,
        document: &mut RD,
        values: &BTreeMap<String, String>,
        generation: u64,
        version: KeyVersion,
    ) -> Result<(), VaultError> {
        let sealed_values = self.seal_value_map(record_key, values, generation, version)?;
        self.store_versioned_streamed_content_by_key(
            record_key,
            original,
            ContentKind::Original,
            generation,
            version,
        )?;
        self.store_versioned_streamed_content_by_key(
            record_key,
            document,
            ContentKind::Document,
            generation,
            version,
        )?;
        self.backend.store_versioned_value_map(
            &RecordIdentity::versioned_storage_key_for(record_key, ContentKind::ValueMap),
            generation,
            &sealed_values,
        )?;
        Ok(())
    }

    fn store_streamed_content<R: Read>(
        &self,
        identity: &RecordIdentity,
        source: &mut R,
        content_kind: ContentKind,
        committed_generation: Option<u64>,
        version: KeyVersion,
    ) -> Result<(), VaultError> {
        let prefix = self.backend.reserve_nonce_prefix()?;
        let generation = committed_generation.unwrap_or(INITIAL_GENERATION);
        let storage_key = match committed_generation {
            Some(_) => identity.versioned_storage_key(content_kind),
            None => identity.storage_key(content_kind),
        };
        let destination = match committed_generation {
            Some(generation) => self.backend.begin_versioned_content(
                &storage_key,
                &prefix,
                content_kind,
                generation,
            )?,
            None => self
                .backend
                .begin_content(&storage_key, &prefix, content_kind)?,
        };
        self.write_streamed_content(
            &identity.record_key(),
            source,
            content_kind,
            generation,
            version,
            destination,
            prefix,
        )
    }

    fn store_versioned_streamed_content_by_key<R: Read>(
        &self,
        record_key: &[u8; 32],
        source: &mut R,
        content_kind: ContentKind,
        generation: u64,
        version: KeyVersion,
    ) -> Result<(), VaultError> {
        let prefix = self.backend.reserve_nonce_prefix()?;
        let storage_key = RecordIdentity::versioned_storage_key_for(record_key, content_kind);
        let destination = self.backend.begin_versioned_content(
            &storage_key,
            &prefix,
            content_kind,
            generation,
        )?;
        self.write_streamed_content(
            record_key,
            source,
            content_kind,
            generation,
            version,
            destination,
            prefix,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn write_streamed_content<R: Read>(
        &self,
        record_key: &[u8; 32],
        source: &mut R,
        content_kind: ContentKind,
        generation: u64,
        version: KeyVersion,
        mut destination: Box<dyn crate::PendingDocument>,
        prefix: [u8; NONCE_PREFIX_BYTES],
    ) -> Result<(), VaultError> {
        write_backend(&mut destination, DOCUMENT_MAGIC_V2)?;
        write_backend(&mut destination, &version.get().to_be_bytes())?;
        write_backend(&mut destination, &generation.to_be_bytes())?;
        write_backend(&mut destination, &prefix)?;

        let cipher = XChaCha20Poly1305::new(self.keys.key(version)?.as_bytes().into());
        let base_aad = versioned_aad(record_key, content_kind, version, generation);
        let mut plaintext = Zeroizing::new(vec![0_u8; DOCUMENT_CHUNK_BYTES]);
        let mut chunk_index = 0_u32;
        loop {
            let length = read_source(source, &mut plaintext)?;
            if length == 0 {
                break;
            }
            let ciphertext = encrypt_document_frame(
                &cipher,
                &prefix,
                &base_aad,
                chunk_index,
                DATA_FRAME,
                &plaintext[..length],
            )?;
            write_frame(&mut destination, DATA_FRAME, &ciphertext)?;
            chunk_index = chunk_index
                .checked_add(1)
                .ok_or(VaultError::DocumentTooLarge)?;
        }

        let final_ciphertext =
            encrypt_document_frame(&cipher, &prefix, &base_aad, chunk_index, FINAL_FRAME, &[])?;
        write_frame(&mut destination, FINAL_FRAME, &final_ciphertext)?;
        destination.commit()?;
        Ok(())
    }

    /// Authenticates and streams a document to the caller-owned destination.
    ///
    /// A failure in a later chunk can occur after earlier authenticated chunks
    /// have been written. Callers needing all-or-nothing output should provide
    /// a transactional destination and commit it only after this returns `Ok`.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::AuthenticationFailed`] for a wrong key, modified
    /// frame, reordered frame, or identity mismatch. Malformed/truncated input,
    /// backend reads, destination writes, and counter exhaustion retain their
    /// other typed variants.
    pub fn load_document<W: Write>(
        &self,
        identity: &RecordIdentity,
        destination: &mut W,
    ) -> Result<(), VaultError> {
        self.load_streamed_content(identity, destination, ContentKind::Document)
    }

    /// Authenticates and streams an unredacted original to a caller-owned sink.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] under the same conditions as
    /// [`Self::load_document`].
    pub fn load_original<W: Write>(
        &self,
        identity: &RecordIdentity,
        destination: &mut W,
    ) -> Result<(), VaultError> {
        self.load_streamed_content(identity, destination, ContentKind::Original)
    }

    fn load_streamed_content<W: Write>(
        &self,
        identity: &RecordIdentity,
        destination: &mut W,
        content_kind: ContentKind,
    ) -> Result<(), VaultError> {
        let record_key = identity.record_key();
        let generation_guard = self.backend.begin_generation_read(&record_key)?;
        let trusted_generation = generation_guard.generation();
        let source = match trusted_generation {
            Some(generation) => self.backend.open_versioned_content(
                &identity.versioned_storage_key(content_kind),
                content_kind,
                generation,
            )?,
            None => self
                .backend
                .open_content(&identity.storage_key(content_kind), content_kind)?,
        };
        self.decrypt_streamed_content(
            &record_key,
            destination,
            content_kind,
            trusted_generation,
            Some(identity.associated_data(content_kind)),
            source,
        )?;
        Ok(())
    }

    fn decrypt_streamed_content<W: Write>(
        &self,
        record_key: &[u8; 32],
        destination: &mut W,
        content_kind: ContentKind,
        trusted_generation: Option<u64>,
        legacy_aad: Option<Vec<u8>>,
        mut source: Box<dyn Read + Send>,
    ) -> Result<KeyVersion, VaultError> {
        let header = read_stream_header(&mut source)?;
        verify_generation(trusted_generation, header.generation, header.legacy)?;
        let key = self.keys.key(header.version)?;
        let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
        let base_aad = if header.legacy {
            legacy_aad.ok_or(VaultError::InvalidFormat)?
        } else {
            versioned_aad(record_key, content_kind, header.version, header.generation)
        };
        let mut chunk_index = 0_u32;

        loop {
            let (kind, ciphertext) = read_frame(&mut source)?;
            let plaintext = Zeroizing::new(decrypt_document_frame(
                &cipher,
                &header.prefix,
                &base_aad,
                chunk_index,
                kind,
                &ciphertext,
            )?);
            match kind {
                DATA_FRAME => {
                    if plaintext.is_empty() {
                        return Err(VaultError::InvalidFormat);
                    }
                    destination
                        .write_all(&plaintext)
                        .map_err(VaultError::DocumentIo)?;
                    chunk_index = chunk_index
                        .checked_add(1)
                        .ok_or(VaultError::DocumentTooLarge)?;
                }
                FINAL_FRAME => {
                    if !plaintext.is_empty() || has_trailing_bytes(&mut source)? {
                        return Err(VaultError::InvalidFormat);
                    }
                    return Ok(header.version);
                }
                _ => return Err(VaultError::InvalidFormat),
            }
        }
    }

    fn load_versioned_value_map_by_key(
        &self,
        record_key: &[u8; 32],
        generation: u64,
    ) -> Result<LoadedValueMap, VaultError> {
        let sealed_values = self.backend.load_versioned_value_map(
            &RecordIdentity::versioned_storage_key_for(record_key, ContentKind::ValueMap),
            generation,
        )?;
        let envelope = parse_value_map(&sealed_values)?;
        verify_generation(Some(generation), envelope.generation, envelope.legacy)?;
        let nonce = value_map_nonce(envelope.prefix);
        let aad = versioned_aad(
            record_key,
            ContentKind::ValueMap,
            envelope.version,
            envelope.generation,
        );
        let cipher = XChaCha20Poly1305::new(self.keys.key(envelope.version)?.as_bytes().into());
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: envelope.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| VaultError::AuthenticationFailed)?,
        );
        let values = SensitiveValueMap(serde_json::from_slice(&plaintext)?);
        Ok(LoadedValueMap {
            values,
            version: envelope.version,
        })
    }

    fn load_versioned_streamed_content_by_key<W: Write>(
        &self,
        record_key: &[u8; 32],
        destination: &mut W,
        content_kind: ContentKind,
        generation: u64,
    ) -> Result<KeyVersion, VaultError> {
        let source = self.backend.open_versioned_content(
            &RecordIdentity::versioned_storage_key_for(record_key, content_kind),
            content_kind,
            generation,
        )?;
        self.decrypt_streamed_content(
            record_key,
            destination,
            content_kind,
            Some(generation),
            None,
            source,
        )
    }

    fn versioned_streamed_content_version_by_key(
        &self,
        record_key: &[u8; 32],
        content_kind: ContentKind,
        generation: u64,
    ) -> Result<KeyVersion, VaultError> {
        let mut source = self.backend.open_versioned_content(
            &RecordIdentity::versioned_storage_key_for(record_key, content_kind),
            content_kind,
            generation,
        )?;
        let header = read_stream_header(&mut source)?;
        verify_generation(Some(generation), header.generation, header.legacy)?;
        self.keys.key(header.version)?;
        Ok(header.version)
    }

    #[allow(clippy::too_many_arguments)]
    fn reencrypt_streamed_content_by_key(
        &self,
        record_key: &[u8; 32],
        content_kind: ContentKind,
        source_generation: u64,
        source_version: KeyVersion,
        target_generation: u64,
        target_version: KeyVersion,
    ) -> Result<(), VaultError> {
        let storage_key = RecordIdentity::versioned_storage_key_for(record_key, content_kind);
        let mut source =
            self.backend
                .open_versioned_content(&storage_key, content_kind, source_generation)?;
        let source_header = read_stream_header(&mut source)?;
        verify_generation(
            Some(source_generation),
            source_header.generation,
            source_header.legacy,
        )?;
        if source_header.version != source_version {
            return Err(VaultError::InconsistentRecordKeyVersions);
        }

        let target_prefix = self.backend.reserve_nonce_prefix()?;
        let mut destination = self.backend.begin_versioned_content(
            &storage_key,
            &target_prefix,
            content_kind,
            target_generation,
        )?;
        write_backend(&mut destination, DOCUMENT_MAGIC_V2)?;
        write_backend(&mut destination, &target_version.get().to_be_bytes())?;
        write_backend(&mut destination, &target_generation.to_be_bytes())?;
        write_backend(&mut destination, &target_prefix)?;

        let source_cipher =
            XChaCha20Poly1305::new(self.keys.key(source_header.version)?.as_bytes().into());
        let target_cipher =
            XChaCha20Poly1305::new(self.keys.key(target_version)?.as_bytes().into());
        let source_aad = versioned_aad(
            record_key,
            content_kind,
            source_header.version,
            source_generation,
        );
        let target_aad = versioned_aad(record_key, content_kind, target_version, target_generation);
        let mut chunk_index = 0_u32;
        loop {
            let (kind, ciphertext) = read_frame(&mut source)?;
            let plaintext = Zeroizing::new(decrypt_document_frame(
                &source_cipher,
                &source_header.prefix,
                &source_aad,
                chunk_index,
                kind,
                &ciphertext,
            )?);
            match kind {
                DATA_FRAME => {
                    if plaintext.is_empty() {
                        return Err(VaultError::InvalidFormat);
                    }
                    let target_ciphertext = encrypt_document_frame(
                        &target_cipher,
                        &target_prefix,
                        &target_aad,
                        chunk_index,
                        DATA_FRAME,
                        &plaintext,
                    )?;
                    write_frame(&mut destination, DATA_FRAME, &target_ciphertext)?;
                    chunk_index = chunk_index
                        .checked_add(1)
                        .ok_or(VaultError::DocumentTooLarge)?;
                }
                FINAL_FRAME => {
                    if !plaintext.is_empty() || has_trailing_bytes(&mut source)? {
                        return Err(VaultError::InvalidFormat);
                    }
                    let target_ciphertext = encrypt_document_frame(
                        &target_cipher,
                        &target_prefix,
                        &target_aad,
                        chunk_index,
                        FINAL_FRAME,
                        &[],
                    )?;
                    write_frame(&mut destination, FINAL_FRAME, &target_ciphertext)?;
                    destination.commit()?;
                    return Ok(());
                }
                _ => return Err(VaultError::InvalidFormat),
            }
        }
    }

    /// Re-encrypts at most `limit` complete records with the active write key.
    ///
    /// Enumeration contains only one-way record hashes. Cursors add non-secret
    /// vault/target scope and an HMAC so they cannot be forged, moved between
    /// vaults, or reused for a later rotation. Each record is authenticated and
    /// rewritten as a new atomic generation while holding its exclusive
    /// generation transaction, so concurrent application writes cannot be
    /// overwritten by stale migration plaintext. Streamed content is migrated
    /// one authenticated frame at a time. If a corrupt record is encountered,
    /// the call fails without advancing a cursor past it; callers can retry the
    /// same input cursor after repair.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] for an invalid limit or target key, corrupt or
    /// unauthentic ciphertext, unavailable historical key, or storage failure.
    pub fn reencrypt_batch(
        &self,
        target_version: KeyVersion,
        cursor: Option<&ReencryptCursor>,
        limit: usize,
    ) -> Result<ReencryptOutcome, VaultError> {
        if limit == 0 {
            return Err(VaultError::InvalidBatchLimit);
        }
        self.keys.key(target_version)?;
        let active = self.keys.active_version();
        if target_version != active {
            return Err(VaultError::InactiveReencryptionTarget {
                requested: target_version.get(),
                active: active.get(),
            });
        }
        if let Some(cursor) = cursor {
            self.validate_reencrypt_cursor(cursor, target_version)?;
        }
        let enumeration_limit = limit.checked_add(1).ok_or(VaultError::InvalidBatchLimit)?;
        let after = cursor.map(|value| &value.record_key);
        let mut record_keys = self.backend.list_record_keys(after, enumeration_limit)?;
        if record_keys.len() > enumeration_limit
            || record_keys.windows(2).any(|pair| pair[0] >= pair[1])
            || after.is_some_and(|after| record_keys.iter().any(|key| key <= after))
        {
            return Err(StorageError::InvalidMetadata.into());
        }
        let has_more = record_keys.len() > limit;
        record_keys.truncate(limit);

        let mut visited = 0;
        let mut rewritten = 0;
        for record_key in &record_keys {
            if self.reencrypt_record(record_key, target_version)? {
                rewritten += 1;
            }
            visited += 1;
        }
        let next_cursor = if has_more {
            let record_key = record_keys
                .last()
                .copied()
                .ok_or(StorageError::InvalidMetadata)?;
            Some(self.new_reencrypt_cursor(target_version, record_key)?)
        } else {
            None
        };
        Ok(ReencryptOutcome {
            visited,
            rewritten,
            next_cursor,
        })
    }

    /// Restores and authenticates a durable cursor token for this vault and
    /// target key version.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::InvalidReencryptCursor`] when the token is
    /// malformed, modified, issued by another vault, or belongs to a different
    /// target-key rotation.
    pub fn reencrypt_cursor_from_token(
        &self,
        target_version: KeyVersion,
        token: &str,
    ) -> Result<ReencryptCursor, VaultError> {
        let cursor = ReencryptCursor::parse_token(token)?;
        self.validate_reencrypt_cursor(&cursor, target_version)?;
        Ok(cursor)
    }

    fn new_reencrypt_cursor(
        &self,
        target_version: KeyVersion,
        record_key: [u8; 32],
    ) -> Result<ReencryptCursor, VaultError> {
        let tag = self.reencrypt_cursor_tag(target_version, &record_key)?;
        Ok(ReencryptCursor {
            record_key,
            scope: self.cursor_scope,
            target_version,
            tag,
        })
    }

    fn validate_reencrypt_cursor(
        &self,
        cursor: &ReencryptCursor,
        target_version: KeyVersion,
    ) -> Result<(), VaultError> {
        if cursor.scope != self.cursor_scope || cursor.target_version != target_version {
            return Err(VaultError::InvalidReencryptCursor);
        }
        let mut mac = self.reencrypt_cursor_mac(target_version)?;
        mac.update(&cursor.record_key);
        mac.verify_slice(&cursor.tag)
            .map_err(|_| VaultError::InvalidReencryptCursor)
    }

    fn reencrypt_cursor_tag(
        &self,
        target_version: KeyVersion,
        record_key: &[u8; 32],
    ) -> Result<[u8; 32], VaultError> {
        let mut mac = self.reencrypt_cursor_mac(target_version)?;
        mac.update(record_key);
        Ok(mac.finalize().into_bytes().into())
    }

    fn reencrypt_cursor_mac(&self, target_version: KeyVersion) -> Result<Hmac<Sha256>, VaultError> {
        let key = self.keys.key(target_version)?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes())
            .expect("HMAC accepts keys of every length");
        mac.update(CURSOR_MAC_DOMAIN);
        mac.update(&self.cursor_scope);
        mac.update(&target_version.get().to_be_bytes());
        Ok(mac)
    }

    fn reencrypt_record(
        &self,
        record_key: &[u8; 32],
        target_version: KeyVersion,
    ) -> Result<bool, VaultError> {
        let mut transaction = self.backend.begin_generation_transaction(record_key)?;
        let generation = transaction
            .generation()
            .ok_or(StorageError::InvalidMetadata)?;
        let loaded = self.load_versioned_value_map_by_key(record_key, generation)?;
        let original_version = self.versioned_streamed_content_version_by_key(
            record_key,
            ContentKind::Original,
            generation,
        )?;
        let document_version = self.versioned_streamed_content_version_by_key(
            record_key,
            ContentKind::Document,
            generation,
        )?;
        if loaded.version != original_version || loaded.version != document_version {
            return Err(VaultError::InconsistentRecordKeyVersions);
        }
        if loaded.version == target_version {
            let authenticated_original = self.load_versioned_streamed_content_by_key(
                record_key,
                &mut std::io::sink(),
                ContentKind::Original,
                generation,
            )?;
            let authenticated_document = self.load_versioned_streamed_content_by_key(
                record_key,
                &mut std::io::sink(),
                ContentKind::Document,
                generation,
            )?;
            if authenticated_original != target_version || authenticated_document != target_version
            {
                return Err(VaultError::InconsistentRecordKeyVersions);
            }
            return Ok(false);
        }
        let next = generation
            .checked_add(1)
            .ok_or(VaultError::GenerationExhausted)?;
        self.reencrypt_streamed_content_by_key(
            record_key,
            ContentKind::Original,
            generation,
            loaded.version,
            next,
            target_version,
        )?;
        self.reencrypt_streamed_content_by_key(
            record_key,
            ContentKind::Document,
            generation,
            loaded.version,
            next,
            target_version,
        )?;
        let sealed_values =
            self.seal_value_map(record_key, &loaded.values.0, next, target_version)?;
        self.backend.store_versioned_value_map(
            &RecordIdentity::versioned_storage_key_for(record_key, ContentKind::ValueMap),
            next,
            &sealed_values,
        )?;
        match transaction.compare_and_swap(Some(generation), next) {
            Ok(()) => Ok(true),
            Err(StorageError::GenerationConflict) => Err(VaultError::GenerationConflict),
            Err(error) => Err(error.into()),
        }
    }

    /// Permanently removes every sealed object belonging to a record.
    ///
    /// Purging a record that has no stored objects succeeds, making retries
    /// safe.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Storage`] when either object cannot be removed.
    pub fn purge(&self, identity: &RecordIdentity) -> Result<(), VaultError> {
        let record_key = identity.record_key();
        let _transaction = self.backend.begin_generation_transaction(&record_key)?;
        self.backend.purge(&PurgeKeys {
            record: record_key,
            legacy_value_map: identity.storage_key(ContentKind::ValueMap),
            legacy_document: identity.storage_key(ContentKind::Document),
            legacy_original: identity.storage_key(ContentKind::Original),
            versioned_value_map: identity.versioned_storage_key(ContentKind::ValueMap),
            versioned_document: identity.versioned_storage_key(ContentKind::Document),
            versioned_original: identity.versioned_storage_key(ContentKind::Original),
        })?;
        Ok(())
    }

    /// Removes every sealed object older than `cutoff`, returning the count.
    ///
    /// Retention, as opposed to deletion. `purge` answers "this record is
    /// gone"; this answers "nothing here outlives its policy". Both are needed:
    /// without a sweep, material that no one ever deletes stays until the disk
    /// does, which makes any retention statement untrue.
    ///
    /// No key is required and nothing is decrypted -- expiry is a property of
    /// the ciphertext object, not of what it contains.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the backend cannot enumerate or remove.
    pub fn purge_expired(&self, cutoff: SystemTime) -> Result<usize, VaultError> {
        Ok(self.backend.purge_expired(cutoff)?)
    }
}

fn read_source<R: Read>(source: &mut R, buffer: &mut [u8]) -> Result<usize, VaultError> {
    loop {
        match source.read(buffer) {
            Ok(length) => return Ok(length),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(VaultError::DocumentIo(error)),
        }
    }
}

fn encrypt_document_frame(
    cipher: &XChaCha20Poly1305,
    prefix: &[u8; NONCE_PREFIX_BYTES],
    base_aad: &[u8],
    index: u32,
    kind: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    cipher
        .encrypt(
            XNonce::from_slice(&document_nonce(prefix, index, kind)),
            Payload {
                msg: plaintext,
                aad: &document_aad(base_aad, index, kind),
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)
}

fn decrypt_document_frame(
    cipher: &XChaCha20Poly1305,
    prefix: &[u8; NONCE_PREFIX_BYTES],
    base_aad: &[u8],
    index: u32,
    kind: u8,
    ciphertext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    cipher
        .decrypt(
            XNonce::from_slice(&document_nonce(prefix, index, kind)),
            Payload {
                msg: ciphertext,
                aad: &document_aad(base_aad, index, kind),
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)
}

fn document_nonce(prefix: &[u8; NONCE_PREFIX_BYTES], index: u32, kind: u8) -> [u8; 24] {
    let mut nonce = [0; 24];
    nonce[..NONCE_PREFIX_BYTES].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_BYTES..23].copy_from_slice(&index.to_be_bytes());
    nonce[23] = kind;
    nonce
}

fn document_aad(base: &[u8], index: u32, kind: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(base.len() + size_of::<u32>() + 1);
    aad.extend_from_slice(base);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(kind);
    aad
}

fn write_frame(
    destination: &mut Box<dyn crate::PendingDocument>,
    kind: u8,
    ciphertext: &[u8],
) -> Result<(), VaultError> {
    let length = u32::try_from(ciphertext.len()).map_err(|_| VaultError::DocumentTooLarge)?;
    write_backend(destination, &[kind])?;
    write_backend(destination, &length.to_be_bytes())?;
    write_backend(destination, ciphertext)
}

fn write_backend(
    destination: &mut Box<dyn crate::PendingDocument>,
    bytes: &[u8],
) -> Result<(), VaultError> {
    destination
        .write_all(bytes)
        .map_err(|error| VaultError::Storage(error.into()))
}

fn read_frame(source: &mut Box<dyn Read + Send>) -> Result<(u8, Vec<u8>), VaultError> {
    let mut header = [0_u8; 5];
    read_backend_exact(source, &mut header)?;
    let length = usize::try_from(u32::from_be_bytes(
        header[1..]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    ))
    .map_err(|_| VaultError::InvalidFormat)?;
    validate_frame_length(header[0], length)?;
    let mut ciphertext = vec![0; length];
    read_backend_exact(source, &mut ciphertext)?;
    Ok((header[0], ciphertext))
}

fn read_backend_exact(
    source: &mut Box<dyn Read + Send>,
    bytes: &mut [u8],
) -> Result<(), VaultError> {
    source.read_exact(bytes).map_err(|error| {
        if error.kind() == ErrorKind::UnexpectedEof {
            VaultError::InvalidFormat
        } else {
            VaultError::Storage(error.into())
        }
    })
}

fn validate_frame_length(kind: u8, length: usize) -> Result<(), VaultError> {
    match kind {
        DATA_FRAME if (TAG_BYTES + 1..=DOCUMENT_CHUNK_BYTES + TAG_BYTES).contains(&length) => {
            Ok(())
        }
        FINAL_FRAME if length == TAG_BYTES => Ok(()),
        _ => Err(VaultError::InvalidFormat),
    }
}

fn has_trailing_bytes(source: &mut Box<dyn Read + Send>) -> Result<bool, VaultError> {
    let mut byte = [0];
    loop {
        match source.read(&mut byte) {
            Ok(0) => return Ok(false),
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(VaultError::Storage(error.into())),
        }
    }
}

fn value_map_nonce(prefix: &[u8; NONCE_PREFIX_BYTES]) -> [u8; 24] {
    let mut nonce = [0; 24];
    nonce[..NONCE_PREFIX_BYTES].copy_from_slice(prefix);
    nonce[23] = VALUE_MAP_NONCE_DOMAIN;
    nonce
}

struct ParsedValueMap<'a> {
    version: KeyVersion,
    generation: u64,
    prefix: &'a [u8; NONCE_PREFIX_BYTES],
    ciphertext: &'a [u8],
    legacy: bool,
}

fn parse_value_map(sealed: &[u8]) -> Result<ParsedValueMap<'_>, VaultError> {
    let Some(magic) = sealed.get(..8) else {
        return Err(VaultError::InvalidFormat);
    };
    if magic == VALUE_MAP_MAGIC_V1 {
        if sealed.len() < 8 + NONCE_PREFIX_BYTES + TAG_BYTES {
            return Err(VaultError::InvalidFormat);
        }
        return Ok(ParsedValueMap {
            version: KeyVersion::new(1).expect("version one is non-zero"),
            generation: 0,
            prefix: sealed[8..27]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
            ciphertext: &sealed[27..],
            legacy: true,
        });
    }
    if magic != VALUE_MAP_MAGIC_V2
        || sealed.len() < 8 + KEY_VERSION_BYTES + GENERATION_BYTES + NONCE_PREFIX_BYTES + TAG_BYTES
    {
        return Err(VaultError::InvalidFormat);
    }
    let version = u32::from_be_bytes(
        sealed[8..12]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    );
    let version = KeyVersion::new(version).map_err(|_| VaultError::InvalidFormat)?;
    let generation = u64::from_be_bytes(
        sealed[12..20]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    );
    if generation == 0 {
        return Err(VaultError::InvalidFormat);
    }
    Ok(ParsedValueMap {
        version,
        generation,
        prefix: sealed[20..39]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
        ciphertext: &sealed[39..],
        legacy: false,
    })
}

fn envelope_aad(
    identity: &RecordIdentity,
    kind: ContentKind,
    envelope: &ParsedValueMap<'_>,
) -> Vec<u8> {
    if envelope.legacy {
        identity.associated_data(kind)
    } else {
        versioned_aad(
            &identity.record_key(),
            kind,
            envelope.version,
            envelope.generation,
        )
    }
}

fn versioned_aad(
    record_key: &[u8; 32],
    kind: ContentKind,
    version: KeyVersion,
    generation: u64,
) -> Vec<u8> {
    let mut aad = RecordIdentity::versioned_associated_data_for(record_key, kind);
    aad.extend_from_slice(&version.get().to_be_bytes());
    aad.extend_from_slice(&generation.to_be_bytes());
    aad
}

fn verify_generation(trusted: Option<u64>, envelope: u64, legacy: bool) -> Result<(), VaultError> {
    let Some(trusted) = trusted else {
        return Ok(());
    };
    let authenticated = if legacy { 0 } else { envelope };
    if authenticated != trusted {
        return Err(VaultError::RollbackDetected {
            trusted,
            envelope: authenticated,
        });
    }
    Ok(())
}

struct StreamHeader {
    version: KeyVersion,
    generation: u64,
    prefix: [u8; NONCE_PREFIX_BYTES],
    legacy: bool,
}

fn read_stream_header(source: &mut Box<dyn Read + Send>) -> Result<StreamHeader, VaultError> {
    let mut magic = [0_u8; 8];
    read_backend_exact(source, &mut magic)?;
    if &magic == DOCUMENT_MAGIC_V1 {
        let mut prefix = [0_u8; NONCE_PREFIX_BYTES];
        read_backend_exact(source, &mut prefix)?;
        return Ok(StreamHeader {
            version: KeyVersion::new(1).expect("version one is non-zero"),
            generation: 0,
            prefix,
            legacy: true,
        });
    }
    if &magic != DOCUMENT_MAGIC_V2 {
        return Err(VaultError::InvalidFormat);
    }
    let mut serialized = [0_u8; KEY_VERSION_BYTES + GENERATION_BYTES + NONCE_PREFIX_BYTES];
    read_backend_exact(source, &mut serialized)?;
    let version = u32::from_be_bytes(
        serialized[..4]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    );
    let version = KeyVersion::new(version).map_err(|_| VaultError::InvalidFormat)?;
    let generation = u64::from_be_bytes(
        serialized[4..12]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    );
    if generation == 0 {
        return Err(VaultError::InvalidFormat);
    }
    Ok(StreamHeader {
        version,
        generation,
        prefix: serialized[12..]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
        legacy: false,
    })
}
