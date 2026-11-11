use std::{
    collections::BTreeMap,
    io::{ErrorKind, Read, Write},
    time::SystemTime,
};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::{Zeroize, Zeroizing};

mod envelope;
mod rotation;

use crate::{
    ContentKind, KeyVersion, Keyring, PurgeKeys, RecordIdentity, StorageBackend, StorageError,
    VaultError, keyring::DerivedKeyring,
};
use envelope::{
    DATA_FRAME, DOCUMENT_CHUNK_BYTES, FINAL_FRAME, NONCE_PREFIX_BYTES, VALUE_MAP_MAGIC_V2,
    encrypt_document_frame, open_frames, parse_value_map, read_stream_header, value_map_nonce,
    verify_generation, versioned_aad, write_frame, write_stream_header,
};

const INITIAL_GENERATION: u64 = 1;

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
        let mut loaded = self.open_value_map(
            &sealed,
            &identity.record_key(),
            trusted_generation,
            Some(identity),
        )?;
        Ok(std::mem::take(&mut loaded.values.0))
    }

    /// Authenticates and decodes a sealed value map against the trusted
    /// generation. A version-1 envelope is authenticated with the version-1
    /// associated data of `legacy_identity` when one is given; rotation gives
    /// none and authenticates every envelope with version-2 data.
    fn open_value_map(
        &self,
        sealed: &[u8],
        record_key: &[u8; 32],
        trusted_generation: Option<u64>,
        legacy_identity: Option<&RecordIdentity>,
    ) -> Result<LoadedValueMap, VaultError> {
        let envelope = parse_value_map(sealed)?;
        verify_generation(trusted_generation, envelope.generation)?;
        let nonce = value_map_nonce(envelope.prefix);
        let aad = match legacy_identity {
            Some(identity) if envelope.legacy => identity.associated_data(ContentKind::ValueMap),
            _ => versioned_aad(
                record_key,
                ContentKind::ValueMap,
                envelope.version,
                envelope.generation,
            ),
        };
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
        Ok(LoadedValueMap {
            values: SensitiveValueMap(serde_json::from_slice(&plaintext)?),
            version: envelope.version,
        })
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
        self.store_streamed_content(identity, source, ContentKind::Document)
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
        self.store_streamed_content(identity, source, ContentKind::Original)
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

    /// Seals one standalone (pre-generation) object under the active key.
    fn store_streamed_content<R: Read>(
        &self,
        identity: &RecordIdentity,
        source: &mut R,
        content_kind: ContentKind,
    ) -> Result<(), VaultError> {
        let prefix = self.backend.reserve_nonce_prefix()?;
        let destination = self.backend.begin_content(
            &identity.storage_key(content_kind),
            &prefix,
            content_kind,
        )?;
        self.write_streamed_content(
            &identity.record_key(),
            source,
            content_kind,
            INITIAL_GENERATION,
            self.keys.active_version(),
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
        write_stream_header(&mut destination, version, generation, &prefix)?;

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
        verify_generation(trusted_generation, header.generation)?;
        let key = self.keys.key(header.version)?;
        let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
        let base_aad = if header.legacy {
            legacy_aad.ok_or(VaultError::InvalidFormat)?
        } else {
            versioned_aad(record_key, content_kind, header.version, header.generation)
        };
        open_frames(
            &cipher,
            &header.prefix,
            &base_aad,
            &mut source,
            |_, plaintext| {
                destination
                    .write_all(plaintext)
                    .map_err(VaultError::DocumentIo)
            },
        )?;
        Ok(header.version)
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
