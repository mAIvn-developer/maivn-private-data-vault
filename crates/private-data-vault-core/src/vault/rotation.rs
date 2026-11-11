//! Key rotation: authenticated, resumable re-encryption of whole records
//! under the active key, one exclusive generation transaction per record.

use std::io::Write;

use chacha20poly1305::{XChaCha20Poly1305, aead::KeyInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::{
    LoadedValueMap, Vault,
    envelope::{
        DATA_FRAME, FINAL_FRAME, encrypt_document_frame, open_frames, read_stream_header,
        verify_generation, versioned_aad, write_frame, write_stream_header,
    },
};
use crate::{
    ContentKind, KeyVersion, RecordIdentity, ReencryptCursor, ReencryptOutcome, StorageBackend,
    StorageError, VaultError,
};

const CURSOR_MAC_DOMAIN: &[u8] = b"maivn-private-data-vault:reencrypt-cursor:v2";

impl<B: StorageBackend> Vault<B> {
    fn load_versioned_value_map_by_key(
        &self,
        record_key: &[u8; 32],
        generation: u64,
    ) -> Result<LoadedValueMap, VaultError> {
        let sealed_values = self.backend.load_versioned_value_map(
            &RecordIdentity::versioned_storage_key_for(record_key, ContentKind::ValueMap),
            generation,
        )?;
        self.open_value_map(&sealed_values, record_key, Some(generation), None)
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
        verify_generation(Some(generation), header.generation)?;
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
        verify_generation(Some(source_generation), source_header.generation)?;
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
        write_stream_header(
            &mut destination,
            target_version,
            target_generation,
            &target_prefix,
        )?;

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
        let reseal = |index, kind, plaintext: &[u8]| {
            encrypt_document_frame(
                &target_cipher,
                &target_prefix,
                &target_aad,
                index,
                kind,
                plaintext,
            )
        };
        let final_index = open_frames(
            &source_cipher,
            &source_header.prefix,
            &source_aad,
            &mut source,
            |index, plaintext| {
                write_frame(
                    &mut destination,
                    DATA_FRAME,
                    &reseal(index, DATA_FRAME, plaintext)?,
                )
            },
        )?;
        write_frame(
            &mut destination,
            FINAL_FRAME,
            &reseal(final_index, FINAL_FRAME, &[])?,
        )?;
        destination.commit()?;
        Ok(())
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
}
