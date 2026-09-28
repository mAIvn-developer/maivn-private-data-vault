use std::{
    io::{Read, Write},
    time::SystemTime,
};

use crate::{ContentKind, StorageError};

/// A backend-owned ciphertext sink that becomes durable only on `commit`.
/// Dropping it without committing must abort the partial object.
pub trait PendingDocument: Write + Send {
    /// Makes every ciphertext byte written to this sink visible atomically.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the ciphertext cannot be synchronized or
    /// atomically moved into its durable location.
    fn commit(self: Box<Self>) -> Result<(), StorageError>;
}

/// Backend-owned shared snapshot of one record's trusted generation.
///
/// Implementations keep any shared lock alive until this value is dropped.
pub trait GenerationRead: Send {
    /// Returns the committed generation, or `None` for a legacy/unpublished record.
    fn generation(&self) -> Option<u64>;
}

/// Exclusive transaction used to publish one complete record generation.
pub trait GenerationTransaction: GenerationRead {
    /// Commits `next` only when the transaction still observes `expected`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::GenerationConflict`] when the expected value no
    /// longer matches or another storage failure when metadata cannot be made
    /// durable.
    fn compare_and_swap(&mut self, expected: Option<u64>, next: u64) -> Result<(), StorageError>;
}

/// Opaque addresses for every legacy and versioned object owned by one record.
///
/// These hashes contain no tenant or record names. A backend needs the full set
/// to make hard deletion cover objects written before and after atomic record
/// generations were introduced.
pub struct PurgeKeys {
    /// Opaque logical record hash used by trusted-generation metadata.
    pub record: [u8; 32],
    /// Legacy value-map address.
    pub legacy_value_map: [u8; 32],
    /// Legacy redacted-document address.
    pub legacy_document: [u8; 32],
    /// Legacy original-document address.
    pub legacy_original: [u8; 32],
    /// Versioned value-map address.
    pub versioned_value_map: [u8; 32],
    /// Versioned redacted-document address.
    pub versioned_document: [u8; 32],
    /// Versioned original-document address.
    pub versioned_original: [u8; 32],
}

/// Ciphertext-only persistence used by [`crate::Vault`].
///
/// Implementations must make `reserve_nonce_prefix` durable before returning
/// it and must never return the same prefix for a given key-derivation salt.
/// This contract lets a managed backend replace [`crate::LocalBackend`]
/// without changing any sealing code.
pub trait StorageBackend: Send + Sync {
    /// Returns the stable, non-secret salt used to derive this vault's key.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the backend cannot load valid metadata.
    fn key_derivation_salt(&self) -> Result<[u8; 16], StorageError>;

    /// Reserves a unique 19-byte prefix for one sealing operation.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when durable reservation fails or the sequence
    /// is exhausted.
    fn reserve_nonce_prefix(&self) -> Result<[u8; 19], StorageError>;

    /// Opens a shared, stable generation snapshot for one opaque record key.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the lock or trusted metadata cannot be read.
    fn begin_generation_read(
        &self,
        record_key: &[u8; 32],
    ) -> Result<Box<dyn GenerationRead>, StorageError>;

    /// Opens an exclusive generation transaction for one opaque record key.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the lock or trusted metadata cannot be read.
    fn begin_generation_transaction(
        &self,
        record_key: &[u8; 32],
    ) -> Result<Box<dyn GenerationTransaction>, StorageError>;

    /// Reads one record's trusted committed generation under a shared lease.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the shared snapshot cannot be acquired.
    fn read_generation(&self, record_key: &[u8; 32]) -> Result<Option<u64>, StorageError> {
        Ok(self.begin_generation_read(record_key)?.generation())
    }

    /// Atomically advances one record's trusted generation.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::GenerationConflict`] for a stale expectation or
    /// another [`StorageError`] when the update cannot be made durable.
    fn compare_and_swap_generation(
        &self,
        record_key: &[u8; 32],
        expected: Option<u64>,
        next: u64,
    ) -> Result<(), StorageError> {
        self.begin_generation_transaction(record_key)?
            .compare_and_swap(expected, next)
    }

    /// Lists opaque record keys in stable byte order after an optional cursor.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when generation metadata cannot be enumerated
    /// or contains a malformed record filename.
    fn list_record_keys(
        &self,
        after: Option<&[u8; 32]>,
        limit: usize,
    ) -> Result<Vec<[u8; 32]>, StorageError>;

    /// Atomically stores a sealed value map under an opaque key.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the sealed bytes are invalid or cannot be
    /// made durable.
    fn store_value_map(&self, storage_key: &[u8; 32], sealed: &[u8]) -> Result<(), StorageError>;

    /// Loads a sealed value map by opaque key.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the object is absent or cannot be read.
    fn load_value_map(&self, storage_key: &[u8; 32]) -> Result<Vec<u8>, StorageError>;

    /// Atomically stores a sealed value map for one committed-generation candidate.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the object cannot be made durable.
    fn store_versioned_value_map(
        &self,
        storage_key: &[u8; 32],
        generation: u64,
        sealed: &[u8],
    ) -> Result<(), StorageError>;

    /// Loads a sealed value map from one exact generation path.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the object is absent or cannot be read.
    fn load_versioned_value_map(
        &self,
        storage_key: &[u8; 32],
        generation: u64,
    ) -> Result<Vec<u8>, StorageError>;

    /// Starts an atomic ciphertext-only streamed-content write.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the pending ciphertext sink cannot be
    /// created.
    fn begin_content(
        &self,
        storage_key: &[u8; 32],
        operation_nonce: &[u8; 19],
        kind: ContentKind,
    ) -> Result<Box<dyn PendingDocument>, StorageError>;

    /// Opens a ciphertext-only content stream.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the object is absent or cannot be opened.
    fn open_content(
        &self,
        storage_key: &[u8; 32],
        kind: ContentKind,
    ) -> Result<Box<dyn Read + Send>, StorageError>;

    /// Starts an atomic streamed-content write for one generation candidate.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the pending sink cannot be created.
    fn begin_versioned_content(
        &self,
        storage_key: &[u8; 32],
        operation_nonce: &[u8; 19],
        kind: ContentKind,
        generation: u64,
    ) -> Result<Box<dyn PendingDocument>, StorageError>;

    /// Opens streamed content from one exact generation path.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the object is absent or cannot be opened.
    fn open_versioned_content(
        &self,
        storage_key: &[u8; 32],
        kind: ContentKind,
        generation: u64,
    ) -> Result<Box<dyn Read + Send>, StorageError>;

    /// Removes every sealed object belonging to one logical record.
    ///
    /// Missing objects are treated as already purged. Implementations must
    /// attempt all deletions and report a failure from any one.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when either sealed object cannot be removed.
    fn purge(&self, keys: &PurgeKeys) -> Result<(), StorageError>;

    /// Removes every sealed object last modified before `cutoff`.
    ///
    /// Retention has to be enforced here rather than a layer up, because a
    /// storage key is a hash of the record identity and cannot be reversed: no
    /// caller can enumerate what a vault holds, and the vault itself cannot
    /// decrypt an identity to make a policy decision about it. Age of the
    /// ciphertext object is the only signal available, and it is sufficient --
    /// retention is a time policy.
    ///
    /// Objects are swept independently rather than by record. A value map and
    /// its document are written at the same moment, so they expire together in
    /// practice; treating them as one unit would require the index this design
    /// deliberately does not keep.
    ///
    /// Returns the number of objects removed.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the store cannot be enumerated or an
    /// expired object cannot be removed.
    fn purge_expired(&self, cutoff: SystemTime) -> Result<usize, StorageError>;
}
