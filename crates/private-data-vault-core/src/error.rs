use std::io;

use thiserror::Error;

/// A failure below the sealing boundary.
#[derive(Debug, Error)]
pub enum StorageError {
    /// The local or managed storage operation failed.
    #[error("storage I/O failed: {0}")]
    Io(#[from] io::Error),
    /// The backend's persistent cryptographic metadata is corrupt or unknown.
    #[error("storage metadata is invalid")]
    InvalidMetadata,
    /// A caller attempted to persist bytes that are not a sealed object.
    #[error("sealed object supplied to storage is invalid")]
    InvalidSealedObject,
    /// The persistent operation-nonce space has been consumed.
    #[error("operation nonce sequence is exhausted")]
    NonceExhausted,
    /// A compare-and-swap observed a different trusted generation.
    #[error("trusted generation changed before commit")]
    GenerationConflict,
    /// No sealed object exists for the requested opaque key.
    #[error("sealed object was not found")]
    NotFound,
}

/// A typed failure from the sealed store.
#[derive(Debug, Error)]
pub enum VaultError {
    /// Authentication failed. This covers a wrong key, modified ciphertext,
    /// or associated data that does not match the identity used while sealing.
    #[error("ciphertext authentication failed")]
    AuthenticationFailed,
    /// A caller supplied an identity that cannot bind a record unambiguously.
    #[error("tenant and record identifiers must not be empty")]
    InvalidIdentity,
    /// A caller supplied no secret from which a protected key could be derived.
    #[error("vault secret must not be empty")]
    InvalidSecret,
    /// Key version zero is reserved and cannot identify encryption material.
    #[error("vault key version must be non-zero")]
    InvalidKeyVersion,
    /// A keyring assigned two secrets to the same version.
    #[error("vault key version {0} is present more than once")]
    DuplicateKeyVersion(u32),
    /// A sealed object names a key version unavailable to this process.
    #[error("vault key version {0} is unavailable")]
    UnknownKeyVersion(u32),
    /// A complete-record rewrite lost its generation compare-and-swap.
    #[error("trusted generation changed before the record bundle committed")]
    GenerationConflict,
    /// A single-kind compatibility write targeted an atomically managed record.
    #[error("records with a trusted generation must be replaced with store_record")]
    AtomicWriteRequired,
    /// The record generation counter cannot advance beyond `u64::MAX`.
    #[error("record generation sequence is exhausted")]
    GenerationExhausted,
    /// Re-encryption must examine at least one record per call.
    #[error("re-encryption batch limit must be greater than zero")]
    InvalidBatchLimit,
    /// A persisted re-encryption cursor is malformed or non-canonical.
    #[error("re-encryption cursor is invalid")]
    InvalidReencryptCursor,
    /// Re-encryption may only target the key selected for new writes.
    #[error("re-encryption target key version {requested} is not the active key version {active}")]
    InactiveReencryptionTarget {
        /// Requested target key version.
        requested: u32,
        /// Key version selected for new writes.
        active: u32,
    },
    /// One trusted generation contained objects written by different keys.
    #[error("record generation contains inconsistent key versions")]
    InconsistentRecordKeyVersions,
    /// The ciphertext envelope does not match the trusted current generation.
    #[error("ciphertext generation {envelope} does not match trusted generation {trusted}")]
    RollbackDetected {
        /// Generation stored in durable trusted metadata.
        trusted: u64,
        /// Generation authenticated by the ciphertext envelope.
        envelope: u64,
    },
    /// The sealed object is truncated, corrupt, or uses an unknown format.
    #[error("sealed object format is invalid")]
    InvalidFormat,
    /// Structured private values could not be encoded or decoded.
    #[error("value map serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Reading plaintext input or writing authenticated plaintext output
    /// failed at the caller-owned stream boundary.
    #[error("document stream I/O failed: {0}")]
    DocumentIo(io::Error),
    /// The document exceeded the counter space reserved by the sealed format.
    #[error("document exceeds the supported authenticated chunk count")]
    DocumentTooLarge,
    /// The memory-hard key derivation failed.
    #[error("key derivation failed")]
    KeyDerivation,
    /// The selected storage backend failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
}
