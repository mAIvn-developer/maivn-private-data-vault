//! Authenticated, sealed storage for private originals, redacted documents,
//! and their value maps.
//!
//! Plaintext is serialized or streamed only inside [`Vault`]. A
//! [`StorageBackend`] receives opaque storage keys and ciphertext, never the
//! material being protected.

#![doc(html_no_source)]

mod error;
mod identity;
mod key;
mod keyring;
mod local;
mod memory;
mod reencrypt;
mod storage;
mod vault;

pub use error::{StorageError, VaultError};
pub use identity::{ContentKind, RecordIdentity};
pub use keyring::{KeyVersion, Keyring};
pub use local::LocalBackend;
pub use memory::{ExchangeRecord, MemoryBackend};
pub use reencrypt::{ReencryptCursor, ReencryptOutcome};
pub use storage::{
    GenerationRead, GenerationTransaction, PendingDocument, PurgeKeys, StorageBackend,
};
pub use vault::Vault;
