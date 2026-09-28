//! An in-process [`StorageBackend`] for the managed exchange flow.
//!
//! The managed tier keeps ciphertext in a database and a private bucket, with
//! publication decided by a compare-and-set in Postgres. Sealing must still
//! happen HERE, in the vault core, so the managed adapter cannot grow its own
//! crypto. This backend is the bridge: the adapter hydrates it with a record's
//! current sealed objects, drives the ordinary [`crate::Vault`] operations
//! against it, and extracts the sealed results to persist. It holds one
//! record's material for one operation and is then dropped.
//!
//! Two deliberate differences from [`crate::LocalBackend`]:
//!
//! * **the key-derivation salt is a constructor argument**, not generated
//!   state. Derivation binds to the salt, so it must be stable per tenant
//!   across processes; the managed adapter derives it from the tenant
//!   identity, which is deterministic and non-secret.
//! * **nonce prefixes are OS-random per call** rather than a persisted
//!   counter. The counter exists locally to guarantee uniqueness on one
//!   machine's state file; nineteen random bytes give a 2^152 space, the
//!   standard `XChaCha` argument, and leave this backend stateless.
//!
//! The in-memory generation map satisfies the vault's internal protocol; the
//! real cross-process publication guard is the database compare-and-set the
//! adapter performs afterwards.

use std::{
    collections::BTreeMap,
    io::{Cursor, Read, Write},
    sync::{Arc, Mutex, PoisonError},
    time::SystemTime,
};

use rand_core::{OsRng, RngCore};

use crate::{
    ContentKind, RecordIdentity, StorageError,
    storage::{GenerationRead, GenerationTransaction, PendingDocument, PurgeKeys, StorageBackend},
};

/// One record's complete sealed state, as it travels to and from external
/// storage. Ciphertext only: nothing here can be opened without the vault.
pub struct ExchangeRecord {
    /// The trusted generation these sealed objects belong to.
    pub generation: u64,
    /// The sealed as-uploaded original.
    pub original: Vec<u8>,
    /// The sealed redacted document.
    pub document: Vec<u8>,
    /// The sealed placeholder-to-value map.
    pub value_map: Vec<u8>,
}

/// One sealed object plus the wall-clock moment it was stored.
#[derive(Clone)]
struct StoredObject {
    sealed: Vec<u8>,
    stored_at: SystemTime,
}

#[derive(Default)]
struct Shared {
    objects: BTreeMap<Vec<u8>, StoredObject>,
    generations: BTreeMap<[u8; 32], u64>,
}

/// In-process ciphertext store for one managed-exchange operation.
pub struct MemoryBackend {
    salt: [u8; 16],
    shared: Arc<Mutex<Shared>>,
}

fn lock(shared: &Arc<Mutex<Shared>>) -> std::sync::MutexGuard<'_, Shared> {
    // A poisoned lock means another thread panicked mid-write. The maps hold
    // only ciphertext staged for this single operation, so continuing with
    // the recovered state is safe; refusing would turn one panic into a
    // permanently wedged exchange.
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

fn object_key(storage_key: &[u8; 32], kind: ContentKind, generation: Option<u64>) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + 1 + 9);
    key.extend_from_slice(storage_key);
    key.push(match kind {
        ContentKind::Original => 0,
        ContentKind::Document => 1,
        ContentKind::ValueMap => 2,
    });
    match generation {
        None => key.push(0),
        Some(value) => {
            key.push(1);
            key.extend_from_slice(&value.to_be_bytes());
        }
    }
    key
}

impl MemoryBackend {
    /// Creates an empty exchange store with a caller-supplied derivation salt.
    #[must_use]
    pub fn new(salt: [u8; 16]) -> Self {
        Self {
            salt,
            shared: Arc::new(Mutex::new(Shared::default())),
        }
    }

    /// Seeds one record's trusted generation, as read from durable metadata.
    pub fn hydrate_generation(&self, record_key: [u8; 32], generation: u64) {
        lock(&self.shared)
            .generations
            .insert(record_key, generation);
    }

    /// Seeds one sealed object exactly as it was previously extracted.
    pub fn hydrate_object(
        &self,
        storage_key: [u8; 32],
        kind: ContentKind,
        generation: Option<u64>,
        sealed: Vec<u8>,
    ) {
        lock(&self.shared).objects.insert(
            object_key(&storage_key, kind, generation),
            StoredObject {
                sealed,
                stored_at: SystemTime::now(),
            },
        );
    }

    /// Returns one sealed object for persistence, or `None` when absent.
    #[must_use]
    pub fn extract_object(
        &self,
        storage_key: &[u8; 32],
        kind: ContentKind,
        generation: Option<u64>,
    ) -> Option<Vec<u8>> {
        lock(&self.shared)
            .objects
            .get(&object_key(storage_key, kind, generation))
            .map(|object| object.sealed.clone())
    }

    /// Returns one record's trusted generation as this exchange now sees it.
    #[must_use]
    pub fn extract_generation(&self, record_key: &[u8; 32]) -> Option<u64> {
        lock(&self.shared).generations.get(record_key).copied()
    }

    /// Returns one record's complete sealed state for external persistence.
    ///
    /// `None` when the record has no trusted generation or any of its three
    /// sealed objects is missing — a partial record must never be persisted,
    /// because it would later hydrate as a record that cannot be opened.
    #[must_use]
    pub fn export_record(&self, identity: &RecordIdentity) -> Option<ExchangeRecord> {
        let generation = self.extract_generation(&identity.record_key())?;
        let object = |kind: ContentKind| {
            self.extract_object(
                &identity.versioned_storage_key(kind),
                kind,
                Some(generation),
            )
        };
        Some(ExchangeRecord {
            generation,
            original: object(ContentKind::Original)?,
            document: object(ContentKind::Document)?,
            value_map: object(ContentKind::ValueMap)?,
        })
    }

    /// Seeds one record's complete sealed state exactly as it was exported.
    pub fn import_record(&self, identity: &RecordIdentity, record: &ExchangeRecord) {
        self.hydrate_generation(identity.record_key(), record.generation);
        let place = |kind: ContentKind, sealed: &Vec<u8>| {
            self.hydrate_object(
                identity.versioned_storage_key(kind),
                kind,
                Some(record.generation),
                sealed.clone(),
            );
        };
        place(ContentKind::Original, &record.original);
        place(ContentKind::Document, &record.document);
        place(ContentKind::ValueMap, &record.value_map);
    }
}

struct MemoryPending {
    shared: Arc<Mutex<Shared>>,
    key: Vec<u8>,
    buffer: Vec<u8>,
}

impl Write for MemoryPending {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl PendingDocument for MemoryPending {
    fn commit(self: Box<Self>) -> Result<(), StorageError> {
        lock(&self.shared).objects.insert(
            self.key.clone(),
            StoredObject {
                sealed: self.buffer,
                stored_at: SystemTime::now(),
            },
        );
        Ok(())
    }
}

struct MemoryGeneration {
    shared: Arc<Mutex<Shared>>,
    record_key: [u8; 32],
    observed: Option<u64>,
}

impl GenerationRead for MemoryGeneration {
    fn generation(&self) -> Option<u64> {
        self.observed
    }
}

impl GenerationTransaction for MemoryGeneration {
    fn compare_and_swap(&mut self, expected: Option<u64>, next: u64) -> Result<(), StorageError> {
        let mut shared = lock(&self.shared);
        let current = shared.generations.get(&self.record_key).copied();
        if current != expected {
            return Err(StorageError::GenerationConflict);
        }
        shared.generations.insert(self.record_key, next);
        self.observed = Some(next);
        Ok(())
    }
}

impl StorageBackend for MemoryBackend {
    fn key_derivation_salt(&self) -> Result<[u8; 16], StorageError> {
        Ok(self.salt)
    }

    fn reserve_nonce_prefix(&self) -> Result<[u8; 19], StorageError> {
        let mut prefix = [0u8; 19];
        OsRng
            .try_fill_bytes(&mut prefix)
            .map_err(|_| StorageError::NonceExhausted)?;
        Ok(prefix)
    }

    fn begin_generation_read(
        &self,
        record_key: &[u8; 32],
    ) -> Result<Box<dyn GenerationRead>, StorageError> {
        let observed = lock(&self.shared).generations.get(record_key).copied();
        Ok(Box::new(MemoryGeneration {
            shared: Arc::clone(&self.shared),
            record_key: *record_key,
            observed,
        }))
    }

    fn begin_generation_transaction(
        &self,
        record_key: &[u8; 32],
    ) -> Result<Box<dyn GenerationTransaction>, StorageError> {
        let observed = lock(&self.shared).generations.get(record_key).copied();
        Ok(Box::new(MemoryGeneration {
            shared: Arc::clone(&self.shared),
            record_key: *record_key,
            observed,
        }))
    }

    fn list_record_keys(
        &self,
        after: Option<&[u8; 32]>,
        limit: usize,
    ) -> Result<Vec<[u8; 32]>, StorageError> {
        let shared = lock(&self.shared);
        let keys = shared
            .generations
            .keys()
            .filter(|key| after.is_none_or(|cursor| key.as_slice() > cursor.as_slice()))
            .take(limit)
            .copied()
            .collect();
        Ok(keys)
    }

    fn store_value_map(&self, storage_key: &[u8; 32], sealed: &[u8]) -> Result<(), StorageError> {
        lock(&self.shared).objects.insert(
            object_key(storage_key, ContentKind::ValueMap, None),
            StoredObject {
                sealed: sealed.to_vec(),
                stored_at: SystemTime::now(),
            },
        );
        Ok(())
    }

    fn load_value_map(&self, storage_key: &[u8; 32]) -> Result<Vec<u8>, StorageError> {
        lock(&self.shared)
            .objects
            .get(&object_key(storage_key, ContentKind::ValueMap, None))
            .map(|object| object.sealed.clone())
            .ok_or(StorageError::NotFound)
    }

    fn store_versioned_value_map(
        &self,
        storage_key: &[u8; 32],
        generation: u64,
        sealed: &[u8],
    ) -> Result<(), StorageError> {
        lock(&self.shared).objects.insert(
            object_key(storage_key, ContentKind::ValueMap, Some(generation)),
            StoredObject {
                sealed: sealed.to_vec(),
                stored_at: SystemTime::now(),
            },
        );
        Ok(())
    }

    fn load_versioned_value_map(
        &self,
        storage_key: &[u8; 32],
        generation: u64,
    ) -> Result<Vec<u8>, StorageError> {
        lock(&self.shared)
            .objects
            .get(&object_key(
                storage_key,
                ContentKind::ValueMap,
                Some(generation),
            ))
            .map(|object| object.sealed.clone())
            .ok_or(StorageError::NotFound)
    }

    fn begin_content(
        &self,
        storage_key: &[u8; 32],
        operation_nonce: &[u8; 19],
        kind: ContentKind,
    ) -> Result<Box<dyn PendingDocument>, StorageError> {
        let _ = operation_nonce;
        Ok(Box::new(MemoryPending {
            shared: Arc::clone(&self.shared),
            key: object_key(storage_key, kind, None),
            buffer: Vec::new(),
        }))
    }

    fn open_content(
        &self,
        storage_key: &[u8; 32],
        kind: ContentKind,
    ) -> Result<Box<dyn Read + Send>, StorageError> {
        let sealed = lock(&self.shared)
            .objects
            .get(&object_key(storage_key, kind, None))
            .map(|object| object.sealed.clone())
            .ok_or(StorageError::NotFound)?;
        Ok(Box::new(Cursor::new(sealed)))
    }

    fn begin_versioned_content(
        &self,
        storage_key: &[u8; 32],
        operation_nonce: &[u8; 19],
        kind: ContentKind,
        generation: u64,
    ) -> Result<Box<dyn PendingDocument>, StorageError> {
        let _ = operation_nonce;
        Ok(Box::new(MemoryPending {
            shared: Arc::clone(&self.shared),
            key: object_key(storage_key, kind, Some(generation)),
            buffer: Vec::new(),
        }))
    }

    fn open_versioned_content(
        &self,
        storage_key: &[u8; 32],
        kind: ContentKind,
        generation: u64,
    ) -> Result<Box<dyn Read + Send>, StorageError> {
        let sealed = lock(&self.shared)
            .objects
            .get(&object_key(storage_key, kind, Some(generation)))
            .map(|object| object.sealed.clone())
            .ok_or(StorageError::NotFound)?;
        Ok(Box::new(Cursor::new(sealed)))
    }

    fn purge(&self, keys: &PurgeKeys) -> Result<(), StorageError> {
        let mut shared = lock(&self.shared);
        shared.generations.remove(&keys.record);
        let addressed = [
            keys.legacy_value_map,
            keys.legacy_document,
            keys.legacy_original,
            keys.versioned_value_map,
            keys.versioned_document,
            keys.versioned_original,
        ];
        // Every object under any addressed storage key, any kind, any
        // generation. Missing objects are already purged, not an error.
        shared
            .objects
            .retain(|key, _| !addressed.iter().any(|address| key.starts_with(address)));
        Ok(())
    }

    fn purge_expired(&self, cutoff: SystemTime) -> Result<usize, StorageError> {
        let mut shared = lock(&self.shared);
        let before = shared.objects.len();
        shared
            .objects
            .retain(|_, object| object.stored_at >= cutoff);
        Ok(before - shared.objects.len())
    }
}
