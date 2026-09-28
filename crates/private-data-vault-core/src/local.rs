use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};

use fs2::FileExt;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::{
    ContentKind, GenerationRead, GenerationTransaction, PendingDocument, PurgeKeys, StorageBackend,
    StorageError,
};

const STATE_MAGIC: &[u8; 8] = b"PDVST002";

/// One slot: magic, generation, salt, instance id, counter, checksum.
const SLOT_BYTES: usize = 8 + 8 + 16 + 11 + 8 + 32;

/// Two slots, written alternately.
///
/// The previous format kept ONE record and overwrote it in place, protected by
/// nothing but a magic string and a length check. That is a nonce-reuse hazard,
/// which for XChaCha20-Poly1305 is the one failure that destroys
/// confidentiality outright rather than degrading it: with `next_counter` at
/// 255, the update to 256 rewrites `..00ff` to `..0100`, and a power loss
/// during that write can leave `..0000` durable. Reopening would accept counter
/// zero and reissue a nonce prefix already used under the same key. Two
/// keystreams under one nonce are XOR-recoverable, and the Poly1305 key falls
/// out with them.
///
/// So: never overwrite the live record. Write the OTHER slot, checksum it,
/// sync it, and let the higher generation win. A torn write damages only the
/// slot being written, whose checksum then fails, and the previous generation
/// is still intact beside it. The counter can skip forward on a crash; it can
/// never go backwards.
const STATE_BYTES: usize = SLOT_BYTES * 2;
const GENERATION_MAGIC: &[u8; 8] = b"PDVGEN01";
const GENERATION_FILE_BYTES: usize = 8 + 8 + 32;

/// Filesystem-backed ciphertext storage with a persistent nonce sequence.
#[derive(Clone, Debug)]
pub struct LocalBackend {
    root: PathBuf,
}

impl LocalBackend {
    /// Opens or creates a local vault rooted at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when directories or persistent state cannot be
    /// created, locked, read, validated, or synchronized.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let root = path.as_ref().to_path_buf();
        create_private_directory(&root)?;
        create_private_directory(&root.join("values"))?;
        create_private_directory(&root.join("documents"))?;
        create_private_directory(&root.join("originals"))?;
        create_private_directory(&root.join("generations"))?;
        create_private_directory(&root.join("generation-locks"))?;
        let backend = Self { root };
        backend.initialize_state()?;
        Ok(backend)
    }

    fn state_file(&self) -> Result<File, StorageError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.root.join("vault.state"))?;
        set_private_file_permissions(&file)?;
        Ok(file)
    }

    fn initialize_state(&self) -> Result<(), StorageError> {
        let mut file = self.state_file()?;
        file.lock_exclusive()?;
        if file.metadata()?.len() == 0 {
            let mut state = State {
                salt: [0; 16],
                instance_id: [0; 11],
                next_counter: 0,
                generation: 0,
            };
            OsRng.fill_bytes(&mut state.salt);
            OsRng.fill_bytes(&mut state.instance_id);
            write_state(&mut file, &state)?;
        } else {
            read_state(&mut file)?;
        }
        fs2::FileExt::unlock(&file)?;
        Ok(())
    }

    fn value_path(&self, storage_key: &[u8; 32]) -> PathBuf {
        self.root
            .join("values")
            .join(format!("{}.pvm", hex::encode(storage_key)))
    }

    fn versioned_value_path(&self, storage_key: &[u8; 32], generation: u64) -> PathBuf {
        self.root
            .join("values")
            .join(format!("{}.{generation:020}.pvm", hex::encode(storage_key)))
    }

    fn document_path(&self, storage_key: &[u8; 32]) -> PathBuf {
        self.root
            .join("documents")
            .join(format!("{}.pvd", hex::encode(storage_key)))
    }

    fn original_path(&self, storage_key: &[u8; 32]) -> PathBuf {
        self.root
            .join("originals")
            .join(format!("{}.pvo", hex::encode(storage_key)))
    }

    fn versioned_content_path(
        &self,
        storage_key: &[u8; 32],
        kind: ContentKind,
        generation: u64,
    ) -> PathBuf {
        let (directory, extension) = match kind {
            ContentKind::ValueMap => ("values", "pvm"),
            ContentKind::Document => ("documents", "pvd"),
            ContentKind::Original => ("originals", "pvo"),
        };
        self.root.join(directory).join(format!(
            "{}.{generation:020}.{extension}",
            hex::encode(storage_key)
        ))
    }

    fn generation_path(&self, record_key: &[u8; 32]) -> PathBuf {
        self.root
            .join("generations")
            .join(format!("{}.pvg", hex::encode(record_key)))
    }

    fn generation_lock_path(&self, record_key: &[u8; 32]) -> PathBuf {
        self.root
            .join("generation-locks")
            .join(format!("{}.lock", hex::encode(record_key)))
    }

    fn content_path(&self, storage_key: &[u8; 32], kind: ContentKind) -> PathBuf {
        match kind {
            ContentKind::ValueMap => self.value_path(storage_key),
            ContentKind::Document => self.document_path(storage_key),
            ContentKind::Original => self.original_path(storage_key),
        }
    }
}

impl StorageBackend for LocalBackend {
    fn key_derivation_salt(&self) -> Result<[u8; 16], StorageError> {
        let mut file = self.state_file()?;
        fs2::FileExt::lock_shared(&file)?;
        let state = read_state(&mut file)?;
        fs2::FileExt::unlock(&file)?;
        Ok(state.salt)
    }

    fn reserve_nonce_prefix(&self) -> Result<[u8; 19], StorageError> {
        let mut file = self.state_file()?;
        file.lock_exclusive()?;
        let mut state = read_state(&mut file)?;
        if state.next_counter == u64::MAX {
            fs2::FileExt::unlock(&file)?;
            return Err(StorageError::NonceExhausted);
        }

        let mut prefix = [0; 19];
        prefix[..11].copy_from_slice(&state.instance_id);
        prefix[11..].copy_from_slice(&state.next_counter.to_be_bytes());
        state.next_counter += 1;
        // Persisting and syncing the increment before returning means a crash
        // can skip a nonce but cannot cause this backend to issue it again.
        write_state(&mut file, &state)?;
        fs2::FileExt::unlock(&file)?;
        Ok(prefix)
    }

    fn begin_generation_read(
        &self,
        record_key: &[u8; 32],
    ) -> Result<Box<dyn GenerationRead>, StorageError> {
        let lock = open_generation_lock(&self.generation_lock_path(record_key))?;
        fs2::FileExt::lock_shared(&lock)?;
        let generation = read_generation_file(&self.generation_path(record_key), record_key)?;
        Ok(Box::new(LocalGenerationRead {
            _lock: lock,
            generation,
        }))
    }

    fn begin_generation_transaction(
        &self,
        record_key: &[u8; 32],
    ) -> Result<Box<dyn GenerationTransaction>, StorageError> {
        let lock = open_generation_lock(&self.generation_lock_path(record_key))?;
        lock.lock_exclusive()?;
        let metadata_path = self.generation_path(record_key);
        let generation = read_generation_file(&metadata_path, record_key)?;
        Ok(Box::new(LocalGenerationTransaction {
            _lock: lock,
            metadata_path,
            record_key: *record_key,
            generation,
        }))
    }

    fn list_record_keys(
        &self,
        after: Option<&[u8; 32]>,
        limit: usize,
    ) -> Result<Vec<[u8; 32]>, StorageError> {
        let mut keys = BTreeSet::new();
        for entry in fs::read_dir(self.root.join("generations"))? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                return Err(StorageError::InvalidMetadata);
            }
            let name = entry.file_name();
            let name = name.to_str().ok_or(StorageError::InvalidMetadata)?;
            if is_generation_temporary(name) {
                continue;
            }
            let encoded = name
                .strip_suffix(".pvg")
                .ok_or(StorageError::InvalidMetadata)?;
            if encoded.len() != 64 {
                return Err(StorageError::InvalidMetadata);
            }
            let decoded = hex::decode(encoded).map_err(|_| StorageError::InvalidMetadata)?;
            let key: [u8; 32] = decoded
                .try_into()
                .map_err(|_| StorageError::InvalidMetadata)?;
            if after.is_none_or(|cursor| key > *cursor) {
                keys.insert(key);
                if keys.len() > limit {
                    keys.pop_last();
                }
            }
        }
        Ok(keys.into_iter().collect())
    }

    fn store_value_map(&self, storage_key: &[u8; 32], sealed: &[u8]) -> Result<(), StorageError> {
        store_sealed_value(&self.value_path(storage_key), sealed)
    }

    fn load_value_map(&self, storage_key: &[u8; 32]) -> Result<Vec<u8>, StorageError> {
        read_sealed_value(&self.value_path(storage_key))
    }

    fn store_versioned_value_map(
        &self,
        storage_key: &[u8; 32],
        generation: u64,
        sealed: &[u8],
    ) -> Result<(), StorageError> {
        store_sealed_value(&self.versioned_value_path(storage_key, generation), sealed)
    }

    fn load_versioned_value_map(
        &self,
        storage_key: &[u8; 32],
        generation: u64,
    ) -> Result<Vec<u8>, StorageError> {
        read_sealed_value(&self.versioned_value_path(storage_key, generation))
    }

    fn begin_content(
        &self,
        storage_key: &[u8; 32],
        operation_nonce: &[u8; 19],
        kind: ContentKind,
    ) -> Result<Box<dyn PendingDocument>, StorageError> {
        begin_pending_content(self.content_path(storage_key, kind), operation_nonce)
    }

    fn open_content(
        &self,
        storage_key: &[u8; 32],
        kind: ContentKind,
    ) -> Result<Box<dyn Read + Send>, StorageError> {
        open_sealed_content(&self.content_path(storage_key, kind))
    }

    fn begin_versioned_content(
        &self,
        storage_key: &[u8; 32],
        operation_nonce: &[u8; 19],
        kind: ContentKind,
        generation: u64,
    ) -> Result<Box<dyn PendingDocument>, StorageError> {
        begin_pending_content(
            self.versioned_content_path(storage_key, kind, generation),
            operation_nonce,
        )
    }

    fn open_versioned_content(
        &self,
        storage_key: &[u8; 32],
        kind: ContentKind,
        generation: u64,
    ) -> Result<Box<dyn Read + Send>, StorageError> {
        open_sealed_content(&self.versioned_content_path(storage_key, kind, generation))
    }

    fn purge(&self, keys: &PurgeKeys) -> Result<(), StorageError> {
        let generation_path = self.generation_path(&keys.record);
        let value_directory = self.root.join("values");
        let document_directory = self.root.join("documents");
        let original_directory = self.root.join("originals");
        let value_result = remove_record_objects(&value_directory, &keys.legacy_value_map, "pvm");
        let document_result =
            remove_record_objects(&document_directory, &keys.legacy_document, "pvd");
        let original_result =
            remove_record_objects(&original_directory, &keys.legacy_original, "pvo");
        let versioned_value_result =
            remove_record_objects(&value_directory, &keys.versioned_value_map, "pvm");
        let versioned_document_result =
            remove_record_objects(&document_directory, &keys.versioned_document, "pvd");
        let versioned_original_result =
            remove_record_objects(&original_directory, &keys.versioned_original, "pvo");
        let generation_result = remove_file_if_present(&generation_path);
        // An unlink is no more durable than a rename. Without syncing the
        // directory, a purge can report success and a crash moments later
        // restore the entry -- which for a HARD DELETE is the whole claim
        // failing, not a performance detail. Owner ruling 2026-08-05: private
        // material is removed, not marked, and material that comes back was
        // never removed.
        let value_sync = sync_directory(&value_directory);
        let document_sync = sync_directory(&document_directory);
        let original_sync = sync_directory(&original_directory);
        let generation_sync = sync_parent_directory(&generation_path);
        value_result
            .and(document_result)
            .and(original_result)
            .and(versioned_value_result)
            .and(versioned_document_result)
            .and(versioned_original_result)
            .and(generation_result)
            .and(value_sync)
            .and(document_sync)
            .and(original_sync)
            .and(generation_sync)
    }

    fn purge_expired(&self, cutoff: SystemTime) -> Result<usize, StorageError> {
        let mut removed = 0;
        for directory in [
            self.root.join("values"),
            self.root.join("documents"),
            self.root.join("originals"),
        ] {
            removed += sweep_directory(&directory, cutoff)?;
        }
        Ok(removed)
    }
}

fn is_generation_temporary(name: &str) -> bool {
    let mut components = name.split('.');
    let record_key = components.next();
    let nonce = components.next();
    let extension = components.next();
    record_key.is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) && nonce.is_some_and(|value| {
        value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) && extension == Some("tmp")
        && components.next().is_none()
}

fn read_sealed_value(path: &Path) -> Result<Vec<u8>, StorageError> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(StorageError::NotFound),
        Err(error) => Err(error.into()),
    }
}

fn store_sealed_value(target: &Path, sealed: &[u8]) -> Result<(), StorageError> {
    let nonce = match sealed.get(..8) {
        Some(b"PDVMAP01") => sealed.get(8..27),
        Some(b"PDVMAP02") => sealed.get(20..39),
        _ => None,
    }
    .ok_or(StorageError::InvalidSealedObject)?;
    let temporary = target.with_extension(format!("{}.tmp", hex::encode(nonce)));
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        set_private_file_permissions(&file)?;
        file.write_all(sealed)?;
        file.sync_all()?;
        fs::rename(&temporary, target)?;
        // Syncing the file makes its contents durable; the directory entry
        // created by the rename must be synchronized separately.
        sync_parent_directory(target)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ignored = fs::remove_file(&temporary);
    }
    write_result
}

fn begin_pending_content(
    target: PathBuf,
    operation_nonce: &[u8; 19],
) -> Result<Box<dyn PendingDocument>, StorageError> {
    let temporary = target.with_extension(format!("{}.tmp", hex::encode(operation_nonce)));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    set_private_file_permissions(&file)?;
    Ok(Box::new(LocalPendingDocument {
        file: Some(file),
        temporary,
        target,
        committed: false,
    }))
}

fn open_sealed_content(path: &Path) -> Result<Box<dyn Read + Send>, StorageError> {
    match File::open(path) {
        Ok(file) => Ok(Box::new(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(StorageError::NotFound),
        Err(error) => Err(error.into()),
    }
}

/// Removes every file in one directory older than `cutoff`.
///
/// A file whose modification time cannot be read is left alone rather than
/// deleted. Retention deleting something it could not evaluate would be a
/// silent data loss, and the sweep runs again shortly.
fn sweep_directory(directory: &Path, cutoff: SystemTime) -> Result<usize, StorageError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let mut removed = 0;
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Ok(modified) = entry.metadata().and_then(|data| data.modified()) else {
            continue;
        };
        if modified < cutoff {
            // Claim the path by renaming BEFORE deciding, rather than
            // re-checking the timestamp and then deleting.
            //
            // A stat-then-delete is racy however tightly it is written: the
            // storage key derives from the record identity, so a re-seal of the
            // same record lands at exactly this path, and a replacement written
            // between the check and the unlink is destroyed while well inside
            // its retention period. Rename is atomic, so moving the file aside
            // first takes ownership of whichever version was there; anything
            // written afterwards lands on a now-empty path and is untouched.
            // If what we claimed turns out to be fresh, it goes back.
            if claim_and_remove_if_expired(&entry.path(), cutoff)? {
                removed += 1;
            }
        }
    }
    Ok(removed)
}

/// Atomically claims `path` and removes it only if it is genuinely expired.
///
/// Returns whether an object was removed. A file that turns out to be inside
/// its retention period is put back where it came from.
///
/// The `.sweeping` suffix cannot collide with a stored object: storage names
/// are hex of a 32-byte key plus `.pvm`/`.pvd`, and this adds a suffix no
/// storage path produces. A crash between the two renames leaves one such file
/// behind, which the next sweep re-evaluates on its own age -- material is
/// never lost, at worst it lingers one interval longer.
fn claim_and_remove_if_expired(path: &Path, cutoff: SystemTime) -> Result<bool, StorageError> {
    let claimed = path.with_extension("sweeping");
    match fs::rename(path, &claimed) {
        Ok(()) => {}
        // Already gone: another sweep, or a purge, got there first.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    }

    let expired = fs::metadata(&claimed)
        .and_then(|data| data.modified())
        .is_ok_and(|modified| modified < cutoff);

    if expired {
        remove_file_if_present(&claimed)?;
        sync_parent_directory(&claimed)?;
        return Ok(true);
    }

    // Fresh after all. Put it back. If a newer write has already taken the
    // path, keep that one and drop this older copy rather than overwriting
    // current material with what we moved aside.
    if path.exists() {
        remove_file_if_present(&claimed)?;
    } else {
        fs::rename(&claimed, path)?;
    }
    Ok(false)
}

/// Makes a just-created or just-removed directory entry durable.
///
/// POSIX requires fsync on the containing directory for a rename or unlink to
/// survive a crash; syncing the file alone is not enough. Windows has no
/// equivalent operation on a directory handle from safe std, and its rename is
/// already ordered against the file data by the filesystem, so this is a no-op
/// there rather than a silently skipped guarantee -- stated so that nobody
/// later reads the absence as an oversight.
#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), StorageError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "matches the unix signature, which genuinely can fail"
)]
fn sync_parent_directory(_path: &Path) -> Result<(), StorageError> {
    Ok(())
}

fn remove_file_if_present(path: &Path) -> Result<(), StorageError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn remove_record_objects(
    directory: &Path,
    storage_key: &[u8; 32],
    extension: &str,
) -> Result<(), StorageError> {
    let encoded = hex::encode(storage_key);
    let legacy_name = format!("{encoded}.{extension}");
    let version_prefix = format!("{encoded}.");
    let version_suffix = format!(".{extension}");
    let mut result = Ok(());
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let is_legacy = name == legacy_name;
        let is_versioned = name
            .strip_prefix(&version_prefix)
            .and_then(|remaining| remaining.strip_suffix(&version_suffix))
            .is_some_and(|generation| {
                generation.len() == 20 && generation.bytes().all(|byte| byte.is_ascii_digit())
            });
        if is_legacy || is_versioned {
            let removal = remove_file_if_present(&entry.path());
            result = result.and(removal);
        }
    }
    result
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), StorageError> {
    File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "matches the unix signature, which genuinely can fail"
)]
fn sync_directory(_directory: &Path) -> Result<(), StorageError> {
    Ok(())
}

struct LocalPendingDocument {
    file: Option<File>,
    temporary: PathBuf,
    target: PathBuf,
    committed: bool,
}

impl Write for LocalPendingDocument {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.file
            .as_mut()
            .expect("pending document owns its file until commit")
            .write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file
            .as_mut()
            .expect("pending document owns its file until commit")
            .flush()
    }
}

impl PendingDocument for LocalPendingDocument {
    fn commit(mut self: Box<Self>) -> Result<(), StorageError> {
        let file = self
            .file
            .take()
            .expect("pending document owns its file until commit");
        file.sync_all()?;
        drop(file);
        fs::rename(&self.temporary, &self.target)?;
        // Same reasoning as store_value_map: the rename's directory entry is
        // not durable until the directory is synced, and commit returning
        // success is what tells the caller its document is safely stored.
        sync_parent_directory(&self.target)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for LocalPendingDocument {
    fn drop(&mut self) {
        if !self.committed {
            self.file.take();
            let _ignored = fs::remove_file(&self.temporary);
        }
    }
}

struct LocalGenerationRead {
    _lock: File,
    generation: Option<u64>,
}

impl GenerationRead for LocalGenerationRead {
    fn generation(&self) -> Option<u64> {
        self.generation
    }
}

struct LocalGenerationTransaction {
    _lock: File,
    metadata_path: PathBuf,
    record_key: [u8; 32],
    generation: Option<u64>,
}

impl GenerationRead for LocalGenerationTransaction {
    fn generation(&self) -> Option<u64> {
        self.generation
    }
}

impl GenerationTransaction for LocalGenerationTransaction {
    fn compare_and_swap(&mut self, expected: Option<u64>, next: u64) -> Result<(), StorageError> {
        if self.generation != expected {
            return Err(StorageError::GenerationConflict);
        }
        if next == 0 || expected.is_some_and(|current| next <= current) {
            return Err(StorageError::InvalidMetadata);
        }
        write_generation_file(&self.metadata_path, &self.record_key, next)?;
        self.generation = Some(next);
        Ok(())
    }
}

fn open_generation_lock(path: &Path) -> Result<File, StorageError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    set_private_file_permissions(&file)?;
    Ok(file)
}

fn encode_generation(record_key: &[u8; 32], generation: u64) -> [u8; GENERATION_FILE_BYTES] {
    let mut bytes = [0_u8; GENERATION_FILE_BYTES];
    bytes[..8].copy_from_slice(GENERATION_MAGIC);
    bytes[8..16].copy_from_slice(&generation.to_be_bytes());
    let mut digest_input = Vec::with_capacity(record_key.len() + 16);
    digest_input.extend_from_slice(record_key);
    digest_input.extend_from_slice(&bytes[..16]);
    bytes[16..].copy_from_slice(&Sha256::digest(&digest_input));
    bytes
}

fn decode_generation(bytes: &[u8], record_key: &[u8; 32]) -> Option<u64> {
    if bytes.len() != GENERATION_FILE_BYTES || &bytes[..8] != GENERATION_MAGIC {
        return None;
    }
    let mut digest_input = Vec::with_capacity(record_key.len() + 16);
    digest_input.extend_from_slice(record_key);
    digest_input.extend_from_slice(&bytes[..16]);
    let digest = Sha256::digest(&digest_input);
    if &bytes[16..] != digest.as_slice() {
        return None;
    }
    let generation = u64::from_be_bytes(bytes[8..16].try_into().ok()?);
    (generation != 0).then_some(generation)
}

fn read_generation_file(path: &Path, record_key: &[u8; 32]) -> Result<Option<u64>, StorageError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() != GENERATION_FILE_BYTES {
        return Err(StorageError::InvalidMetadata);
    }
    decode_generation(&bytes, record_key)
        .map(Some)
        .ok_or(StorageError::InvalidMetadata)
}

fn write_generation_file(
    path: &Path,
    record_key: &[u8; 32],
    generation: u64,
) -> Result<(), StorageError> {
    let mut random = [0_u8; 16];
    OsRng.fill_bytes(&mut random);
    let temporary = path.with_extension(format!("{}.tmp", hex::encode(random)));
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        set_private_file_permissions(&file)?;
        file.write_all(&encode_generation(record_key, generation))?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        sync_parent_directory(path)
    })();
    if write_result.is_err() {
        let _ignored = fs::remove_file(&temporary);
    }
    write_result
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;

    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> Result<(), StorageError> {
    fs::create_dir_all(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(file: &File) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "matches the Unix implementation, which can fail"
)]
fn set_private_file_permissions(_file: &File) -> Result<(), StorageError> {
    Ok(())
}

#[derive(Clone, Copy)]
struct State {
    salt: [u8; 16],
    instance_id: [u8; 11],
    next_counter: u64,
    /// Monotonic write generation. Decides which slot is live; never reused.
    generation: u64,
}

/// Serialise one slot with its checksum.
fn encode_slot(state: &State) -> [u8; SLOT_BYTES] {
    let mut bytes = [0; SLOT_BYTES];
    bytes[..8].copy_from_slice(STATE_MAGIC);
    bytes[8..16].copy_from_slice(&state.generation.to_be_bytes());
    bytes[16..32].copy_from_slice(&state.salt);
    bytes[32..43].copy_from_slice(&state.instance_id);
    bytes[43..51].copy_from_slice(&state.next_counter.to_be_bytes());
    let digest = Sha256::digest(&bytes[..51]);
    bytes[51..].copy_from_slice(&digest);
    bytes
}

/// Parse one slot, returning `None` when it is absent, torn or corrupt.
///
/// A damaged slot is not an error. It is the expected state of the slot that
/// was mid-write when the power went, and the whole point of keeping two.
fn decode_slot(bytes: &[u8]) -> Option<State> {
    if bytes.len() < SLOT_BYTES || &bytes[..8] != STATE_MAGIC {
        return None;
    }
    let digest = Sha256::digest(&bytes[..51]);
    // Constant time is unnecessary here: this is an integrity check against
    // power loss, not a secret comparison, and the input is not attacker-chosen
    // in the sense that would make timing meaningful.
    if digest.as_slice() != &bytes[51..SLOT_BYTES] {
        return None;
    }
    let mut generation = [0; 8];
    generation.copy_from_slice(&bytes[8..16]);
    let mut salt = [0; 16];
    salt.copy_from_slice(&bytes[16..32]);
    let mut instance_id = [0; 11];
    instance_id.copy_from_slice(&bytes[32..43]);
    let mut counter = [0; 8];
    counter.copy_from_slice(&bytes[43..51]);
    Some(State {
        salt,
        instance_id,
        next_counter: u64::from_be_bytes(counter),
        generation: u64::from_be_bytes(generation),
    })
}

fn read_state(file: &mut File) -> Result<State, StorageError> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = [0; STATE_BYTES];
    file.read_exact(&mut bytes)
        .map_err(|_| StorageError::InvalidMetadata)?;

    // Highest valid generation wins. One torn slot is survivable and expected;
    // both invalid means we cannot establish where the nonce counter had
    // reached, and continuing from a guess is how a nonce gets reissued. Fail
    // closed: a vault that will not open is recoverable from backup, a vault
    // that reuses a nonce is not.
    let first = decode_slot(&bytes[..SLOT_BYTES]);
    let second = decode_slot(&bytes[SLOT_BYTES..]);
    match (first, second) {
        (Some(a), Some(b)) => Ok(if a.generation >= b.generation { a } else { b }),
        (Some(only), None) | (None, Some(only)) => Ok(only),
        (None, None) => Err(StorageError::InvalidMetadata),
    }
}

fn write_state(file: &mut File, state: &State) -> Result<(), StorageError> {
    // Write the slot the live record is NOT in, so a torn write cannot damage
    // the only copy of where the nonce counter had reached.
    let mut next = *state;
    next.generation = state.generation.wrapping_add(1);
    let offset = if next.generation.is_multiple_of(2) {
        0
    } else {
        SLOT_BYTES
    };

    let encoded = encode_slot(&next);
    file.seek(SeekFrom::Start(
        u64::try_from(offset).expect("slot offset fits in u64"),
    ))?;
    file.write_all(&encoded)?;
    // Sync before the caller is allowed to use the prefix. A returned nonce
    // whose increment is still in the page cache is a nonce this vault can
    // issue twice.
    file.sync_all()?;
    Ok(())
}
