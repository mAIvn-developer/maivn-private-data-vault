use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};

use fs2::FileExt;
use rand_core::{OsRng, RngCore};

use crate::{
    ContentKind, GenerationRead, GenerationTransaction, PendingDocument, PurgeKeys, StorageBackend,
    StorageError,
};

mod generation;
mod state;
mod sweep;

use state::{State, read_state, write_state};
use sweep::sweep_directory;

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

    /// Where one sealed object lives: `<kind directory>/<hex key>.<extension>`
    /// for a standalone object, `<hex key>.<generation:020>.<extension>` for
    /// one generation of a record bundle.
    fn object_path(
        &self,
        storage_key: &[u8; 32],
        kind: ContentKind,
        generation: Option<u64>,
    ) -> PathBuf {
        let (directory, extension) = match kind {
            ContentKind::ValueMap => ("values", "pvm"),
            ContentKind::Document => ("documents", "pvd"),
            ContentKind::Original => ("originals", "pvo"),
        };
        let key = hex::encode(storage_key);
        let name = match generation {
            None => format!("{key}.{extension}"),
            Some(generation) => format!("{key}.{generation:020}.{extension}"),
        };
        self.root.join(directory).join(name)
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
        generation::begin_read(
            &self.generation_lock_path(record_key),
            &self.generation_path(record_key),
            record_key,
        )
    }

    fn begin_generation_transaction(
        &self,
        record_key: &[u8; 32],
    ) -> Result<Box<dyn GenerationTransaction>, StorageError> {
        generation::begin_transaction(
            &self.generation_lock_path(record_key),
            self.generation_path(record_key),
            record_key,
        )
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
        store_sealed_value(
            &self.object_path(storage_key, ContentKind::ValueMap, None),
            sealed,
        )
    }

    fn load_value_map(&self, storage_key: &[u8; 32]) -> Result<Vec<u8>, StorageError> {
        read_sealed_value(&self.object_path(storage_key, ContentKind::ValueMap, None))
    }

    fn store_versioned_value_map(
        &self,
        storage_key: &[u8; 32],
        generation: u64,
        sealed: &[u8],
    ) -> Result<(), StorageError> {
        store_sealed_value(
            &self.object_path(storage_key, ContentKind::ValueMap, Some(generation)),
            sealed,
        )
    }

    fn load_versioned_value_map(
        &self,
        storage_key: &[u8; 32],
        generation: u64,
    ) -> Result<Vec<u8>, StorageError> {
        read_sealed_value(&self.object_path(storage_key, ContentKind::ValueMap, Some(generation)))
    }

    fn begin_content(
        &self,
        storage_key: &[u8; 32],
        operation_nonce: &[u8; 19],
        kind: ContentKind,
    ) -> Result<Box<dyn PendingDocument>, StorageError> {
        begin_pending_content(self.object_path(storage_key, kind, None), operation_nonce)
    }

    fn open_content(
        &self,
        storage_key: &[u8; 32],
        kind: ContentKind,
    ) -> Result<Box<dyn Read + Send>, StorageError> {
        open_sealed_content(&self.object_path(storage_key, kind, None))
    }

    fn begin_versioned_content(
        &self,
        storage_key: &[u8; 32],
        operation_nonce: &[u8; 19],
        kind: ContentKind,
        generation: u64,
    ) -> Result<Box<dyn PendingDocument>, StorageError> {
        begin_pending_content(
            self.object_path(storage_key, kind, Some(generation)),
            operation_nonce,
        )
    }

    fn open_versioned_content(
        &self,
        storage_key: &[u8; 32],
        kind: ContentKind,
        generation: u64,
    ) -> Result<Box<dyn Read + Send>, StorageError> {
        open_sealed_content(&self.object_path(storage_key, kind, Some(generation)))
    }

    fn purge(&self, keys: &PurgeKeys) -> Result<(), StorageError> {
        let generation_path = self.generation_path(&keys.record);
        let value_directory = self.root.join("values");
        let document_directory = self.root.join("documents");
        let original_directory = self.root.join("originals");
        // Every removal and sync is attempted; the first failure, in this
        // order, is the result.
        //
        // An unlink is no more durable than a rename. Without syncing the
        // directory, a purge can report success and a crash moments later
        // restore the entry -- which for a HARD DELETE is the whole claim
        // failing, not a performance detail. Owner ruling 2026-08-05: private
        // material is removed, not marked, and material that comes back was
        // never removed.
        [
            remove_record_objects(&value_directory, &keys.legacy_value_map, "pvm"),
            remove_record_objects(&document_directory, &keys.legacy_document, "pvd"),
            remove_record_objects(&original_directory, &keys.legacy_original, "pvo"),
            remove_record_objects(&value_directory, &keys.versioned_value_map, "pvm"),
            remove_record_objects(&document_directory, &keys.versioned_document, "pvd"),
            remove_record_objects(&original_directory, &keys.versioned_original, "pvo"),
            remove_file_if_present(&generation_path),
            sync_directory(&value_directory),
            sync_directory(&document_directory),
            sync_directory(&original_directory),
            sync_parent_directory(&generation_path),
        ]
        .into_iter()
        .collect()
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

/// `<64 hex record key>.<32 hex nonce>.tmp`, the name of an interrupted
/// generation-file write.
fn is_generation_temporary(name: &str) -> bool {
    let is_lower_hex = |value: &str, length: usize| {
        value.len() == length
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    let mut components = name.split('.');
    components.next().is_some_and(|key| is_lower_hex(key, 64))
        && components
            .next()
            .is_some_and(|nonce| is_lower_hex(nonce, 32))
        && components.next() == Some("tmp")
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

/// Makes a just-created or just-removed directory entry durable.
fn sync_parent_directory(path: &Path) -> Result<(), StorageError> {
    path.parent().map_or(Ok(()), sync_directory)
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

/// POSIX requires fsync on the containing directory for a rename or unlink to
/// survive a crash; syncing the file alone is not enough. Windows has no
/// equivalent operation on a directory handle from safe std, and its rename is
/// already ordered against the file data by the filesystem, so this is a no-op
/// there rather than a silently skipped guarantee -- stated so that nobody
/// later reads the absence as an oversight.
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
