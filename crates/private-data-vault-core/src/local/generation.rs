//! Trusted record generations: one checksummed `generations/<record>.pvg`
//! file per record, read under a shared lock and advanced by compare-and-swap
//! under an exclusive one.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use fs2::FileExt;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use super::{set_private_file_permissions, sync_parent_directory};
use crate::{GenerationRead, GenerationTransaction, StorageError};

const GENERATION_MAGIC: &[u8; 8] = b"PDVGEN01";
const GENERATION_FILE_BYTES: usize = 8 + 8 + 32;

/// Opens a shared snapshot of one record's trusted generation.
pub(super) fn begin_read(
    lock_path: &Path,
    metadata_path: &Path,
    record_key: &[u8; 32],
) -> Result<Box<dyn GenerationRead>, StorageError> {
    let lock = open_generation_lock(lock_path)?;
    fs2::FileExt::lock_shared(&lock)?;
    let generation = read_generation_file(metadata_path, record_key)?;
    Ok(Box::new(LocalGenerationRead {
        _lock: lock,
        generation,
    }))
}

/// Opens an exclusive transaction over one record's trusted generation.
pub(super) fn begin_transaction(
    lock_path: &Path,
    metadata_path: PathBuf,
    record_key: &[u8; 32],
) -> Result<Box<dyn GenerationTransaction>, StorageError> {
    let lock = open_generation_lock(lock_path)?;
    lock.lock_exclusive()?;
    let generation = read_generation_file(&metadata_path, record_key)?;
    Ok(Box::new(LocalGenerationTransaction {
        _lock: lock,
        metadata_path,
        record_key: *record_key,
        generation,
    }))
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
