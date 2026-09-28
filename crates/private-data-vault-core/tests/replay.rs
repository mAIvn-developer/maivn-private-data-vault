use std::{
    collections::BTreeMap,
    fs,
    io::{self, Cursor, Read},
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
};

use private_data_vault_core::{
    LocalBackend, RecordIdentity, StorageBackend, StorageError, Vault, VaultError,
};

fn identity() -> RecordIdentity {
    RecordIdentity::new("tenant-a", "generation-record").expect("test identity is valid")
}

fn values(value: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("<PRIVATE_1>".to_owned(), value.to_owned())])
}

fn blob_for_generation(directory: &Path, generation: u64) -> PathBuf {
    fs::read_dir(directory)
        .expect("ciphertext directory exists")
        .map(|entry| entry.expect("ciphertext entry is readable").path())
        .find(|path| {
            let bytes = fs::read(path).expect("ciphertext is readable");
            bytes.get(12..20) == Some(generation.to_be_bytes().as_slice())
        })
        .expect("requested generation exists")
}

fn only_generation_file(root: &Path) -> PathBuf {
    let entries = fs::read_dir(root.join("generations"))
        .expect("generation directory exists")
        .collect::<Result<Vec<_>, _>>()
        .expect("generation directory is readable");
    assert_eq!(entries.len(), 1, "test stores exactly one record");
    entries[0].path()
}

fn record_key_from_generation_path(path: &Path) -> [u8; 32] {
    let encoded = path
        .file_stem()
        .and_then(|name| name.to_str())
        .expect("generation filename is UTF-8");
    hex::decode(encoded)
        .expect("generation filename is hex")
        .try_into()
        .expect("record key has 32 bytes")
}

struct FailingReader;

impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("synthetic source failure"))
    }
}

#[test]
fn generation_compare_and_swap_has_exactly_one_winner() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let record_key = [0xA5; 32];
    backend
        .compare_and_swap_generation(&record_key, None, 7)
        .expect("initial generation is committed");
    let barrier = Arc::new(Barrier::new(3));

    let handles = (0..2)
        .map(|_| {
            let backend = backend.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                backend.compare_and_swap_generation(&record_key, Some(7), 8)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("CAS thread completes"))
        .collect::<Vec<_>>();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StorageError::GenerationConflict)))
            .count(),
        1
    );
    assert_eq!(
        backend
            .read_generation(&record_key)
            .expect("generation is readable"),
        Some(8)
    );
}

#[test]
fn restored_older_ciphertext_is_rejected_before_plaintext_release() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = Vault::open(
        LocalBackend::open(directory.path()).expect("backend opens"),
        b"correct horse battery staple",
    )
    .expect("vault opens");
    let record = identity();

    vault
        .store_record(
            &record,
            &mut Cursor::new(b"generation-one original"),
            &mut Cursor::new(b"generation-one redacted"),
            &values("Ada Lovelace"),
        )
        .expect("generation one commits");
    let generation_one_value = fs::read(blob_for_generation(&directory.path().join("values"), 1))
        .expect("generation-one value map is readable");
    let generation_one_document =
        fs::read(blob_for_generation(&directory.path().join("documents"), 1))
            .expect("generation-one document is readable");

    vault
        .store_record(
            &record,
            &mut Cursor::new(b"generation-two original"),
            &mut Cursor::new(b"generation-two redacted"),
            &values("Grace Hopper"),
        )
        .expect("generation two commits");
    fs::write(
        blob_for_generation(&directory.path().join("values"), 2),
        generation_one_value,
    )
    .expect("older value ciphertext is restored over the current path");
    fs::write(
        blob_for_generation(&directory.path().join("documents"), 2),
        generation_one_document,
    )
    .expect("older document ciphertext is restored over the current path");

    assert!(matches!(
        vault.load_value_map(&record),
        Err(VaultError::RollbackDetected {
            trusted: 2,
            envelope: 1
        })
    ));
    let mut opened = Vec::new();
    assert!(matches!(
        vault.load_document(&record, &mut opened),
        Err(VaultError::RollbackDetected {
            trusted: 2,
            envelope: 1
        })
    ));
    assert!(opened.is_empty(), "no stale plaintext is released");
}

#[test]
fn failed_rewrite_leaves_the_prior_complete_bundle_authoritative() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = Vault::open(
        LocalBackend::open(directory.path()).expect("backend opens"),
        b"correct horse battery staple",
    )
    .expect("vault opens");
    let record = identity();
    vault
        .store_record(
            &record,
            &mut Cursor::new(b"generation-one original"),
            &mut Cursor::new(b"generation-one redacted"),
            &values("Ada Lovelace"),
        )
        .expect("generation one commits");

    let result = vault.store_record(
        &record,
        &mut Cursor::new(b"unpublished generation-two original"),
        &mut FailingReader,
        &values("Grace Hopper"),
    );

    assert!(matches!(result, Err(VaultError::DocumentIo(_))));
    assert_eq!(
        vault.load_value_map(&record).expect("prior values remain"),
        values("Ada Lovelace")
    );
    let mut original = Vec::new();
    vault
        .load_original(&record, &mut original)
        .expect("prior original remains");
    assert_eq!(original, b"generation-one original");
    let mut document = Vec::new();
    vault
        .load_document(&record, &mut document)
        .expect("prior document remains");
    assert_eq!(document, b"generation-one redacted");
}

#[test]
fn single_kind_writes_refuse_after_atomic_record_publication() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = Vault::open(
        LocalBackend::open(directory.path()).expect("backend opens"),
        b"correct horse battery staple",
    )
    .expect("vault opens");
    let record = identity();
    vault
        .store_record(
            &record,
            &mut Cursor::new(b"original"),
            &mut Cursor::new(b"redacted"),
            &values("Ada Lovelace"),
        )
        .expect("record commits");

    assert!(matches!(
        vault.store_value_map(&record, &values("Grace Hopper")),
        Err(VaultError::AtomicWriteRequired)
    ));
    assert!(matches!(
        vault.store_document(&record, &mut Cursor::new(b"replacement")),
        Err(VaultError::AtomicWriteRequired)
    ));
    assert!(matches!(
        vault.store_original(&record, &mut Cursor::new(b"replacement")),
        Err(VaultError::AtomicWriteRequired)
    ));
}

#[test]
fn higher_envelope_generation_is_rejected_before_authentication() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = Vault::open(
        LocalBackend::open(directory.path()).expect("backend opens"),
        b"correct horse battery staple",
    )
    .expect("vault opens");
    let record = identity();
    vault
        .store_record(
            &record,
            &mut Cursor::new(b"original"),
            &mut Cursor::new(b"redacted"),
            &values("Ada Lovelace"),
        )
        .expect("record commits");
    let path = blob_for_generation(&directory.path().join("values"), 1);
    let mut sealed = fs::read(&path).expect("value ciphertext is readable");
    sealed[12..20].copy_from_slice(&2_u64.to_be_bytes());
    fs::write(path, sealed).expect("higher envelope generation is written");

    assert!(matches!(
        vault.load_value_map(&record),
        Err(VaultError::RollbackDetected {
            trusted: 1,
            envelope: 2
        })
    ));
}

#[test]
fn missing_or_malformed_trusted_generation_fails_closed() {
    for mutation in ["missing", "truncated"] {
        let directory = tempfile::tempdir().expect("temporary directory is created");
        let vault = Vault::open(
            LocalBackend::open(directory.path()).expect("backend opens"),
            b"correct horse battery staple",
        )
        .expect("vault opens");
        let record = identity();
        vault
            .store_record(
                &record,
                &mut Cursor::new(b"original"),
                &mut Cursor::new(b"redacted"),
                &values("Ada Lovelace"),
            )
            .expect("record commits");
        let metadata = only_generation_file(directory.path());
        if mutation == "missing" {
            fs::remove_file(metadata).expect("trusted metadata is removed");
            assert!(matches!(
                vault.load_value_map(&record),
                Err(VaultError::Storage(StorageError::NotFound))
            ));
        } else {
            fs::write(metadata, [0xA5]).expect("trusted metadata is truncated");
            assert!(matches!(
                vault.load_value_map(&record),
                Err(VaultError::Storage(StorageError::InvalidMetadata))
            ));
        }
    }
}

#[test]
fn exhausted_generation_refuses_before_staging_a_rewrite() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let vault = Vault::open(backend.clone(), b"correct horse battery staple").expect("vault opens");
    let record = identity();
    vault
        .store_record(
            &record,
            &mut Cursor::new(b"generation-one original"),
            &mut Cursor::new(b"generation-one redacted"),
            &values("Ada Lovelace"),
        )
        .expect("generation one commits");
    let record_key = record_key_from_generation_path(&only_generation_file(directory.path()));
    backend
        .compare_and_swap_generation(&record_key, Some(1), u64::MAX)
        .expect("test advances trusted generation to the maximum");

    assert!(matches!(
        vault.store_record(
            &record,
            &mut Cursor::new(b"unreachable original"),
            &mut Cursor::new(b"unreachable redacted"),
            &values("Grace Hopper"),
        ),
        Err(VaultError::GenerationExhausted)
    ));
    assert!(
        blob_for_generation(&directory.path().join("values"), 1).exists(),
        "the prior ciphertext is untouched"
    );
}
