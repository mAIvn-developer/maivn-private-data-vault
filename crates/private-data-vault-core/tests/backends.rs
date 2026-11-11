//! The storage-backend contract, exercised identically against the local and
//! the in-memory backend, plus each backend's own failure handling.

use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Write},
    path::Path,
    time::{Duration, SystemTime},
};

use private_data_vault_core::{
    ContentKind, KeyVersion, LocalBackend, MemoryBackend, RecordIdentity, StorageBackend,
    StorageError, Vault, VaultError,
};
use tempfile::tempdir;

const KEY: [u8; 32] = [9; 32];

fn identity(record: &str) -> RecordIdentity {
    RecordIdentity::new("tenant", record).expect("identity")
}

fn values(value: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("[NAME_1]".to_owned(), value.to_owned())])
}

fn load_document<B: StorageBackend>(vault: &Vault<B>, record: &RecordIdentity) -> Vec<u8> {
    let mut output = Vec::new();
    vault
        .load_document(record, &mut output)
        .expect("document opens");
    output
}

fn load_original<B: StorageBackend>(vault: &Vault<B>, record: &RecordIdentity) -> Vec<u8> {
    let mut output = Vec::new();
    vault
        .load_original(record, &mut output)
        .expect("original opens");
    output
}

/// Standalone (pre-generation) records: value maps, documents and originals
/// stored one kind at a time, merged, purged and swept.
fn standalone_records_round_trip<B: StorageBackend>(vault: &Vault<B>) {
    let record = identity("standalone");
    vault
        .merge_value_map(&record, &values("first"))
        .expect("merge into an absent record");
    vault
        .merge_value_map(
            &record,
            &BTreeMap::from([("[EMAIL_1]".to_owned(), "a@example.invalid".to_owned())]),
        )
        .expect("merge into an existing record");
    let mut merged = values("first");
    merged.insert("[EMAIL_1]".to_owned(), "a@example.invalid".to_owned());
    assert_eq!(vault.load_value_map(&record).expect("loads"), merged);
    vault
        .store_value_map(&record, &values("replaced"))
        .expect("store replaces");
    assert_eq!(
        vault.load_value_map(&record).expect("loads"),
        values("replaced")
    );

    vault
        .store_document(&record, &mut Cursor::new(b"redacted"))
        .expect("document stores");
    vault
        .store_original(&record, &mut Cursor::new(b"original"))
        .expect("original stores");
    assert_eq!(load_document(vault, &record), b"redacted");
    assert_eq!(load_original(vault, &record), b"original");

    vault.purge(&record).expect("purges");
    assert!(matches!(
        vault.load_value_map(&record),
        Err(VaultError::Storage(StorageError::NotFound))
    ));
    assert!(matches!(
        vault.load_document(&record, &mut Vec::new()),
        Err(VaultError::Storage(StorageError::NotFound))
    ));
    vault
        .purge(&record)
        .expect("purging an absent record succeeds");
}

fn sweeping_respects_the_cutoff<B: StorageBackend>(vault: &Vault<B>) {
    let record = identity("swept");
    vault
        .store_record(
            &record,
            &mut Cursor::new(b"original"),
            &mut Cursor::new(b"document"),
            &values("v"),
        )
        .expect("stores");
    let past = SystemTime::now() - Duration::from_hours(1);
    assert_eq!(vault.purge_expired(past).expect("sweeps"), 0);
    let future = SystemTime::now() + Duration::from_hours(1);
    assert_eq!(vault.purge_expired(future).expect("sweeps"), 3);
    assert!(vault.load_value_map(&record).is_err());
}

/// Trait-level generation rules shared by every backend.
fn generation_transactions_compare_and_swap<B: StorageBackend>(backend: &B) {
    assert_eq!(backend.read_generation(&KEY).expect("reads"), None);
    backend
        .compare_and_swap_generation(&KEY, None, 1)
        .expect("first publication");
    assert_eq!(backend.read_generation(&KEY).expect("reads"), Some(1));
    assert!(matches!(
        backend.compare_and_swap_generation(&KEY, None, 2),
        Err(StorageError::GenerationConflict)
    ));
    assert!(matches!(
        backend.compare_and_swap_generation(&KEY, Some(7), 8),
        Err(StorageError::GenerationConflict)
    ));
    backend
        .compare_and_swap_generation(&KEY, Some(1), 2)
        .expect("advances");
    assert_eq!(backend.read_generation(&KEY).expect("reads"), Some(2));
}

/// Reusing a nonce prefix under one key would expose plaintext: every
/// reservation must differ from every other.
fn nonce_prefixes_never_repeat<B: StorageBackend>(backend: &B) {
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..200 {
        assert!(seen.insert(backend.reserve_nonce_prefix().expect("reserves")));
    }
}

/// An uncommitted sink stores nothing; flushing it is harmless.
fn an_abandoned_write_leaves_nothing<B: StorageBackend>(backend: &B) {
    let nonce = [5; 19];
    for generation in [None, Some(3)] {
        let mut pending = match generation {
            None => backend.begin_content(&KEY, &nonce, ContentKind::Document),
            Some(generation) => {
                backend.begin_versioned_content(&KEY, &nonce, ContentKind::Document, generation)
            }
        }
        .expect("sink opens");
        pending.write_all(b"partial").expect("writes");
        pending.flush().expect("flushes");
        drop(pending);
        let opened = match generation {
            None => backend.open_content(&KEY, ContentKind::Document),
            Some(generation) => {
                backend.open_versioned_content(&KEY, ContentKind::Document, generation)
            }
        };
        assert!(matches!(opened, Err(StorageError::NotFound)));
    }
}

/// Purging one record hard-deletes all its ciphertext and nothing else.
fn purge_removes_exactly_one_record<B: StorageBackend>(vault: &Vault<B>) {
    for record in ["kept", "purged"] {
        vault
            .store_record(
                &identity(record),
                &mut Cursor::new(b"o"),
                &mut Cursor::new(b"d"),
                &values(record),
            )
            .expect("stores");
    }
    vault.purge(&identity("purged")).expect("purges");

    assert_eq!(
        vault
            .backend()
            .list_record_keys(None, 10)
            .expect("lists")
            .len(),
        1,
        "the purged record's generation is gone"
    );
    assert_eq!(
        vault.load_value_map(&identity("kept")).expect("kept"),
        values("kept")
    );
    let future = SystemTime::now() + Duration::from_hours(1);
    assert_eq!(
        vault.purge_expired(future).expect("sweeps"),
        3,
        "only the kept record's three objects were left to sweep"
    );
}

fn rotation_walks_every_record<B: StorageBackend>(vault: &Vault<B>) {
    for record in ["r1", "r2", "r3"] {
        vault
            .store_record(
                &identity(record),
                &mut Cursor::new(b"o"),
                &mut Cursor::new(b"d"),
                &values(record),
            )
            .expect("stores");
    }
    let active = KeyVersion::new(1).expect("version");
    let first = vault.reencrypt_batch(active, None, 2).expect("first batch");
    assert_eq!((first.visited, first.rewritten), (2, 0));
    let second = vault
        .reencrypt_batch(active, first.next_cursor.as_ref(), 2)
        .expect("second batch");
    assert_eq!((second.visited, second.rewritten), (1, 0));
    assert!(second.next_cursor.is_none());
}

#[test]
fn the_memory_backend_meets_the_storage_contract() {
    let vault = || Vault::open(MemoryBackend::new([1; 16]), b"secret").expect("vault opens");
    standalone_records_round_trip(&vault());
    sweeping_respects_the_cutoff(&vault());
    rotation_walks_every_record(&vault());
    purge_removes_exactly_one_record(&vault());
    generation_transactions_compare_and_swap(&MemoryBackend::new([1; 16]));
    an_abandoned_write_leaves_nothing(&MemoryBackend::new([1; 16]));
    nonce_prefixes_never_repeat(&MemoryBackend::new([1; 16]));
}

#[test]
fn the_local_backend_meets_the_storage_contract() {
    let directories: Vec<_> = (0..6).map(|_| tempdir().expect("directory")).collect();
    let vault = |index: usize| {
        Vault::open(
            LocalBackend::open(directories[index].path()).expect("backend opens"),
            b"secret",
        )
        .expect("vault opens")
    };
    standalone_records_round_trip(&vault(0));
    sweeping_respects_the_cutoff(&vault(1));
    rotation_walks_every_record(&vault(2));
    purge_removes_exactly_one_record(&vault(5));
    generation_transactions_compare_and_swap(
        &LocalBackend::open(directories[3].path()).expect("backend opens"),
    );
    an_abandoned_write_leaves_nothing(
        &LocalBackend::open(directories[4].path()).expect("backend opens"),
    );
    nonce_prefixes_never_repeat(&LocalBackend::open(directories[4].path()).expect("backend opens"));
    for directory in ["documents", "originals"] {
        let leftovers = fs::read_dir(directories[4].path().join(directory))
            .expect("directory")
            .count();
        assert_eq!(leftovers, 0, "no temporary file survives in {directory}");
    }
}

#[test]
fn local_generations_only_move_forward() {
    let directory = tempdir().expect("directory");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let mut transaction = backend
        .begin_generation_transaction(&KEY)
        .expect("transaction");
    assert!(matches!(
        transaction.compare_and_swap(None, 0),
        Err(StorageError::InvalidMetadata)
    ));
    transaction.compare_and_swap(None, 5).expect("publishes");
    assert!(matches!(
        transaction.compare_and_swap(Some(5), 5),
        Err(StorageError::InvalidMetadata)
    ));
    assert!(matches!(
        transaction.compare_and_swap(Some(5), 4),
        Err(StorageError::InvalidMetadata)
    ));
    assert_eq!(transaction.generation(), Some(5));
}

fn state_slot(generation: u64, counter: u64) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut slot = b"PDVST002".to_vec();
    slot.extend_from_slice(&generation.to_be_bytes());
    slot.extend_from_slice(&[1; 16]);
    slot.extend_from_slice(&[2; 11]);
    slot.extend_from_slice(&counter.to_be_bytes());
    let checksum = Sha256::digest(&slot);
    slot.extend_from_slice(&checksum);
    slot
}

#[test]
fn an_exhausted_nonce_counter_refuses_to_seal() {
    let directory = tempdir().expect("directory");
    let mut state = state_slot(2, u64::MAX);
    state.extend(state_slot(1, u64::MAX - 1));
    fs::write(directory.path().join("vault.state"), &state).expect("state");

    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    assert!(matches!(
        backend.reserve_nonce_prefix(),
        Err(StorageError::NonceExhausted)
    ));
    let vault = Vault::open(backend, b"secret").expect("vault opens");
    assert!(matches!(
        vault.store_value_map(&identity("r"), &values("v")),
        Err(VaultError::Storage(StorageError::NonceExhausted))
    ));
    assert_eq!(
        fs::read(directory.path().join("vault.state")).expect("state"),
        state,
        "a refused reservation writes nothing"
    );
}

#[test]
fn malformed_generation_metadata_fails_closed() {
    let directory = tempdir().expect("directory");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    backend
        .compare_and_swap_generation(&KEY, None, 1)
        .expect("publishes");
    let path = directory
        .path()
        .join("generations")
        .join(format!("{}.pvg", hex::encode(KEY)));
    let valid = fs::read(&path).expect("generation file");

    fs::write(&path, []).expect("empty");
    assert_eq!(backend.read_generation(&KEY).expect("reads"), None);

    let mut wrong_magic = valid.clone();
    wrong_magic[0] ^= 1;
    let mut wrong_checksum = valid.clone();
    *wrong_checksum.last_mut().expect("checksum") ^= 1;
    let mut zero_generation = b"PDVGEN01".to_vec();
    zero_generation.extend_from_slice(&0_u64.to_be_bytes());
    zero_generation.extend_from_slice(&valid[16..]);
    for damaged in [
        wrong_magic,
        wrong_checksum,
        zero_generation,
        valid[..20].to_vec(),
    ] {
        fs::write(&path, &damaged).expect("damage");
        assert!(matches!(
            backend.read_generation(&KEY),
            Err(StorageError::InvalidMetadata)
        ));
    }
}

/// Puts something into a fresh vault's `generations` directory.
type Plant = fn(&Path);

#[test]
fn record_enumeration_refuses_anything_but_generation_files() {
    let cases: [(&str, Plant); 5] = [
        ("a directory", |generations| {
            fs::create_dir(generations.join("nested")).expect("directory");
        }),
        ("a foreign name", |generations| {
            fs::write(generations.join("notes.txt"), b"x").expect("file");
        }),
        ("a short key", |generations| {
            fs::write(generations.join("abcd.pvg"), b"x").expect("file");
        }),
        ("a non-hex key", |generations| {
            fs::write(generations.join(format!("{}.pvg", "z".repeat(64))), b"x").expect("file");
        }),
        (
            "a temporary-looking name with another extension",
            |generations| {
                let name = format!("{}.{}.bak", "a".repeat(64), "0".repeat(32));
                fs::write(generations.join(name), b"x").expect("file");
            },
        ),
    ];
    for (label, plant) in cases {
        let directory = tempdir().expect("directory");
        let backend = LocalBackend::open(directory.path()).expect("backend opens");
        plant(&directory.path().join("generations"));
        assert!(
            matches!(
                backend.list_record_keys(None, 10),
                Err(StorageError::InvalidMetadata)
            ),
            "{label} must be refused"
        );
    }
}

#[test]
fn record_enumeration_skips_interrupted_writes_and_pages_in_key_order() {
    let directory = tempdir().expect("directory");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let keys = [[3; 32], [1; 32], [2; 32]];
    for key in keys {
        backend
            .compare_and_swap_generation(&key, None, 1)
            .expect("publishes");
    }
    fs::write(
        directory.path().join("generations").join(format!(
            "{}.{}.tmp",
            hex::encode([4; 32]),
            "0".repeat(32)
        )),
        b"partial",
    )
    .expect("temporary file");

    assert_eq!(
        backend.list_record_keys(None, 2).expect("lists"),
        vec![[1; 32], [2; 32]]
    );
    assert_eq!(
        backend.list_record_keys(Some(&[1; 32]), 5).expect("lists"),
        vec![[2; 32], [3; 32]]
    );
}

#[test]
fn the_local_backend_stores_only_sealed_value_maps() {
    let directory = tempdir().expect("directory");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    for junk in [
        &b"short"[..],
        b"NOTAMAP0 plus enough bytes to look like a header......",
    ] {
        assert!(matches!(
            backend.store_value_map(&KEY, junk),
            Err(StorageError::InvalidSealedObject)
        ));
        assert!(matches!(
            backend.store_versioned_value_map(&KEY, 1, junk),
            Err(StorageError::InvalidSealedObject)
        ));
    }
    assert_eq!(
        fs::read_dir(directory.path().join("values"))
            .expect("values")
            .count(),
        0
    );
}

#[test]
fn an_unreadable_object_is_a_storage_failure_not_a_missing_record() {
    let directory = tempdir().expect("directory");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    fs::create_dir(
        directory
            .path()
            .join("values")
            .join(format!("{}.pvm", hex::encode(KEY))),
    )
    .expect("a directory where the object should be");

    assert!(matches!(
        backend.load_value_map(&KEY),
        Err(StorageError::Io(_))
    ));
}

#[test]
fn sweeping_leaves_directories_alone() {
    let directory = tempdir().expect("directory");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    fs::create_dir(directory.path().join("values").join("nested")).expect("directory");
    let future = SystemTime::now() + Duration::from_hours(1);

    assert_eq!(backend.purge_expired(future).expect("sweeps"), 0);
    assert!(directory.path().join("values").join("nested").is_dir());
}

#[test]
fn sweeping_tolerates_a_missing_directory_and_reports_an_unreadable_one() {
    let directory = tempdir().expect("directory");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let future = SystemTime::now() + Duration::from_hours(1);
    fs::remove_dir(directory.path().join("originals")).expect("remove");
    assert_eq!(backend.purge_expired(future).expect("sweeps"), 0);

    fs::remove_dir(directory.path().join("values")).expect("remove");
    fs::write(directory.path().join("values"), b"not a directory").expect("file");
    assert!(matches!(
        backend.purge_expired(future),
        Err(StorageError::Io(_))
    ));
}

/// A minimal object the local backend accepts as a sealed value map.
fn sealed_value_map() -> Vec<u8> {
    let mut sealed = b"PDVMAP02".to_vec();
    sealed.resize(64, 1);
    sealed
}

#[test]
fn a_failed_value_map_write_leaves_no_temporary_file() {
    let directory = tempdir().expect("directory");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let values = directory.path().join("values");
    fs::create_dir(values.join(format!("{}.pvm", hex::encode(KEY)))).expect("blocking directory");

    assert!(matches!(
        backend.store_value_map(&KEY, &sealed_value_map()),
        Err(StorageError::Io(_))
    ));
    let names: Vec<_> = fs::read_dir(&values)
        .expect("values")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    assert_eq!(
        names.len(),
        1,
        "only the blocking directory remains: {names:?}"
    );
}

#[test]
fn purge_removes_only_names_it_owns() {
    let directory = tempdir().expect("directory");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let vault = Vault::open(backend, b"secret").expect("vault opens");
    let record = identity("owned");
    vault
        .store_record(
            &record,
            &mut Cursor::new(b"o"),
            &mut Cursor::new(b"d"),
            &values("v"),
        )
        .expect("stores");
    let values_directory = directory.path().join("values");
    let versioned = fs::read_dir(&values_directory)
        .expect("values")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .find(|name| name.ends_with(".00000000000000000001.pvm"))
        .expect("versioned value map");
    let key = versioned.split('.').next().expect("key").to_owned();
    let lookalikes = [
        format!("{key}.1.pvm"),
        format!("{key}.0000000000000000000x.pvm"),
        format!("{key}.00000000000000000001.pvd"),
        format!("{key}.pvm.bak"),
    ];
    for name in &lookalikes {
        fs::write(values_directory.join(name), b"x").expect("lookalike");
    }

    vault.purge(&record).expect("purges");

    let mut remaining: Vec<_> = fs::read_dir(&values_directory)
        .expect("values")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    remaining.sort();
    let mut expected = lookalikes.to_vec();
    expected.sort();
    assert_eq!(remaining, expected);
}

#[test]
fn unreadable_generation_metadata_is_a_storage_failure() {
    let directory = tempdir().expect("directory");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    fs::create_dir(
        directory
            .path()
            .join("generations")
            .join(format!("{}.pvg", hex::encode(KEY))),
    )
    .expect("a directory where the metadata should be");

    assert!(matches!(
        backend.read_generation(&KEY),
        Err(StorageError::Io(_))
    ));
}

#[test]
fn a_state_slot_whose_checksum_fails_is_ignored() {
    let directory = tempdir().expect("directory");
    // The higher generation's counter was altered without its checksum.
    let mut tampered = state_slot(6, 40);
    tampered[43..51].copy_from_slice(&7_u64.to_be_bytes());
    let mut state = tampered;
    state.extend(state_slot(5, 39));
    fs::write(directory.path().join("vault.state"), &state).expect("state");

    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let prefix = backend.reserve_nonce_prefix().expect("reserves");
    assert_eq!(prefix[11..], 39_u64.to_be_bytes());
}

/// Opaque addresses as the vault computes them (see `golden_vectors.rs`).
fn record_key(tenant: &str, record: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut encoded = b"maivn-private-data-vault:record-key:v1".to_vec();
    for field in [tenant, record] {
        encoded.extend_from_slice(&(field.len() as u64).to_be_bytes());
        encoded.extend_from_slice(field.as_bytes());
    }
    Sha256::digest(encoded).into()
}

fn storage_key(record_key: &[u8; 32], kind: ContentKind) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut encoded = b"maivn-private-data-vault:storage-key:v2".to_vec();
    encoded.extend_from_slice(record_key);
    encoded.push(kind as u8);
    Sha256::digest(encoded).into()
}

#[test]
fn a_record_missing_any_object_never_exports() {
    let kinds = [
        ContentKind::Original,
        ContentKind::Document,
        ContentKind::ValueMap,
    ];
    let record = record_key("tenant", "partial");
    for missing in kinds {
        let backend = MemoryBackend::new([1; 16]);
        backend.hydrate_generation(record, 1).expect("imports");
        for kind in kinds.into_iter().filter(|kind| *kind != missing) {
            backend.hydrate_object(
                storage_key(&record, kind),
                kind,
                Some(1),
                b"sealed".to_vec(),
            );
        }
        assert!(
            backend.export_record(&identity("partial")).is_none(),
            "{missing:?} is missing, so the record must not export"
        );
    }
}
