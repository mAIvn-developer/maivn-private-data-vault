use std::{
    collections::{BTreeMap, HashSet},
    fs,
    path::Path,
    sync::{Arc, Barrier},
    thread,
};

use private_data_vault_core::{LocalBackend, RecordIdentity, StorageBackend, Vault, VaultError};

fn identity(tenant: &str, record: &str) -> RecordIdentity {
    RecordIdentity::new(tenant, record).expect("test identity is valid")
}

fn values() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("<PRIVATE_1>".to_owned(), "Ada Lovelace".to_owned()),
        (
            "<PRIVATE_2>".to_owned(),
            "ada.lovelace@example.test".to_owned(),
        ),
    ])
}

#[test]
fn empty_secret_is_rejected() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");

    assert!(matches!(
        Vault::open(backend, b""),
        Err(VaultError::InvalidSecret)
    ));
}

fn value_blob(root: &Path) -> std::path::PathBuf {
    let entries = fs::read_dir(root.join("values"))
        .expect("value directory exists")
        .collect::<Result<Vec<_>, _>>()
        .expect("value directory is readable");
    assert_eq!(entries.len(), 1, "test stores exactly one value map");
    entries[0].path()
}

#[test]
fn value_map_round_trip_preserves_structure() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let vault = Vault::open(backend, b"correct horse battery staple").expect("vault opens");
    let record = identity("tenant-a", "record-a");

    vault
        .store_value_map(&record, &values())
        .expect("value map seals");

    assert_eq!(
        vault.load_value_map(&record).expect("value map opens"),
        values()
    );
}

#[test]
fn independent_vaults_merge_without_losing_concurrent_keys() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let barrier = Arc::new(Barrier::new(8));
    let handles = (0..8)
        .map(|index| {
            let path = directory.path().to_path_buf();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let vault =
                    Vault::open(LocalBackend::open(path).unwrap(), b"test-merge-secret").unwrap();
                barrier.wait();
                vault
                    .merge_value_map(
                        &identity("tenant", "thread"),
                        &BTreeMap::from([(format!("key-{index}"), format!("value-{index}"))]),
                    )
                    .unwrap();
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.join().unwrap();
    }
    let vault = Vault::open(
        LocalBackend::open(directory.path()).unwrap(),
        b"test-merge-secret",
    )
    .unwrap();
    let record = identity("tenant", "thread");
    assert_eq!(vault.load_value_map(&record).unwrap().len(), 8);
    vault
        .merge_value_map(
            &record,
            &BTreeMap::from([("key-0".to_owned(), "updated".to_owned())]),
        )
        .unwrap();
    let stored = vault.load_value_map(&record).unwrap();
    assert_eq!(stored.len(), 8);
    assert_eq!(stored["key-0"], "updated");
    let wrong = Vault::open(
        LocalBackend::open(directory.path()).unwrap(),
        b"wrong-secret",
    )
    .unwrap();
    assert!(matches!(
        wrong.merge_value_map(&record, &BTreeMap::new()),
        Err(VaultError::AuthenticationFailed)
    ));
    assert_eq!(vault.load_value_map(&record).unwrap(), stored);
}

#[test]
fn wrong_secret_returns_authentication_error() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let record = identity("tenant-a", "record-a");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    Vault::open(backend, b"correct horse battery staple")
        .expect("vault opens")
        .store_value_map(&record, &values())
        .expect("value map seals");

    let backend = LocalBackend::open(directory.path()).expect("backend reopens");
    let wrong_vault = Vault::open(backend, b"incorrect secret").expect("vault opens");

    assert!(matches!(
        wrong_vault.load_value_map(&record),
        Err(VaultError::AuthenticationFailed)
    ));
}

#[test]
fn modified_ciphertext_returns_authentication_error() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let record = identity("tenant-a", "record-a");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let vault = Vault::open(backend, b"correct horse battery staple").expect("vault opens");
    vault
        .store_value_map(&record, &values())
        .expect("value map seals");

    let path = value_blob(directory.path());
    let mut blob = fs::read(&path).expect("sealed blob is readable");
    let last = blob.last_mut().expect("sealed blob is not empty");
    *last ^= 0x01;
    fs::write(path, blob).expect("tampered blob is written");

    assert!(matches!(
        vault.load_value_map(&record),
        Err(VaultError::AuthenticationFailed)
    ));
}

#[test]
fn local_backend_file_never_contains_value_map_plaintext() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let record = identity("tenant-a", "record-a");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let vault = Vault::open(backend, b"correct horse battery staple").expect("vault opens");
    vault
        .store_value_map(&record, &values())
        .expect("value map seals");

    let blob = fs::read(value_blob(directory.path())).expect("sealed blob is readable");

    assert!(
        !blob
            .windows(b"Ada Lovelace".len())
            .any(|window| window == b"Ada Lovelace")
    );
}

#[test]
fn ciphertext_moved_to_another_identity_fails_authentication() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let source = identity("tenant-a", "record-a");
    let destination = identity("tenant-b", "record-b");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let vault = Vault::open(backend, b"correct horse battery staple").expect("vault opens");
    vault
        .store_value_map(&source, &values())
        .expect("source value map seals");
    let source_path = value_blob(directory.path());
    let source_blob = fs::read(&source_path).expect("source blob is readable");

    vault
        .store_value_map(&destination, &values())
        .expect("destination value map seals");
    let destination_path = fs::read_dir(directory.path().join("values"))
        .expect("value directory exists")
        .map(|entry| entry.expect("entry is readable").path())
        .find(|path| path != &source_path)
        .expect("destination blob exists");
    fs::write(destination_path, source_blob).expect("ciphertext is moved");

    assert!(matches!(
        vault.load_value_map(&destination),
        Err(VaultError::AuthenticationFailed)
    ));
}

#[test]
fn reopening_backend_never_reuses_an_operation_nonce() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let record = identity("tenant-a", "record-a");
    let secret = b"correct horse battery staple";

    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    Vault::open(backend, secret)
        .expect("vault opens")
        .store_value_map(&record, &values())
        .expect("first value map seals");
    let path = value_blob(directory.path());
    let first_blob = fs::read(&path).expect("first blob is readable");

    let backend = LocalBackend::open(directory.path()).expect("backend reopens");
    Vault::open(backend, secret)
        .expect("vault reopens")
        .store_value_map(&record, &values())
        .expect("second value map seals");
    let second_blob = fs::read(path).expect("second blob is readable");

    assert_eq!(&first_blob[..8], b"PDVMAP02");
    assert_eq!(&second_blob[..8], b"PDVMAP02");
    assert_eq!(
        &first_blob[20..31],
        &second_blob[20..31],
        "a backend keeps one stable nonce namespace"
    );
    let first_counter = u64::from_be_bytes(
        first_blob[31..39]
            .try_into()
            .expect("first nonce counter is present"),
    );
    let second_counter = u64::from_be_bytes(
        second_blob[31..39]
            .try_into()
            .expect("second nonce counter is present"),
    );
    assert_eq!(
        second_counter,
        first_counter + 1,
        "the persisted nonce sequence must advance across backend instances"
    );
}

#[test]
fn concurrent_backends_reserve_distinct_nonce_prefixes() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    LocalBackend::open(directory.path()).expect("backend state is initialized");
    let root = directory.path().to_path_buf();
    let handles = (0..16)
        .map(|_| {
            let root = root.clone();
            thread::spawn(move || {
                LocalBackend::open(root)
                    .expect("backend opens")
                    .reserve_nonce_prefix()
                    .expect("nonce is reserved")
            })
        })
        .collect::<Vec<_>>();
    let prefixes = handles
        .into_iter()
        .map(|handle| handle.join().expect("nonce thread completes"))
        .collect::<Vec<_>>();
    let unique = prefixes.iter().copied().collect::<HashSet<_>>();

    assert_eq!(unique.len(), prefixes.len());
    assert!(
        prefixes
            .iter()
            .all(|prefix| prefix[..11] == prefixes[0][..11])
    );
    let mut counters = prefixes
        .iter()
        .map(|prefix| {
            u64::from_be_bytes(prefix[11..].try_into().expect("nonce counter is present"))
        })
        .collect::<Vec<_>>();
    counters.sort_unstable();
    assert_eq!(counters, (0..16).collect::<Vec<_>>());
}
