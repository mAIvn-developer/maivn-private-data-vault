use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Read},
    path::Path,
    time::SystemTime,
};

use private_data_vault_core::{
    ContentKind, GenerationRead, GenerationTransaction, KeyVersion, Keyring, LocalBackend,
    PendingDocument, PurgeKeys, RecordIdentity, StorageBackend, StorageError, Vault, VaultError,
};
use sha2::{Digest, Sha256};

const LEGACY_SALT: [u8; 16] = *b"fixed-v1-salt-01";
const LEGACY_VALUE_MAP_HEX: &str = concat!(
    "5044564d4150303166697865642d76312d7072656669782d303031",
    "58c84a322d9c59d6e9cad33729bf968943ddf861044baa00d2d453",
    "934172a7b48993f4b4f211a4ca7d72ad2c9bde",
);
const LEGACY_DOCUMENT_HEX: &str = concat!(
    "504456444f43303166697865642d76312d7072656669782d303031",
    "0000000027bc4997650a8d7e04f3c35beeebfde4699fc207ed1a93",
    "fe44d5a44b62f2c8b9387a80465e2432350100000010b560c062",
    "9ba6ab0ad6980556b2df8cc1",
);

struct LegacyValueBackend {
    sealed: Vec<u8>,
    document: Vec<u8>,
}

struct LegacyGeneration;

impl GenerationRead for LegacyGeneration {
    fn generation(&self) -> Option<u64> {
        None
    }
}

impl GenerationTransaction for LegacyGeneration {
    fn compare_and_swap(&mut self, _expected: Option<u64>, _next: u64) -> Result<(), StorageError> {
        unreachable!("legacy fixture is read-only")
    }
}

impl StorageBackend for LegacyValueBackend {
    fn key_derivation_salt(&self) -> Result<[u8; 16], StorageError> {
        Ok(LEGACY_SALT)
    }

    fn reserve_nonce_prefix(&self) -> Result<[u8; 19], StorageError> {
        unreachable!("legacy fixture is read-only")
    }

    fn begin_generation_read(
        &self,
        _record_key: &[u8; 32],
    ) -> Result<Box<dyn GenerationRead>, StorageError> {
        Ok(Box::new(LegacyGeneration))
    }

    fn begin_generation_transaction(
        &self,
        _record_key: &[u8; 32],
    ) -> Result<Box<dyn GenerationTransaction>, StorageError> {
        unreachable!("legacy fixture is read-only")
    }

    fn list_record_keys(
        &self,
        _after: Option<&[u8; 32]>,
        _limit: usize,
    ) -> Result<Vec<[u8; 32]>, StorageError> {
        Ok(Vec::new())
    }

    fn store_value_map(&self, _storage_key: &[u8; 32], _sealed: &[u8]) -> Result<(), StorageError> {
        unreachable!("legacy fixture is read-only")
    }

    fn load_value_map(&self, _storage_key: &[u8; 32]) -> Result<Vec<u8>, StorageError> {
        Ok(self.sealed.clone())
    }

    fn store_versioned_value_map(
        &self,
        _storage_key: &[u8; 32],
        _generation: u64,
        _sealed: &[u8],
    ) -> Result<(), StorageError> {
        unreachable!("legacy fixture is read-only")
    }

    fn load_versioned_value_map(
        &self,
        _storage_key: &[u8; 32],
        _generation: u64,
    ) -> Result<Vec<u8>, StorageError> {
        unreachable!("legacy fixture has no trusted generation")
    }

    fn begin_content(
        &self,
        _storage_key: &[u8; 32],
        _operation_nonce: &[u8; 19],
        _kind: ContentKind,
    ) -> Result<Box<dyn PendingDocument>, StorageError> {
        unreachable!("legacy fixture contains only a value map")
    }

    fn open_content(
        &self,
        _storage_key: &[u8; 32],
        kind: ContentKind,
    ) -> Result<Box<dyn Read + Send>, StorageError> {
        assert_eq!(kind, ContentKind::Document);
        Ok(Box::new(Cursor::new(self.document.clone())))
    }

    fn begin_versioned_content(
        &self,
        _storage_key: &[u8; 32],
        _operation_nonce: &[u8; 19],
        _kind: ContentKind,
        _generation: u64,
    ) -> Result<Box<dyn PendingDocument>, StorageError> {
        unreachable!("legacy fixture is read-only")
    }

    fn open_versioned_content(
        &self,
        _storage_key: &[u8; 32],
        _kind: ContentKind,
        _generation: u64,
    ) -> Result<Box<dyn Read + Send>, StorageError> {
        unreachable!("legacy fixture has no trusted generation")
    }

    fn purge(&self, _keys: &PurgeKeys) -> Result<(), StorageError> {
        unreachable!("legacy fixture is read-only")
    }

    fn purge_expired(&self, _cutoff: SystemTime) -> Result<usize, StorageError> {
        unreachable!("legacy fixture is read-only")
    }
}

fn identity(record: &str) -> RecordIdentity {
    RecordIdentity::new("tenant-a", record).expect("test identity is valid")
}

fn values(value: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("<PRIVATE_1>".to_owned(), value.to_owned())])
}

fn versioned_storage_key(record_key: &[u8; 32], kind: ContentKind) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(65);
    encoded.extend_from_slice(b"maivn-private-data-vault:storage-key:v2");
    encoded.extend_from_slice(record_key);
    encoded.push(kind as u8);
    Sha256::digest(encoded).into()
}

fn assert_migration_record(vault: &Vault<LocalBackend>, index: usize) {
    let record = identity(&format!("migration-record-{index}"));
    assert_eq!(
        vault.load_value_map(&record).expect("migrated values open"),
        values(&format!("private-{index}"))
    );
    let mut original = Vec::new();
    vault
        .load_original(&record, &mut original)
        .expect("migrated original opens");
    assert_eq!(original, format!("original-{index}").as_bytes());
    let mut document = Vec::new();
    vault
        .load_document(&record, &mut document)
        .expect("migrated document opens");
    assert_eq!(document, format!("redacted-{index}").as_bytes());
}

fn only_value_blob(root: &Path) -> std::path::PathBuf {
    let entries = fs::read_dir(root.join("values"))
        .expect("value directory exists")
        .collect::<Result<Vec<_>, _>>()
        .expect("value directory is readable");
    assert_eq!(entries.len(), 1, "test stores exactly one value map");
    entries[0].path()
}

fn only_streamed_blob(root: &Path, directory: &str) -> std::path::PathBuf {
    let entries = fs::read_dir(root.join(directory))
        .expect("streamed-content directory exists")
        .collect::<Result<Vec<_>, _>>()
        .expect("streamed-content directory is readable");
    assert_eq!(entries.len(), 1, "test stores exactly one streamed object");
    entries[0].path()
}

#[test]
fn zero_is_not_a_valid_key_version() {
    assert!(matches!(
        KeyVersion::new(0),
        Err(VaultError::InvalidKeyVersion)
    ));
}

#[test]
fn literal_version_one_value_map_remains_readable() {
    let backend = LegacyValueBackend {
        sealed: hex::decode(LEGACY_VALUE_MAP_HEX).expect("literal vector is valid hex"),
        document: hex::decode(LEGACY_DOCUMENT_HEX).expect("literal vector is valid hex"),
    };
    let vault = Vault::open(backend, b"legacy tenant secret").expect("legacy vault opens");

    assert_eq!(
        vault
            .load_value_map(&identity("legacy-record"))
            .expect("legacy value map opens"),
        values("Ada Lovelace")
    );
}

#[test]
fn literal_version_one_document_remains_readable() {
    let backend = LegacyValueBackend {
        sealed: hex::decode(LEGACY_VALUE_MAP_HEX).expect("literal vector is valid hex"),
        document: hex::decode(LEGACY_DOCUMENT_HEX).expect("literal vector is valid hex"),
    };
    let vault = Vault::open(backend, b"legacy tenant secret").expect("legacy vault opens");
    let mut opened = Vec::new();

    vault
        .load_document(&identity("legacy-document"), &mut opened)
        .expect("legacy document opens");

    assert_eq!(opened, b"legacy private document");
}

#[test]
fn old_ciphertext_opens_after_a_new_key_becomes_active() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let record = identity("rotated-record");
    let version_one = KeyVersion::new(1).expect("version is valid");
    let version_two = KeyVersion::new(2).expect("version is valid");

    Vault::open_keyring(
        LocalBackend::open(directory.path()).expect("backend opens"),
        Keyring::new(version_one, b"first tenant secret").expect("keyring is valid"),
    )
    .expect("vault opens")
    .store_value_map(&record, &values("Ada Lovelace"))
    .expect("version-one value map seals");

    let rotated = Keyring::new(version_two, b"second tenant secret")
        .expect("keyring is valid")
        .with_decrypt_only(version_one, b"first tenant secret")
        .expect("decrypt-only key is added");
    let vault = Vault::open_keyring(
        LocalBackend::open(directory.path()).expect("backend reopens"),
        rotated,
    )
    .expect("rotated vault opens");

    assert_eq!(
        vault.load_value_map(&record).expect("old value map opens"),
        values("Ada Lovelace")
    );
}

#[test]
fn new_writes_use_the_active_version_and_authenticate_the_header() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let record = identity("active-version");
    let version_one = KeyVersion::new(1).expect("version is valid");
    let version_two = KeyVersion::new(2).expect("version is valid");
    let keyring = Keyring::new(version_two, b"same derived material")
        .expect("keyring is valid")
        .with_decrypt_only(version_one, b"same derived material")
        .expect("decrypt-only key is added");
    let vault = Vault::open_keyring(
        LocalBackend::open(directory.path()).expect("backend opens"),
        keyring,
    )
    .expect("vault opens");

    vault
        .store_value_map(&record, &values("Grace Hopper"))
        .expect("value map seals");

    let path = only_value_blob(directory.path());
    let mut sealed = fs::read(&path).expect("sealed value map is readable");
    assert_eq!(&sealed[..8], b"PDVMAP02");
    assert_eq!(&sealed[8..12], &2_u32.to_be_bytes());
    assert_eq!(&sealed[12..20], &1_u64.to_be_bytes());

    sealed[8..12].copy_from_slice(&1_u32.to_be_bytes());
    fs::write(path, sealed).expect("tampered version header is written");

    assert!(matches!(
        vault.load_value_map(&record),
        Err(VaultError::AuthenticationFailed)
    ));
}

#[test]
fn an_unavailable_historical_key_is_typed() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let record = identity("missing-key");
    let version_one = KeyVersion::new(1).expect("version is valid");
    let version_two = KeyVersion::new(2).expect("version is valid");

    Vault::open_keyring(
        LocalBackend::open(directory.path()).expect("backend opens"),
        Keyring::new(version_one, b"first tenant secret").expect("keyring is valid"),
    )
    .expect("vault opens")
    .store_value_map(&record, &values("Katherine Johnson"))
    .expect("version-one value map seals");

    let vault = Vault::open_keyring(
        LocalBackend::open(directory.path()).expect("backend reopens"),
        Keyring::new(version_two, b"second tenant secret").expect("keyring is valid"),
    )
    .expect("version-two vault opens");

    assert!(matches!(
        vault.load_value_map(&record),
        Err(VaultError::UnknownKeyVersion(1))
    ));
}

#[test]
fn document_and_original_headers_are_authenticated() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let record = identity("streamed-header-binding");
    let version_one = KeyVersion::new(1).expect("version is valid");
    let version_two = KeyVersion::new(2).expect("version is valid");
    let keyring = Keyring::new(version_two, b"same derived material")
        .expect("keyring is valid")
        .with_decrypt_only(version_one, b"same derived material")
        .expect("decrypt-only key is added");
    let vault = Vault::open_keyring(
        LocalBackend::open(directory.path()).expect("backend opens"),
        keyring,
    )
    .expect("vault opens");
    vault
        .store_document(&record, &mut Cursor::new(b"redacted document"))
        .expect("document seals");
    vault
        .store_original(&record, &mut Cursor::new(b"unredacted original"))
        .expect("original seals");

    for (storage_directory, load_original) in [("documents", false), ("originals", true)] {
        let path = only_streamed_blob(directory.path(), storage_directory);
        let mut sealed = fs::read(&path).expect("streamed ciphertext is readable");
        assert_eq!(&sealed[..8], b"PDVDOC02");
        assert_eq!(&sealed[8..12], &2_u32.to_be_bytes());
        assert_eq!(&sealed[12..20], &1_u64.to_be_bytes());
        sealed[8..12].copy_from_slice(&1_u32.to_be_bytes());
        fs::write(path, sealed).expect("tampered streamed header is written");

        let result = if load_original {
            vault.load_original(&record, &mut Vec::new())
        } else {
            vault.load_document(&record, &mut Vec::new())
        };
        assert!(matches!(result, Err(VaultError::AuthenticationFailed)));
    }
}

#[test]
fn re_encryption_resumes_in_bounded_batches_and_is_idempotent() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let version_one = KeyVersion::new(1).expect("version is valid");
    let version_two = KeyVersion::new(2).expect("version is valid");
    let first_vault = Vault::open_keyring(
        LocalBackend::open(directory.path()).expect("backend opens"),
        Keyring::new(version_one, b"first tenant secret").expect("keyring is valid"),
    )
    .expect("version-one vault opens");
    for index in 0..5 {
        let record = identity(&format!("migration-record-{index}"));
        first_vault
            .store_record(
                &record,
                &mut Cursor::new(format!("original-{index}")),
                &mut Cursor::new(format!("redacted-{index}")),
                &values(&format!("private-{index}")),
            )
            .expect("version-one record commits");
    }
    drop(first_vault);

    let rotated_keyring = || {
        Keyring::new(version_two, b"second tenant secret")
            .expect("keyring is valid")
            .with_decrypt_only(version_one, b"first tenant secret")
            .expect("decrypt-only key is added")
    };
    let vault = Vault::open_keyring(
        LocalBackend::open(directory.path()).expect("backend reopens"),
        rotated_keyring(),
    )
    .expect("rotated vault opens");
    let first = vault
        .reencrypt_batch(version_two, None, 2)
        .expect("first migration batch completes");
    assert_eq!((first.visited, first.rewritten), (2, 2));
    assert!(first.next_cursor.is_some());
    let restart_token = first
        .next_cursor
        .as_ref()
        .expect("more records remain")
        .to_token();
    drop(vault);

    let vault = Vault::open_keyring(
        LocalBackend::open(directory.path()).expect("backend reopens after interruption"),
        rotated_keyring(),
    )
    .expect("rotated vault reopens");
    let restart_cursor = vault
        .reencrypt_cursor_from_token(version_two, &restart_token)
        .expect("cursor token is valid for the reopened vault");
    let second = vault
        .reencrypt_batch(version_two, Some(&restart_cursor), 2)
        .expect("second migration batch completes");
    assert_eq!((second.visited, second.rewritten), (2, 2));
    assert!(second.next_cursor.is_some());
    let third = vault
        .reencrypt_batch(version_two, second.next_cursor.as_ref(), 2)
        .expect("final migration batch completes");
    assert_eq!((third.visited, third.rewritten), (1, 1));
    assert!(third.next_cursor.is_none());

    for index in 0..5 {
        assert_migration_record(&vault, index);
    }

    let repeated = vault
        .reencrypt_batch(version_two, None, 10)
        .expect("completed migration can be rerun");
    assert_eq!((repeated.visited, repeated.rewritten), (5, 0));
    assert!(repeated.next_cursor.is_none());
    drop(vault);

    let active_only = Vault::open_keyring(
        LocalBackend::open(directory.path()).expect("backend reopens"),
        Keyring::new(version_two, b"second tenant secret").expect("keyring is valid"),
    )
    .expect("vault opens after the historical key is removed");
    for index in 0..5 {
        assert_migration_record(&active_only, index);
    }
}

#[test]
fn corrupt_record_stops_re_encryption_before_later_records() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let version_one = KeyVersion::new(1).expect("version is valid");
    let version_two = KeyVersion::new(2).expect("version is valid");
    let first_vault = Vault::open_keyring(
        LocalBackend::open(directory.path()).expect("backend opens"),
        Keyring::new(version_one, b"first tenant secret").expect("keyring is valid"),
    )
    .expect("version-one vault opens");
    for index in 0..3 {
        first_vault
            .store_record(
                &identity(&format!("corruption-record-{index}")),
                &mut Cursor::new(format!("original-{index}")),
                &mut Cursor::new(format!("redacted-{index}")),
                &values(&format!("private-{index}")),
            )
            .expect("version-one record commits");
    }
    drop(first_vault);

    let inspection_backend = LocalBackend::open(directory.path()).expect("backend reopens");
    let record_keys = inspection_backend
        .list_record_keys(None, 10)
        .expect("record keys enumerate");
    assert_eq!(record_keys.len(), 3);
    let corrupt_path = directory.path().join("values").join(format!(
        "{}.00000000000000000001.pvm",
        hex::encode(versioned_storage_key(
            &record_keys[1],
            ContentKind::ValueMap
        ))
    ));
    let valid_ciphertext = fs::read(&corrupt_path).expect("sealed value map is readable");
    let mut corrupt_ciphertext = valid_ciphertext.clone();
    *corrupt_ciphertext
        .last_mut()
        .expect("sealed value map is non-empty") ^= 1;
    fs::write(&corrupt_path, corrupt_ciphertext).expect("test corrupts the middle record");

    let rotated = Keyring::new(version_two, b"second tenant secret")
        .expect("keyring is valid")
        .with_decrypt_only(version_one, b"first tenant secret")
        .expect("decrypt-only key is added");
    let vault = Vault::open_keyring(
        LocalBackend::open(directory.path()).expect("backend reopens"),
        rotated,
    )
    .expect("rotated vault opens");
    assert!(matches!(
        vault.reencrypt_batch(version_two, None, 10),
        Err(VaultError::AuthenticationFailed)
    ));
    assert_eq!(
        inspection_backend
            .read_generation(&record_keys[0])
            .expect("first generation is readable"),
        Some(2),
        "the record before the corruption may commit"
    );
    assert_eq!(
        inspection_backend
            .read_generation(&record_keys[2])
            .expect("later generation is readable"),
        Some(1),
        "no record after the corruption is visited"
    );

    fs::write(corrupt_path, valid_ciphertext).expect("test repairs sealed value map");
    let resumed = vault
        .reencrypt_batch(version_two, None, 10)
        .expect("same input cursor safely retries after repair");
    assert_eq!((resumed.visited, resumed.rewritten), (3, 2));
    assert!(resumed.next_cursor.is_none());
}

#[test]
fn late_stream_corruption_aborts_the_pending_generation() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let version_one = KeyVersion::new(1).expect("version is valid");
    let version_two = KeyVersion::new(2).expect("version is valid");
    let first_vault = Vault::open_keyring(
        LocalBackend::open(directory.path()).expect("backend opens"),
        Keyring::new(version_one, b"first tenant secret").expect("keyring is valid"),
    )
    .expect("version-one vault opens");
    first_vault
        .store_record(
            &identity("late-stream-corruption"),
            &mut Cursor::new(vec![b'o'; 2 * 64 * 1024 + 17]),
            &mut Cursor::new(b"redacted"),
            &values("private"),
        )
        .expect("multi-frame record commits");
    drop(first_vault);

    let inspection_backend = LocalBackend::open(directory.path()).expect("backend reopens");
    let record_key = inspection_backend
        .list_record_keys(None, 2)
        .expect("record key enumerates")[0];
    let original_storage_key = versioned_storage_key(&record_key, ContentKind::Original);
    let original_path = directory.path().join("originals").join(format!(
        "{}.00000000000000000001.pvo",
        hex::encode(original_storage_key)
    ));
    let pending_generation_path = directory.path().join("originals").join(format!(
        "{}.00000000000000000002.pvo",
        hex::encode(original_storage_key)
    ));
    let valid_ciphertext = fs::read(&original_path).expect("sealed original is readable");
    let mut corrupt_ciphertext = valid_ciphertext.clone();
    *corrupt_ciphertext
        .last_mut()
        .expect("sealed original is non-empty") ^= 1;
    fs::write(&original_path, corrupt_ciphertext).expect("final frame is corrupted");

    let vault = Vault::open_keyring(
        LocalBackend::open(directory.path()).expect("backend reopens"),
        Keyring::new(version_two, b"second tenant secret")
            .expect("keyring is valid")
            .with_decrypt_only(version_one, b"first tenant secret")
            .expect("decrypt-only key is added"),
    )
    .expect("rotated vault opens");
    assert!(matches!(
        vault.reencrypt_batch(version_two, None, 1),
        Err(VaultError::AuthenticationFailed)
    ));
    assert_eq!(
        inspection_backend
            .read_generation(&record_key)
            .expect("trusted generation is readable"),
        Some(1)
    );
    assert!(
        !pending_generation_path.exists(),
        "failed late authentication drops the pending generation object"
    );

    fs::write(original_path, valid_ciphertext).expect("test repairs sealed original");
    let resumed = vault
        .reencrypt_batch(version_two, None, 1)
        .expect("repair permits retry from the same cursor");
    assert_eq!((resumed.visited, resumed.rewritten), (1, 1));
}

#[test]
fn re_encryption_controls_fail_closed() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let version_one = KeyVersion::new(1).expect("version is valid");
    let version_two = KeyVersion::new(2).expect("version is valid");
    let vault = Vault::open_keyring(
        LocalBackend::open(directory.path()).expect("backend opens"),
        Keyring::new(version_two, b"second tenant secret")
            .expect("keyring is valid")
            .with_decrypt_only(version_one, b"first tenant secret")
            .expect("decrypt-only key is added"),
    )
    .expect("vault opens");

    assert!(matches!(
        vault.reencrypt_batch(version_two, None, 0),
        Err(VaultError::InvalidBatchLimit)
    ));
    assert!(matches!(
        vault.reencrypt_batch(version_one, None, 1),
        Err(VaultError::InactiveReencryptionTarget {
            requested: 1,
            active: 2
        })
    ));
    for invalid in [
        "",
        "pdv-reencrypt-v1:00",
        "pdv-reencrypt-v2:00",
        &format!("pdv-reencrypt-v2:{}", "A".repeat(168)),
    ] {
        assert!(matches!(
            vault.reencrypt_cursor_from_token(version_two, invalid),
            Err(VaultError::InvalidReencryptCursor)
        ));
    }
}

#[test]
fn cursor_tokens_are_integrity_protected_and_rotation_scoped() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let version_two = KeyVersion::new(2).expect("version is valid");
    let version_three = KeyVersion::new(3).expect("version is valid");
    let vault = Vault::open_keyring(
        LocalBackend::open(directory.path()).expect("backend opens"),
        Keyring::new(version_two, b"second tenant secret").expect("keyring is valid"),
    )
    .expect("vault opens");
    for index in 0..2 {
        vault
            .store_record(
                &identity(&format!("cursor-record-{index}")),
                &mut Cursor::new(format!("original-{index}")),
                &mut Cursor::new(format!("redacted-{index}")),
                &values(&format!("private-{index}")),
            )
            .expect("record commits");
    }
    let outcome = vault
        .reencrypt_batch(version_two, None, 1)
        .expect("first cursor batch completes");
    let token = outcome.next_cursor.expect("one record remains").to_token();
    assert!(
        vault
            .reencrypt_cursor_from_token(version_two, &token)
            .is_ok(),
        "the issuing vault accepts its authenticated cursor"
    );

    let mut tampered = token.clone().into_bytes();
    let last = tampered.last_mut().expect("token is non-empty");
    *last = if *last == b'0' { b'1' } else { b'0' };
    let tampered = String::from_utf8(tampered).expect("token remains ASCII");
    assert!(matches!(
        vault.reencrypt_cursor_from_token(version_two, &tampered),
        Err(VaultError::InvalidReencryptCursor)
    ));
    let arbitrary = format!("pdv-reencrypt-v2:{}", "f".repeat(168));
    assert!(matches!(
        vault.reencrypt_cursor_from_token(version_two, &arbitrary),
        Err(VaultError::InvalidReencryptCursor)
    ));

    let other_directory = tempfile::tempdir().expect("other directory is created");
    let other_vault = Vault::open_keyring(
        LocalBackend::open(other_directory.path()).expect("other backend opens"),
        Keyring::new(version_two, b"second tenant secret").expect("keyring is valid"),
    )
    .expect("other vault opens");
    assert!(matches!(
        other_vault.reencrypt_cursor_from_token(version_two, &token),
        Err(VaultError::InvalidReencryptCursor)
    ));

    let next_rotation = Vault::open_keyring(
        LocalBackend::open(directory.path()).expect("backend reopens"),
        Keyring::new(version_three, b"third tenant secret")
            .expect("keyring is valid")
            .with_decrypt_only(version_two, b"second tenant secret")
            .expect("decrypt-only key is added"),
    )
    .expect("next rotation vault opens");
    assert!(matches!(
        next_rotation.reencrypt_cursor_from_token(version_three, &token),
        Err(VaultError::InvalidReencryptCursor)
    ));
}

#[test]
fn generation_enumeration_ignores_only_atomic_temporary_files() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let version = KeyVersion::new(1).expect("version is valid");
    let vault = Vault::open_keyring(
        LocalBackend::open(directory.path()).expect("backend opens"),
        Keyring::new(version, b"tenant secret").expect("keyring is valid"),
    )
    .expect("vault opens");
    vault
        .store_record(
            &identity("enumerated-record"),
            &mut Cursor::new(b"original"),
            &mut Cursor::new(b"redacted"),
            &values("private"),
        )
        .expect("record commits");

    let generations = directory.path().join("generations");
    fs::write(
        generations.join(format!("{}.{}.tmp", "a".repeat(64), "b".repeat(32))),
        b"simulated interrupted atomic write",
    )
    .expect("temporary generation file is written");
    let backend = LocalBackend::open(directory.path()).expect("backend reopens");
    assert_eq!(
        backend
            .list_record_keys(None, 10)
            .expect("canonical temporary file is ignored")
            .len(),
        1
    );

    fs::write(generations.join("unexpected.tmp"), b"malformed").expect("malformed file is written");
    assert!(matches!(
        backend.list_record_keys(None, 10),
        Err(StorageError::InvalidMetadata)
    ));
}
