//! Golden vectors for every persisted or exchanged byte format.
//!
//! Fixed secrets, salts, nonce prefixes and inputs must keep producing these
//! exact bytes. Each vector is checked twice: against an independent
//! re-implementation of the documented format (the `oracle` module), and
//! against a recorded digest, so neither a refactor of the vault nor a change
//! in a cryptographic dependency can alter the format unnoticed.
//!
//! A failure here is a format change. Never update a vector to make it pass.

use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Read},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
};

use private_data_vault_core::{
    ContentKind, GenerationRead, GenerationTransaction, KeyVersion, Keyring, LocalBackend,
    MemoryBackend, PendingDocument, PurgeKeys, RecordIdentity, StorageBackend, StorageError, Vault,
    VaultError,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const SALT: [u8; 16] = *b"golden-salt-0001";
const SECRET: &[u8] = b"golden-vector-secret";
const ROTATED_SECRET: &[u8] = b"golden-vector-secret-two";
const INSTANCE: [u8; 11] = *b"golden-inst";
const TENANT: &str = "tenant-a";
const RECORD: &str = "record-1";

fn values() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("[EMAIL_1]".to_owned(), "ada@example.invalid".to_owned()),
        ("[NAME_1]".to_owned(), "Ada".to_owned()),
    ])
}

/// Two full 64 KiB chunks and a partial one: three data frames.
fn large_original() -> Vec<u8> {
    (0..150_000_u32).map(|index| (index % 251) as u8).collect()
}

const DOCUMENT: &[u8] = b"Contact [NAME_1] at [EMAIL_1].";

fn identity() -> RecordIdentity {
    RecordIdentity::new(TENANT, RECORD).expect("valid identity")
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The memory backend with a predictable nonce sequence in place of `OsRng`.
struct Deterministic {
    inner: MemoryBackend,
    counter: AtomicU64,
}

impl Deterministic {
    fn new() -> Self {
        Self {
            inner: MemoryBackend::new(SALT),
            counter: AtomicU64::new(0),
        }
    }
}

impl StorageBackend for Deterministic {
    fn key_derivation_salt(&self) -> Result<[u8; 16], StorageError> {
        self.inner.key_derivation_salt()
    }

    fn reserve_nonce_prefix(&self) -> Result<[u8; 19], StorageError> {
        Ok(oracle::prefix(self.counter.fetch_add(1, Ordering::SeqCst)))
    }

    fn begin_generation_read(
        &self,
        key: &[u8; 32],
    ) -> Result<Box<dyn GenerationRead>, StorageError> {
        self.inner.begin_generation_read(key)
    }

    fn begin_generation_transaction(
        &self,
        key: &[u8; 32],
    ) -> Result<Box<dyn GenerationTransaction>, StorageError> {
        self.inner.begin_generation_transaction(key)
    }

    fn list_record_keys(
        &self,
        after: Option<&[u8; 32]>,
        limit: usize,
    ) -> Result<Vec<[u8; 32]>, StorageError> {
        self.inner.list_record_keys(after, limit)
    }

    fn store_value_map(&self, key: &[u8; 32], sealed: &[u8]) -> Result<(), StorageError> {
        self.inner.store_value_map(key, sealed)
    }

    fn load_value_map(&self, key: &[u8; 32]) -> Result<Vec<u8>, StorageError> {
        self.inner.load_value_map(key)
    }

    fn store_versioned_value_map(
        &self,
        key: &[u8; 32],
        generation: u64,
        sealed: &[u8],
    ) -> Result<(), StorageError> {
        self.inner
            .store_versioned_value_map(key, generation, sealed)
    }

    fn load_versioned_value_map(
        &self,
        key: &[u8; 32],
        generation: u64,
    ) -> Result<Vec<u8>, StorageError> {
        self.inner.load_versioned_value_map(key, generation)
    }

    fn begin_content(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 19],
        kind: ContentKind,
    ) -> Result<Box<dyn PendingDocument>, StorageError> {
        self.inner.begin_content(key, nonce, kind)
    }

    fn open_content(
        &self,
        key: &[u8; 32],
        kind: ContentKind,
    ) -> Result<Box<dyn Read + Send>, StorageError> {
        self.inner.open_content(key, kind)
    }

    fn begin_versioned_content(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 19],
        kind: ContentKind,
        generation: u64,
    ) -> Result<Box<dyn PendingDocument>, StorageError> {
        self.inner
            .begin_versioned_content(key, nonce, kind, generation)
    }

    fn open_versioned_content(
        &self,
        key: &[u8; 32],
        kind: ContentKind,
        generation: u64,
    ) -> Result<Box<dyn Read + Send>, StorageError> {
        self.inner.open_versioned_content(key, kind, generation)
    }

    fn purge(&self, keys: &PurgeKeys) -> Result<(), StorageError> {
        self.inner.purge(keys)
    }

    fn purge_expired(&self, cutoff: SystemTime) -> Result<usize, StorageError> {
        self.inner.purge_expired(cutoff)
    }
}

/// An independent implementation of the documented sealed formats.
mod oracle {
    use argon2::{Algorithm, Argon2, Params, Version};
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit, Payload},
    };
    use private_data_vault_core::ContentKind;
    use sha2::{Digest, Sha256};

    pub const CHUNK: usize = 64 * 1024;

    pub fn prefix(counter: u64) -> [u8; 19] {
        let mut prefix = [0; 19];
        prefix[..11].copy_from_slice(&super::INSTANCE);
        prefix[11..].copy_from_slice(&counter.to_be_bytes());
        prefix
    }

    /// Argon2id v0x13, 19 MiB, two passes, one lane, 32-byte output.
    pub fn key(secret: &[u8], salt: &[u8; 16]) -> [u8; 32] {
        let params = Params::new(19 * 1024, 2, 1, Some(32)).expect("parameters");
        let mut key = [0; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(secret, salt, &mut key)
            .expect("derivation");
        key
    }

    fn length_prefixed(output: &mut Vec<u8>, field: &str) {
        output.extend_from_slice(&(field.len() as u64).to_be_bytes());
        output.extend_from_slice(field.as_bytes());
    }

    /// Version-1 associated data; its SHA-256 is the legacy storage address.
    pub fn legacy_aad(tenant: &str, record: &str, kind: ContentKind) -> Vec<u8> {
        let mut aad = b"maivn-private-data-vault:aad:v1".to_vec();
        aad.push(kind as u8);
        length_prefixed(&mut aad, tenant);
        length_prefixed(&mut aad, record);
        aad
    }

    pub fn legacy_storage_key(tenant: &str, record: &str, kind: ContentKind) -> [u8; 32] {
        Sha256::digest(legacy_aad(tenant, record, kind)).into()
    }

    pub fn record_key(tenant: &str, record: &str) -> [u8; 32] {
        let mut encoded = b"maivn-private-data-vault:record-key:v1".to_vec();
        length_prefixed(&mut encoded, tenant);
        length_prefixed(&mut encoded, record);
        Sha256::digest(encoded).into()
    }

    pub fn storage_key(record_key: &[u8; 32], kind: ContentKind) -> [u8; 32] {
        let mut encoded = b"maivn-private-data-vault:storage-key:v2".to_vec();
        encoded.extend_from_slice(record_key);
        encoded.push(kind as u8);
        Sha256::digest(encoded).into()
    }

    pub fn versioned_aad(
        record_key: &[u8; 32],
        kind: ContentKind,
        version: u32,
        generation: u64,
    ) -> Vec<u8> {
        let mut aad = b"maivn-private-data-vault:aad:v2".to_vec();
        aad.extend_from_slice(record_key);
        aad.push(kind as u8);
        aad.extend_from_slice(&version.to_be_bytes());
        aad.extend_from_slice(&generation.to_be_bytes());
        aad
    }

    fn seal(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        XChaCha20Poly1305::new(key.into())
            .encrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("encryption")
    }

    fn value_map_nonce(prefix: &[u8; 19]) -> [u8; 24] {
        let mut nonce = [0; 24];
        nonce[..19].copy_from_slice(prefix);
        nonce[23] = 2;
        nonce
    }

    /// `PDVMAP02 | version u32 | generation u64 | prefix | ciphertext+tag`.
    pub fn value_map(
        key: &[u8; 32],
        aad: &[u8],
        version: u32,
        generation: u64,
        prefix: &[u8; 19],
        json: &[u8],
    ) -> Vec<u8> {
        let mut sealed = b"PDVMAP02".to_vec();
        sealed.extend_from_slice(&version.to_be_bytes());
        sealed.extend_from_slice(&generation.to_be_bytes());
        sealed.extend_from_slice(prefix);
        sealed.extend(seal(key, &value_map_nonce(prefix), aad, json));
        sealed
    }

    /// `PDVMAP01 | prefix | ciphertext+tag`, authenticated with version-1 data.
    pub fn legacy_value_map(key: &[u8; 32], aad: &[u8], prefix: &[u8; 19], json: &[u8]) -> Vec<u8> {
        let mut sealed = b"PDVMAP01".to_vec();
        sealed.extend_from_slice(prefix);
        sealed.extend(seal(key, &value_map_nonce(prefix), aad, json));
        sealed
    }

    /// Frames: `kind u8 | length u32 | ciphertext+tag`; each frame's nonce is
    /// `prefix | index u32 | kind` and its associated data `base | index | kind`.
    fn frames(key: &[u8; 32], base_aad: &[u8], prefix: &[u8; 19], plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut index = 0_u32;
        let mut frame = |kind: u8, chunk: &[u8], index: u32| {
            let mut nonce = [0; 24];
            nonce[..19].copy_from_slice(prefix);
            nonce[19..23].copy_from_slice(&index.to_be_bytes());
            nonce[23] = kind;
            let mut aad = base_aad.to_vec();
            aad.extend_from_slice(&index.to_be_bytes());
            aad.push(kind);
            let ciphertext = seal(key, &nonce, &aad, chunk);
            out.push(kind);
            out.extend_from_slice(
                &u32::try_from(ciphertext.len())
                    .expect("frame fits")
                    .to_be_bytes(),
            );
            out.extend(ciphertext);
        };
        for chunk in plaintext.chunks(CHUNK) {
            frame(0, chunk, index);
            index += 1;
        }
        frame(1, &[], index);
        out
    }

    /// `PDVDOC02 | version u32 | generation u64 | prefix | frames`.
    pub fn stream(
        key: &[u8; 32],
        base_aad: &[u8],
        version: u32,
        generation: u64,
        prefix: &[u8; 19],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let mut sealed = b"PDVDOC02".to_vec();
        sealed.extend_from_slice(&version.to_be_bytes());
        sealed.extend_from_slice(&generation.to_be_bytes());
        sealed.extend_from_slice(prefix);
        sealed.extend(frames(key, base_aad, prefix, plaintext));
        sealed
    }

    /// One version-1 record generation as the vault seals it: value map,
    /// original, then document, from consecutive nonce counters.
    pub fn bundle(
        key: &[u8; 32],
        record_key: &[u8; 32],
        generation: u64,
        counter: u64,
        [json, original, document]: [&[u8]; 3],
    ) -> [Vec<u8>; 3] {
        let aad = |kind| versioned_aad(record_key, kind, 1, generation);
        [
            value_map(
                key,
                &aad(ContentKind::ValueMap),
                1,
                generation,
                &prefix(counter),
                json,
            ),
            stream(
                key,
                &aad(ContentKind::Original),
                1,
                generation,
                &prefix(counter + 1),
                original,
            ),
            stream(
                key,
                &aad(ContentKind::Document),
                1,
                generation,
                &prefix(counter + 2),
                document,
            ),
        ]
    }

    /// `PDVDOC01 | prefix | frames`, authenticated with version-1 data.
    pub fn legacy_stream(
        key: &[u8; 32],
        base_aad: &[u8],
        prefix: &[u8; 19],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let mut sealed = b"PDVDOC01".to_vec();
        sealed.extend_from_slice(prefix);
        sealed.extend(frames(key, base_aad, prefix, plaintext));
        sealed
    }
}

fn json(values: &BTreeMap<String, String>) -> Vec<u8> {
    serde_json::to_vec(values).expect("JSON")
}

#[test]
fn identity_addresses_are_pinned() {
    let record_key = oracle::record_key(TENANT, RECORD);
    assert_eq!(
        hex::encode(record_key),
        "abf0d76b8a673680c7e86f73b2211d51a75d547a7f8709cee3bdc6828b2473ca"
    );
    assert_eq!(
        [
            ContentKind::ValueMap,
            ContentKind::Document,
            ContentKind::Original
        ]
        .map(|kind| kind as u8),
        [1, 2, 3]
    );
    let addresses = [
        ContentKind::ValueMap,
        ContentKind::Document,
        ContentKind::Original,
    ]
    .map(|kind| {
        format!(
            "{} {}",
            hex::encode(oracle::legacy_storage_key(TENANT, RECORD, kind)),
            hex::encode(oracle::storage_key(&record_key, kind))
        )
    });
    assert_eq!(
        addresses,
        [
            "1e35090e675e18819094b58f02ecf8cb82e3bca1059d8eed959f8b4927b77d32 27e129eed07d48da0c9b41c28ce9fa1f5b1db95d456c9eab9624604cb259f90c",
            "f96cbdd0df9b7d6dbd84e08da5f85d81b31056843b250306380ed366f43de894 d718126a7acff1b40bc648e73dc06b47535586c326128593f51d1a6b6aeb29e2",
            "604bc6414f04a61842906405c823e7a5f4cb8ccddbe1488082347fee70a29d87 b64d3c127b9e141ec7e9199e58d9785e1bb9ae0dc449fd30057e4e9a5c1f428d"
        ]
    );
}

#[test]
fn a_standalone_value_map_seals_to_the_pinned_bytes() {
    let backend = Deterministic::new();
    let vault = Vault::open(backend, SECRET).expect("vault opens");
    vault
        .store_value_map(&identity(), &values())
        .expect("stores");

    let sealed = vault
        .backend()
        .inner
        .extract_object(
            &oracle::legacy_storage_key(TENANT, RECORD, ContentKind::ValueMap),
            ContentKind::ValueMap,
            None,
        )
        .expect("stored at the legacy address");

    let key = oracle::key(SECRET, &SALT);
    let aad = oracle::versioned_aad(
        &oracle::record_key(TENANT, RECORD),
        ContentKind::ValueMap,
        1,
        1,
    );
    assert_eq!(
        sealed,
        oracle::value_map(&key, &aad, 1, 1, &oracle::prefix(0), &json(&values()))
    );
    assert_eq!(
        hex::encode(&sealed),
        "5044564d41503032000000010000000000000001676f6c64656e2d696e73740000000000000000d61f99aebfbe263c20705e9a04d02a3aa0d32f374720840a8b585145eb77ca6986455da6546f48289050e51e419b6afa8d10535f30aa6e8d5ba312a79f407ab9ae702f1d"
    );
}

#[test]
fn a_record_bundle_seals_to_the_pinned_bytes_and_replacement_advances_it() {
    let backend = Deterministic::new();
    let vault = Vault::open(backend, SECRET).expect("vault opens");
    let original = large_original();
    vault
        .store_record(
            &identity(),
            &mut Cursor::new(&original),
            &mut Cursor::new(DOCUMENT),
            &values(),
        )
        .expect("stores");
    let first = vault
        .backend()
        .inner
        .export_record(&identity())
        .expect("complete record");

    let key = oracle::key(SECRET, &SALT);
    let record_key = oracle::record_key(TENANT, RECORD);
    assert_eq!(first.generation, 1);
    assert_eq!(
        [&first.value_map, &first.original, &first.document],
        oracle::bundle(
            &key,
            &record_key,
            1,
            0,
            [&json(&values()), &original, DOCUMENT]
        )
        .each_ref()
    );
    assert_eq!(
        [
            digest(&first.value_map),
            digest(&first.original),
            digest(&first.document)
        ],
        [
            "5d3221acd26e315fdc662c5cea36befb0f2a2e3e7547efcaa1622b86321f1b45",
            "40073b36b42b4c21393d17ead4e74a9bdde05e5a79fbbae680d76c4f864ab2dd",
            "35d232e6b5299d69be0d939137b6ae7ab50fcc0cc19ea9d07c46013555ccb05e"
        ]
    );

    vault
        .replace_record(
            &identity(),
            &mut Cursor::new(b"v2 original"),
            &mut Cursor::new(b"v2 document"),
            &BTreeMap::new(),
        )
        .expect("replaces");
    let second = vault
        .backend()
        .inner
        .export_record(&identity())
        .expect("complete record");
    assert_eq!(second.generation, 2);
    assert_eq!(
        [&second.value_map, &second.original, &second.document],
        oracle::bundle(
            &key,
            &record_key,
            2,
            3,
            [b"{}", b"v2 original", b"v2 document"]
        )
        .each_ref()
    );
}

#[test]
fn rotation_rewrites_to_the_pinned_bytes_and_issues_the_pinned_cursor() {
    let old = Vault::open(Deterministic::new(), SECRET).expect("vault opens");
    for record in ["record-1", "record-2"] {
        let identity = RecordIdentity::new(TENANT, record).expect("identity");
        old.store_record(
            &identity,
            &mut Cursor::new(b"original"),
            &mut Cursor::new(b"document"),
            &values(),
        )
        .expect("stores");
    }
    let records: Vec<_> = ["record-1", "record-2"]
        .map(|record| {
            old.backend()
                .inner
                .export_record(&RecordIdentity::new(TENANT, record).expect("identity"))
                .expect("record")
        })
        .into();

    let backend = Deterministic::new();
    backend.counter.store(100, Ordering::SeqCst);
    for (record, exported) in ["record-1", "record-2"].into_iter().zip(&records) {
        backend
            .inner
            .import_record(
                &RecordIdentity::new(TENANT, record).expect("identity"),
                exported,
            )
            .expect("imports");
    }
    let version_two = KeyVersion::new(2).expect("version");
    let keyring = Keyring::new(version_two, ROTATED_SECRET)
        .and_then(|keyring| keyring.with_decrypt_only(KeyVersion::new(1).expect("version"), SECRET))
        .expect("keyring");
    let vault = Vault::open_keyring(backend, keyring).expect("vault opens");

    let outcome = vault
        .reencrypt_batch(version_two, None, 1)
        .expect("first batch");
    let cursor = outcome.next_cursor.expect("one record remains");
    assert_eq!((outcome.visited, outcome.rewritten), (1, 1));
    assert_eq!(
        cursor.to_token(),
        "pdv-reencrypt-v2:676f6c64656e2d73616c742d30303031000000021c826be88fec8cac9b40c761b588c659c518e3cb05abd916b08d4620ac74b63c5b0f4f6804391909964885a43f523b8627270139ef7bb216bd1e468d9113b697"
    );
    assert_eq!(
        vault
            .reencrypt_cursor_from_token(version_two, &cursor.to_token())
            .expect("authentic"),
        cursor
    );

    // The first record in key order was rewritten as generation 2 under key 2.
    let key_two = oracle::key(ROTATED_SECRET, &SALT);
    let rewritten = ["record-1", "record-2"]
        .into_iter()
        .map(|record| {
            (
                record,
                vault
                    .backend()
                    .inner
                    .export_record(&RecordIdentity::new(TENANT, record).expect("identity"))
                    .expect("record"),
            )
        })
        .find(|(_, record)| record.generation == 2)
        .expect("one record rewritten");
    let record_key = oracle::record_key(TENANT, rewritten.0);
    let aad = |kind| oracle::versioned_aad(&record_key, kind, 2, 2);
    assert_eq!(
        rewritten.1.original,
        oracle::stream(
            &key_two,
            &aad(ContentKind::Original),
            2,
            2,
            &oracle::prefix(100),
            b"original"
        )
    );
    assert_eq!(
        rewritten.1.document,
        oracle::stream(
            &key_two,
            &aad(ContentKind::Document),
            2,
            2,
            &oracle::prefix(101),
            b"document"
        )
    );
    assert_eq!(
        rewritten.1.value_map,
        oracle::value_map(
            &key_two,
            &aad(ContentKind::ValueMap),
            2,
            2,
            &oracle::prefix(102),
            &json(&values())
        )
    );
}

#[test]
fn legacy_version_one_objects_still_open() {
    let key = oracle::key(SECRET, &SALT);
    let backend = Deterministic::new();
    let value_map = oracle::legacy_value_map(
        &key,
        &oracle::legacy_aad(TENANT, RECORD, ContentKind::ValueMap),
        &oracle::prefix(7),
        &json(&values()),
    );
    let original = large_original();
    for (kind, sealed) in [
        (ContentKind::ValueMap, value_map),
        (
            ContentKind::Document,
            oracle::legacy_stream(
                &key,
                &oracle::legacy_aad(TENANT, RECORD, ContentKind::Document),
                &oracle::prefix(8),
                DOCUMENT,
            ),
        ),
        (
            ContentKind::Original,
            oracle::legacy_stream(
                &key,
                &oracle::legacy_aad(TENANT, RECORD, ContentKind::Original),
                &oracle::prefix(9),
                &original,
            ),
        ),
    ] {
        backend.inner.hydrate_object(
            oracle::legacy_storage_key(TENANT, RECORD, kind),
            kind,
            None,
            sealed,
        );
    }
    let vault = Vault::open(backend, SECRET).expect("vault opens");

    assert_eq!(
        vault.load_value_map(&identity()).expect("value map"),
        values()
    );
    let mut document = Vec::new();
    vault
        .load_document(&identity(), &mut document)
        .expect("document");
    assert_eq!(document, DOCUMENT);
    let mut opened = Vec::new();
    vault
        .load_original(&identity(), &mut opened)
        .expect("original");
    assert_eq!(opened, original);
}

/// One `vault.state` slot: magic, generation, salt, instance id, counter, SHA-256.
fn state_slot(generation: u64, counter: u64) -> Vec<u8> {
    let mut slot = b"PDVST002".to_vec();
    slot.extend_from_slice(&generation.to_be_bytes());
    slot.extend_from_slice(&SALT);
    slot.extend_from_slice(&INSTANCE);
    slot.extend_from_slice(&counter.to_be_bytes());
    let checksum = Sha256::digest(&slot);
    slot.extend_from_slice(&checksum);
    slot
}

fn files(root: &Path) -> Vec<String> {
    let mut names = Vec::new();
    for directory in ["values", "documents", "originals", "generations"] {
        for entry in fs::read_dir(root.join(directory)).expect("directory") {
            names.push(format!(
                "{directory}/{}",
                entry.expect("entry").file_name().to_string_lossy()
            ));
        }
    }
    names.sort();
    names
}

#[test]
fn the_local_backend_layout_and_state_format_are_pinned() {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path();
    // Generation 6 in the first slot (even), generation 5 in the second: the
    // higher generation wins and its counter (40) is the next nonce.
    let mut state = state_slot(6, 40);
    state.extend(state_slot(5, 39));
    fs::create_dir_all(root).expect("root");
    fs::write(root.join("vault.state"), &state).expect("state");

    let backend = LocalBackend::open(root).expect("backend opens");
    assert_eq!(backend.key_derivation_salt().expect("salt"), SALT);
    let vault = Vault::open(backend, SECRET).expect("vault opens");
    vault
        .store_record(
            &identity(),
            &mut Cursor::new(b"original"),
            &mut Cursor::new(DOCUMENT),
            &values(),
        )
        .expect("stores");
    let standalone = RecordIdentity::new(TENANT, "standalone").expect("identity");
    vault
        .store_value_map(&standalone, &values())
        .expect("stores");
    vault
        .store_document(&standalone, &mut Cursor::new(DOCUMENT))
        .expect("stores");

    // Three reservations for the bundle, two for the standalone record:
    // counters 40..=44 issued; each write lands in the slot the live record is
    // not in (even generations in slot 0, odd in slot 1).
    let mut expected_state = state_slot(10, 44);
    expected_state.extend(state_slot(11, 45));
    assert_eq!(
        fs::read(root.join("vault.state")).expect("state"),
        expected_state
    );

    let record_key = oracle::record_key(TENANT, RECORD);
    let key = oracle::key(SECRET, &SALT);
    let hex_key = |kind| hex::encode(oracle::storage_key(&record_key, kind));
    let legacy = |kind| hex::encode(oracle::legacy_storage_key(TENANT, "standalone", kind));
    let mut expected_files = vec![
        format!(
            "documents/{}.00000000000000000001.pvd",
            hex_key(ContentKind::Document)
        ),
        format!("documents/{}.pvd", legacy(ContentKind::Document)),
        format!("generations/{}.pvg", hex::encode(record_key)),
        format!(
            "originals/{}.00000000000000000001.pvo",
            hex_key(ContentKind::Original)
        ),
        format!(
            "values/{}.00000000000000000001.pvm",
            hex_key(ContentKind::ValueMap)
        ),
        format!("values/{}.pvm", legacy(ContentKind::ValueMap)),
    ];
    expected_files.sort();
    assert_eq!(files(root), expected_files);

    // Generation file: PDVGEN01 | generation u64 | SHA-256(record key | first 16 bytes).
    let mut generation = b"PDVGEN01".to_vec();
    generation.extend_from_slice(&1_u64.to_be_bytes());
    let mut checked = record_key.to_vec();
    checked.extend_from_slice(&generation);
    generation.extend_from_slice(&Sha256::digest(&checked));
    assert_eq!(
        fs::read(
            root.join("generations")
                .join(format!("{}.pvg", hex::encode(record_key)))
        )
        .expect("generation"),
        generation
    );

    let aad = |kind| oracle::versioned_aad(&record_key, kind, 1, 1);
    let document_path = root.join("documents").join(format!(
        "{}.00000000000000000001.pvd",
        hex_key(ContentKind::Document)
    ));
    let document = fs::read(document_path).expect("document");
    assert_eq!(
        document,
        oracle::stream(
            &key,
            &aad(ContentKind::Document),
            1,
            1,
            &oracle::prefix(42),
            DOCUMENT
        )
    );
    assert_eq!(
        digest(&document),
        "d27abd37676c5d4e278f7fae3e112da5f9265a734c8ec9c512fd23c51afc9fe0"
    );
}

#[test]
fn storage_error_messages_crossing_into_python_are_pinned() {
    let storage = [
        StorageError::Io(std::io::Error::other("disk")),
        StorageError::InvalidMetadata,
        StorageError::InvalidSealedObject,
        StorageError::NonceExhausted,
        StorageError::GenerationConflict,
        StorageError::NotFound,
    ]
    .map(|error| error.to_string());
    assert_eq!(
        storage,
        [
            "storage I/O failed: disk",
            "storage metadata is invalid",
            "sealed object supplied to storage is invalid",
            "operation nonce sequence is exhausted",
            "trusted generation changed before commit",
            "sealed object was not found",
        ]
    );
}

#[test]
fn vault_error_messages_crossing_into_python_are_pinned() {
    let serialization = serde_json::from_slice::<u8>(b"x").expect_err("invalid JSON");
    let vault = [
        VaultError::AuthenticationFailed,
        VaultError::InvalidIdentity,
        VaultError::InvalidSecret,
        VaultError::InvalidKeyVersion,
        VaultError::DuplicateKeyVersion(3),
        VaultError::UnknownKeyVersion(4),
        VaultError::GenerationConflict,
        VaultError::AtomicWriteRequired,
        VaultError::GenerationExhausted,
        VaultError::InvalidBatchLimit,
        VaultError::InvalidReencryptCursor,
        VaultError::InactiveReencryptionTarget {
            requested: 1,
            active: 2,
        },
        VaultError::InconsistentRecordKeyVersions,
        VaultError::RollbackDetected {
            trusted: 5,
            envelope: 4,
        },
        VaultError::InvalidFormat,
        VaultError::Serialization(serialization),
        VaultError::DocumentIo(std::io::Error::other("pipe")),
        VaultError::DocumentTooLarge,
        VaultError::KeyDerivation,
        VaultError::Storage(StorageError::NotFound),
    ]
    .map(|error| error.to_string());
    assert_eq!(
        vault,
        [
            "ciphertext authentication failed",
            "tenant and record identifiers must not be empty",
            "vault secret must not be empty",
            "vault key version must be non-zero",
            "vault key version 3 is present more than once",
            "vault key version 4 is unavailable",
            "trusted generation changed before the record bundle committed",
            "records with a trusted generation must be replaced with store_record",
            "record generation sequence is exhausted",
            "re-encryption batch limit must be greater than zero",
            "re-encryption cursor is invalid",
            "re-encryption target key version 1 is not the active key version 2",
            "record generation contains inconsistent key versions",
            "ciphertext generation 4 does not match trusted generation 5",
            "sealed object format is invalid",
            "value map serialization failed: expected value at line 1 column 1",
            "document stream I/O failed: pipe",
            "document exceeds the supported authenticated chunk count",
            "key derivation failed",
            "sealed object was not found",
        ]
    );
}

/// A record whose objects are validly sealed version-1 objects under the
/// right key, claiming trusted generation 0.
fn version_one_record_at_generation_zero() -> private_data_vault_core::ExchangeRecord {
    let key = oracle::key(SECRET, &SALT);
    let stream = |kind, plaintext: &[u8], counter| {
        oracle::legacy_stream(
            &key,
            &oracle::legacy_aad(TENANT, RECORD, kind),
            &oracle::prefix(counter),
            plaintext,
        )
    };
    private_data_vault_core::ExchangeRecord {
        generation: 0,
        original: stream(ContentKind::Original, b"original", 1),
        document: stream(ContentKind::Document, DOCUMENT, 2),
        value_map: oracle::legacy_value_map(
            &key,
            &oracle::legacy_aad(TENANT, RECORD, ContentKind::ValueMap),
            &oracle::prefix(3),
            &json(&values()),
        ),
    }
}

#[test]
fn an_import_at_generation_zero_never_opens() {
    let backend = MemoryBackend::new(SALT);
    assert!(matches!(
        backend.import_record(&identity(), &version_one_record_at_generation_zero()),
        Err(VaultError::InvalidFormat)
    ));
    assert!(matches!(
        backend.hydrate_generation(oracle::record_key(TENANT, RECORD), 0),
        Err(VaultError::InvalidFormat)
    ));
    let record_key = oracle::record_key(TENANT, RECORD);
    for kind in [
        ContentKind::Original,
        ContentKind::Document,
        ContentKind::ValueMap,
    ] {
        assert!(
            backend
                .extract_object(&oracle::storage_key(&record_key, kind), kind, Some(0))
                .is_none(),
            "a refused import stores no {kind:?}"
        );
    }
    assert_eq!(backend.extract_generation(&record_key), None);
    let vault = Vault::open(backend, SECRET).expect("vault opens");

    assert!(vault.load_value_map(&identity()).is_err());
    assert!(vault.load_document(&identity(), &mut Vec::new()).is_err());
}
