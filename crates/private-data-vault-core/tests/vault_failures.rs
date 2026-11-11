//! How the vault behaves when storage misbehaves or sealed bytes are damaged:
//! every failure is typed, nothing partial is published, and no damaged object
//! is ever opened.

use std::{
    collections::BTreeMap,
    io::{self, Cursor, Read, Write},
    sync::Mutex,
    time::SystemTime,
};

use private_data_vault_core::{
    ContentKind, GenerationRead, GenerationTransaction, KeyVersion, Keyring, MemoryBackend,
    PendingDocument, PurgeKeys, RecordIdentity, StorageBackend, StorageError, Vault, VaultError,
};

fn identity() -> RecordIdentity {
    RecordIdentity::new("tenant", "record").expect("identity")
}

fn values() -> BTreeMap<String, String> {
    BTreeMap::from([("[NAME_1]".to_owned(), "Ada".to_owned())])
}

fn version(value: u32) -> KeyVersion {
    KeyVersion::new(value).expect("version")
}

/// Which storage call fails, and how.
#[derive(Clone, Copy, PartialEq)]
enum Fault {
    None,
    StageContent(ContentKind),
    StageValueMap,
    OpenContent,
    Conflict,
    CasFails,
    LoadValueMap,
    /// Storage stops answering before the final frame.
    BrokenReader,
    /// Storage errors once every byte has been read.
    ErrorAtEnd,
    /// Storage is interrupted once every byte has been read, then ends.
    InterruptedAtEnd,
}

/// A memory backend that fails one chosen operation and can lie when listing.
struct Faulty {
    inner: MemoryBackend,
    fault: Mutex<Fault>,
    listing: Mutex<Option<Vec<[u8; 32]>>>,
}

impl Faulty {
    fn new() -> Self {
        Self {
            inner: MemoryBackend::new([4; 16]),
            fault: Mutex::new(Fault::None),
            listing: Mutex::new(None),
        }
    }

    fn fault(&self) -> Fault {
        *self.fault.lock().expect("fault lock")
    }
}

fn injected() -> StorageError {
    StorageError::Io(io::Error::other("injected"))
}

struct FaultyTransaction {
    inner: Box<dyn GenerationTransaction>,
    fault: Fault,
}

impl GenerationRead for FaultyTransaction {
    fn generation(&self) -> Option<u64> {
        self.inner.generation()
    }
}

impl GenerationTransaction for FaultyTransaction {
    fn compare_and_swap(&mut self, expected: Option<u64>, next: u64) -> Result<(), StorageError> {
        match self.fault {
            Fault::Conflict => Err(StorageError::GenerationConflict),
            Fault::CasFails => Err(injected()),
            _ => self.inner.compare_and_swap(expected, next),
        }
    }
}

/// Yields the sealed bytes, then ends the way the fault prescribes.
struct EndingReader {
    bytes: Cursor<Vec<u8>>,
    end: Fault,
}

impl Read for EndingReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.bytes.read(buffer)?;
        if read > 0 {
            return Ok(read);
        }
        match self.end {
            Fault::BrokenReader | Fault::ErrorAtEnd => Err(io::Error::other("connection reset")),
            Fault::InterruptedAtEnd => {
                self.end = Fault::None;
                Err(io::Error::from(io::ErrorKind::Interrupted))
            }
            _ => Ok(0),
        }
    }
}

impl StorageBackend for Faulty {
    fn key_derivation_salt(&self) -> Result<[u8; 16], StorageError> {
        self.inner.key_derivation_salt()
    }

    fn reserve_nonce_prefix(&self) -> Result<[u8; 19], StorageError> {
        self.inner.reserve_nonce_prefix()
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
        Ok(Box::new(FaultyTransaction {
            inner: self.inner.begin_generation_transaction(key)?,
            fault: self.fault(),
        }))
    }

    fn list_record_keys(
        &self,
        after: Option<&[u8; 32]>,
        limit: usize,
    ) -> Result<Vec<[u8; 32]>, StorageError> {
        match self.listing.lock().expect("listing lock").clone() {
            Some(listing) => Ok(listing),
            None => self.inner.list_record_keys(after, limit),
        }
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
        if self.fault() == Fault::StageValueMap {
            return Err(injected());
        }
        self.inner
            .store_versioned_value_map(key, generation, sealed)
    }

    fn load_versioned_value_map(
        &self,
        key: &[u8; 32],
        generation: u64,
    ) -> Result<Vec<u8>, StorageError> {
        if self.fault() == Fault::LoadValueMap {
            return Err(injected());
        }
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
        if self.fault() == Fault::StageContent(kind) {
            return Err(injected());
        }
        self.inner
            .begin_versioned_content(key, nonce, kind, generation)
    }

    fn open_versioned_content(
        &self,
        key: &[u8; 32],
        kind: ContentKind,
        generation: u64,
    ) -> Result<Box<dyn Read + Send>, StorageError> {
        let fault = self.fault();
        if fault == Fault::OpenContent {
            return Err(injected());
        }
        let mut sealed = Vec::new();
        self.inner
            .open_versioned_content(key, kind, generation)?
            .read_to_end(&mut sealed)
            .expect("memory read");
        if fault == Fault::BrokenReader {
            // Drop the final frame so the reader runs dry mid-stream.
            sealed.truncate(sealed.len() - 21);
        }
        Ok(Box::new(EndingReader {
            bytes: Cursor::new(sealed),
            end: fault,
        }))
    }

    fn purge(&self, keys: &PurgeKeys) -> Result<(), StorageError> {
        self.inner.purge(keys)
    }

    fn purge_expired(&self, cutoff: SystemTime) -> Result<usize, StorageError> {
        self.inner.purge_expired(cutoff)
    }
}

fn faulty_vault() -> Vault<Faulty> {
    Vault::open(Faulty::new(), b"secret").expect("vault opens")
}

fn store(vault: &Vault<Faulty>) -> Result<(), VaultError> {
    vault.store_record(
        &identity(),
        &mut Cursor::new(b"original"),
        &mut Cursor::new(b"document"),
        &values(),
    )
}

fn set(vault: &Vault<Faulty>, fault: Fault) {
    *vault.backend().fault.lock().expect("fault lock") = fault;
}

fn generation(vault: &Vault<Faulty>) -> Option<u64> {
    vault.backend().inner.extract_generation(&record_key())
}

/// The opaque record key: SHA-256 of a domain and the length-prefixed identity.
fn record_key() -> [u8; 32] {
    record_key_of("record")
}

fn record_key_of(record: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut encoded = b"maivn-private-data-vault:record-key:v1".to_vec();
    for field in ["tenant", record] {
        encoded.extend_from_slice(&(field.len() as u64).to_be_bytes());
        encoded.extend_from_slice(field.as_bytes());
    }
    Sha256::digest(encoded).into()
}

#[test]
fn a_failed_staging_step_publishes_nothing() {
    for fault in [
        Fault::StageContent(ContentKind::Original),
        Fault::StageContent(ContentKind::Document),
        Fault::StageValueMap,
    ] {
        let vault = faulty_vault();
        set(&vault, fault);
        assert!(matches!(
            store(&vault),
            Err(VaultError::Storage(StorageError::Io(_)))
        ));
        assert_eq!(generation(&vault), None, "no generation was published");
    }
}

#[test]
fn a_lost_publication_race_is_typed_and_keeps_the_prior_generation() {
    let vault = faulty_vault();
    store(&vault).expect("first generation");
    set(&vault, Fault::Conflict);
    assert!(matches!(store(&vault), Err(VaultError::GenerationConflict)));
    set(&vault, Fault::CasFails);
    assert!(matches!(
        store(&vault),
        Err(VaultError::Storage(StorageError::Io(_)))
    ));
    assert_eq!(generation(&vault), Some(1));
    set(&vault, Fault::None);
    assert_eq!(vault.load_value_map(&identity()).expect("opens"), values());
}

fn rotating_vault() -> Vault<Faulty> {
    let old = faulty_vault();
    store(&old).expect("stores under key 1");
    let exported = old
        .backend()
        .inner
        .export_record(&identity())
        .expect("record");
    let backend = Faulty::new();
    backend
        .inner
        .import_record(&identity(), &exported)
        .expect("imports");
    let keyring = Keyring::new(version(2), b"rotated")
        .and_then(|ring| ring.with_decrypt_only(version(1), b"secret"))
        .expect("keyring");
    Vault::open_keyring(backend, keyring).expect("vault opens")
}

#[test]
fn rotation_failures_are_typed_and_leave_the_record_readable() {
    for (fault, expected) in [
        (Fault::Conflict, "conflict"),
        (Fault::CasFails, "storage"),
        (Fault::StageContent(ContentKind::Original), "storage"),
        (Fault::StageContent(ContentKind::Document), "storage"),
        (Fault::StageValueMap, "storage"),
        (Fault::OpenContent, "storage"),
        (Fault::BrokenReader, "storage"),
        (Fault::LoadValueMap, "storage"),
    ] {
        let vault = rotating_vault();
        set(&vault, fault);
        let result = vault.reencrypt_batch(version(2), None, 5);
        match expected {
            "conflict" => assert!(matches!(result, Err(VaultError::GenerationConflict))),
            _ => assert!(
                matches!(result, Err(VaultError::Storage(StorageError::Io(_)))),
                "rotation must surface the storage failure"
            ),
        }
        set(&vault, Fault::None);
        assert_eq!(generation(&vault), Some(1));
        assert_eq!(vault.load_value_map(&identity()).expect("opens"), values());
    }
}

#[test]
fn a_backend_that_lists_out_of_order_is_refused() {
    // Real records, so only the listing itself can be at fault.
    let vault = faulty_vault();
    for record in ["r1", "r2", "r3"] {
        vault
            .store_record(
                &RecordIdentity::new("tenant", record).expect("identity"),
                &mut Cursor::new(b"o"),
                &mut Cursor::new(b"d"),
                &values(),
            )
            .expect("stores");
    }
    let mut keys = ["r1", "r2", "r3"].map(record_key_of);
    keys.sort_unstable();
    let cursor = vault
        .reencrypt_batch(version(1), None, 1)
        .expect("first batch")
        .next_cursor
        .expect("more records");
    for (listing, after) in [
        (vec![keys[1], keys[0]], None),
        (vec![keys[0], keys[0]], None),
        (vec![keys[0], keys[1], keys[2]], None),
        (vec![keys[0], keys[1]], Some(&cursor)),
    ] {
        *vault.backend().listing.lock().expect("listing") = Some(listing);
        assert!(matches!(
            vault.reencrypt_batch(version(1), after, 1),
            Err(VaultError::Storage(StorageError::InvalidMetadata))
        ));
    }
    // A listed key without a trusted generation is not a record.
    *vault.backend().listing.lock().expect("listing") = Some(vec![[0xEE; 32]]);
    assert!(matches!(
        vault.reencrypt_batch(version(1), None, 1),
        Err(VaultError::Storage(StorageError::InvalidMetadata))
    ));
}

#[test]
fn reading_storage_that_fails_mid_stream_is_a_storage_error() {
    let vault = faulty_vault();
    store(&vault).expect("stores");
    set(&vault, Fault::BrokenReader);
    let mut output = Vec::new();
    assert!(matches!(
        vault.load_document(&identity(), &mut output),
        Err(VaultError::Storage(StorageError::Io(_)))
    ));
}

/// A caller-owned source that is interrupted once, then reads normally.
struct InterruptedOnce {
    data: Cursor<Vec<u8>>,
    interrupted: bool,
}

impl Read for InterruptedOnce {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        self.data.read(buffer)
    }
}

struct FailingSource;

impl Read for FailingSource {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("source failed"))
    }
}

struct FailingSink;

impl Write for FailingSink {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("sink failed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn caller_streams_are_retried_on_interruption_and_their_failures_are_typed() {
    let vault = Vault::open(MemoryBackend::new([4; 16]), b"secret").expect("vault opens");
    let mut source = InterruptedOnce {
        data: Cursor::new(b"after an interruption".to_vec()),
        interrupted: false,
    };
    vault
        .store_document(&identity(), &mut source)
        .expect("an interrupted read is retried");
    let mut output = Vec::new();
    vault
        .load_document(&identity(), &mut output)
        .expect("opens");
    assert_eq!(output, b"after an interruption");

    assert!(matches!(
        vault.load_document(&identity(), &mut FailingSink),
        Err(VaultError::DocumentIo(_))
    ));
    let other = RecordIdentity::new("tenant", "other").expect("identity");
    assert!(matches!(
        vault.store_original(&other, &mut FailingSource),
        Err(VaultError::DocumentIo(_))
    ));
    assert!(matches!(
        vault.load_original(&other, &mut Vec::new()),
        Err(VaultError::Storage(StorageError::NotFound))
    ));
}

#[test]
fn the_end_of_a_stream_is_read_to_the_end() {
    let vault = faulty_vault();
    store(&vault).expect("stores");
    set(&vault, Fault::InterruptedAtEnd);
    let mut output = Vec::new();
    vault
        .load_document(&identity(), &mut output)
        .expect("an interruption after the final frame is retried");
    assert_eq!(output, b"document");
    set(&vault, Fault::ErrorAtEnd);
    assert!(matches!(
        vault.load_document(&identity(), &mut Vec::new()),
        Err(VaultError::Storage(StorageError::Io(_)))
    ));
    set(&vault, Fault::OpenContent);
    assert!(matches!(
        vault.load_original(&identity(), &mut Vec::new()),
        Err(VaultError::Storage(StorageError::Io(_)))
    ));
}

/// The record sealed under key 1, then re-imported for a vault holding keys
/// 2 (active) and 1, with `damage` applied to the export first.
fn rotating_vault_with(
    damage: impl FnOnce(&mut private_data_vault_core::ExchangeRecord),
) -> Vault<Faulty> {
    let old = faulty_vault();
    store(&old).expect("stores under key 1");
    let mut exported = old
        .backend()
        .inner
        .export_record(&identity())
        .expect("record");
    damage(&mut exported);
    let backend = Faulty::new();
    backend
        .inner
        .import_record(&identity(), &exported)
        .expect("imports");
    let keyring = Keyring::new(version(2), b"rotated")
        .and_then(|ring| ring.with_decrypt_only(version(1), b"secret"))
        .expect("keyring");
    Vault::open_keyring(backend, keyring).expect("vault opens")
}

#[test]
fn a_record_mixing_key_versions_is_never_rotated() {
    // The same record sealed at generation 1 under key 2.
    let newer = Vault::open_keyring(
        Faulty::new(),
        Keyring::new(version(2), b"rotated").expect("keyring"),
    )
    .expect("vault opens");
    store(&newer).expect("stores under key 2");
    let under_two = newer
        .backend()
        .inner
        .export_record(&identity())
        .expect("record");

    for mix in [0, 1, 2] {
        let vault = rotating_vault_with(|record| match mix {
            0 => record.original.clone_from(&under_two.original),
            1 => record.document.clone_from(&under_two.document),
            _ => record.value_map.clone_from(&under_two.value_map),
        });
        assert!(
            matches!(
                vault.reencrypt_batch(version(2), None, 5),
                Err(VaultError::InconsistentRecordKeyVersions)
            ),
            "mix {mix}"
        );
    }
}

#[test]
fn a_damaged_record_is_never_rotated() {
    // Trailing bytes after the final frame of the source stream.
    let vault = rotating_vault_with(|record| record.document.push(0));
    assert!(matches!(
        vault.reencrypt_batch(version(2), None, 5),
        Err(VaultError::InvalidFormat)
    ));

    // A record already under the target key is still authenticated in full.
    for damaged in [0, 1] {
        let current = Vault::open_keyring(
            Faulty::new(),
            Keyring::new(version(2), b"rotated").expect("keyring"),
        )
        .expect("vault opens");
        store(&current).expect("stores under key 2");
        let mut exported = current
            .backend()
            .inner
            .export_record(&identity())
            .expect("record");
        let stream = if damaged == 0 {
            &mut exported.original
        } else {
            &mut exported.document
        };
        let last = stream.len() - 1;
        stream[last - 21] ^= 1;
        let backend = Faulty::new();
        backend
            .inner
            .import_record(&identity(), &exported)
            .expect("imports");
        let vault = Vault::open_keyring(
            backend,
            Keyring::new(version(2), b"rotated").expect("keyring"),
        )
        .expect("vault opens");
        assert!(
            matches!(
                vault.reencrypt_batch(version(2), None, 5),
                Err(VaultError::AuthenticationFailed)
            ),
            "stream {damaged}"
        );
    }
}

fn three_records(salt: [u8; 16], keyring: Keyring) -> Vault<MemoryBackend> {
    let vault = Vault::open_keyring(MemoryBackend::new(salt), keyring).expect("vault opens");
    for record in ["r1", "r2", "r3"] {
        vault
            .store_record(
                &RecordIdentity::new("tenant", record).expect("identity"),
                &mut Cursor::new(b"o"),
                &mut Cursor::new(b"d"),
                &values(),
            )
            .expect("stores");
    }
    vault
}

#[test]
fn a_cursor_from_another_vault_or_rotation_is_refused() {
    let keyring = || Keyring::new(version(2), b"secret").expect("keyring");
    let issuing = three_records([1; 16], keyring());
    let cursor = issuing
        .reencrypt_batch(version(2), None, 1)
        .expect("batch")
        .next_cursor
        .expect("more records");

    let other_vault = three_records([2; 16], keyring());
    assert!(matches!(
        other_vault.reencrypt_batch(version(2), Some(&cursor), 1),
        Err(VaultError::InvalidReencryptCursor)
    ));

    let later_rotation = three_records(
        [1; 16],
        Keyring::new(version(3), b"newer")
            .and_then(|ring| ring.with_decrypt_only(version(2), b"secret"))
            .expect("keyring"),
    );
    assert!(matches!(
        later_rotation.reencrypt_batch(version(3), Some(&cursor), 1),
        Err(VaultError::InvalidReencryptCursor)
    ));
    assert!(matches!(
        later_rotation.reencrypt_cursor_from_token(version(3), &cursor.to_token()),
        Err(VaultError::InvalidReencryptCursor)
    ));
}

#[test]
fn merging_never_partially_rewrites_a_bundled_record() {
    let vault = Vault::open(MemoryBackend::new([4; 16]), b"secret").expect("vault opens");
    vault
        .store_record(
            &identity(),
            &mut Cursor::new(b"o"),
            &mut Cursor::new(b"d"),
            &values(),
        )
        .expect("stores");
    let extra = BTreeMap::from([("[EMAIL_1]".to_owned(), "a@example.invalid".to_owned())]);
    assert!(matches!(
        vault.merge_value_map(&identity(), &extra),
        Err(VaultError::AtomicWriteRequired)
    ));
    assert_eq!(vault.load_value_map(&identity()).expect("opens"), values());
}

#[test]
fn only_the_canonical_token_restores_a_cursor() {
    let vault = three_records(
        [1; 16],
        Keyring::new(version(2), b"secret").expect("keyring"),
    );
    let cursor = vault
        .reencrypt_batch(version(2), None, 1)
        .expect("batch")
        .next_cursor
        .expect("more records");
    let token = cursor.to_token();
    assert_eq!(
        vault
            .reencrypt_cursor_from_token(version(2), &token)
            .expect("canonical token"),
        cursor
    );

    let (prefix, payload) = token.split_once(':').expect("prefixed token");
    for altered in [
        payload.to_owned(),
        format!("{prefix}:{}", payload.to_uppercase()),
        format!("{prefix}:{payload}00"),
        format!("{prefix}:{}", &payload[..payload.len() - 2]),
        format!("pdv-reencrypt-v1:{payload}"),
    ] {
        assert!(
            matches!(
                vault.reencrypt_cursor_from_token(version(2), &altered),
                Err(VaultError::InvalidReencryptCursor)
            ),
            "{altered}"
        );
    }
}

#[test]
fn a_batch_that_reaches_the_last_record_issues_no_cursor() {
    let vault = three_records(
        [1; 16],
        Keyring::new(version(1), b"secret").expect("keyring"),
    );
    let outcome = vault.reencrypt_batch(version(1), None, 3).expect("batch");
    assert_eq!((outcome.visited, outcome.rewritten), (3, 0));
    assert!(outcome.next_cursor.is_none());
}
