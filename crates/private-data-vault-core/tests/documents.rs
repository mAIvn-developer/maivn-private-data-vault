use std::{fs, io::Cursor, path::Path};

use private_data_vault_core::{ContentKind, LocalBackend, RecordIdentity, Vault, VaultError};

fn identity(tenant: &str, record: &str) -> RecordIdentity {
    RecordIdentity::new(tenant, record).expect("test identity is valid")
}

fn document_blob(root: &Path) -> std::path::PathBuf {
    let entries = fs::read_dir(root.join("documents"))
        .expect("document directory exists")
        .collect::<Result<Vec<_>, _>>()
        .expect("document directory is readable");
    assert_eq!(entries.len(), 1, "test stores exactly one document");
    entries[0].path()
}

fn original_blob(root: &Path) -> std::path::PathBuf {
    let entries = fs::read_dir(root.join("originals"))
        .expect("original directory exists")
        .collect::<Result<Vec<_>, _>>()
        .expect("original directory is readable");
    assert_eq!(entries.len(), 1, "test stores exactly one original");
    entries[0].path()
}

fn count_frames(blob: &[u8]) -> usize {
    let mut offset = match blob.get(..8) {
        Some(b"PDVDOC01") => 27,
        Some(b"PDVDOC02") => 39,
        _ => panic!("test fixture has a recognized document envelope"),
    };
    let mut count = 0;
    while offset < blob.len() {
        let length = usize::try_from(u32::from_be_bytes(
            blob[offset + 1..offset + 5]
                .try_into()
                .expect("frame length is present"),
        ))
        .expect("u32 frame length fits in usize");
        offset += 5 + length;
        count += 1;
    }
    assert_eq!(offset, blob.len(), "test fixture contains complete frames");
    count
}

#[test]
fn multi_megabyte_document_round_trip_uses_multiple_authenticated_frames() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let vault = Vault::open(backend, b"correct horse battery staple").expect("vault opens");
    let record = identity("tenant-a", "large-document");
    let document = (0..(2 * 1024 * 1024 + 137))
        .map(|index| u8::try_from(index % 251).expect("value fits in u8"))
        .collect::<Vec<_>>();

    vault
        .store_document(&record, &mut Cursor::new(&document))
        .expect("document seals");
    let mut opened = Vec::new();
    vault
        .load_document(&record, &mut opened)
        .expect("document opens");

    assert_eq!(opened, document);
    let blob = fs::read(document_blob(directory.path())).expect("sealed document is readable");
    assert!(
        count_frames(&blob) > 2,
        "a multi-megabyte document must not be one in-memory AEAD message"
    );
}

#[test]
fn original_and_redacted_document_are_distinct_authenticated_kinds() {
    assert_eq!(ContentKind::ValueMap as u8, 1);
    assert_eq!(ContentKind::Document as u8, 2);
    assert_eq!(ContentKind::Original as u8, 3);

    let directory = tempfile::tempdir().expect("temporary directory is created");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let vault = Vault::open(backend, b"correct horse battery staple").expect("vault opens");
    let record = identity("tenant-a", "original-and-redacted");
    let original = b"Ada Lovelace lives at 12 St James's Square";
    let redacted = b"<PRIVATE_1> lives at <PRIVATE_2>";

    vault
        .store_original(&record, &mut Cursor::new(original))
        .expect("original seals");
    vault
        .store_document(&record, &mut Cursor::new(redacted))
        .expect("redacted document seals");

    let mut opened_original = Vec::new();
    vault
        .load_original(&record, &mut opened_original)
        .expect("original opens");
    let mut opened_document = Vec::new();
    vault
        .load_document(&record, &mut opened_document)
        .expect("redacted document opens");

    assert_eq!(opened_original, original);
    assert_eq!(opened_document, redacted);

    let sealed_original = fs::read(original_blob(directory.path())).expect("original is readable");
    fs::write(document_blob(directory.path()), sealed_original)
        .expect("kind-substitution fixture is written");
    assert!(matches!(
        vault.load_document(&record, &mut Vec::new()),
        Err(VaultError::AuthenticationFailed)
    ));
}

#[test]
fn empty_document_round_trip_is_authenticated() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let vault = Vault::open(backend, b"correct horse battery staple").expect("vault opens");
    let record = identity("tenant-a", "empty-document");

    vault
        .store_document(&record, &mut Cursor::new(Vec::<u8>::new()))
        .expect("empty document seals");
    let mut opened = Vec::new();

    vault
        .load_document(&record, &mut opened)
        .expect("empty document opens");
    assert!(opened.is_empty());
}

#[test]
fn wrong_secret_rejects_document_before_writing_plaintext() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let record = identity("tenant-a", "record-a");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    Vault::open(backend, b"correct horse battery staple")
        .expect("vault opens")
        .store_document(&record, &mut Cursor::new(b"private document"))
        .expect("document seals");

    let backend = LocalBackend::open(directory.path()).expect("backend reopens");
    let wrong_vault = Vault::open(backend, b"incorrect secret").expect("vault opens");
    let mut output = Vec::new();

    assert!(matches!(
        wrong_vault.load_document(&record, &mut output),
        Err(VaultError::AuthenticationFailed)
    ));
    assert!(output.is_empty());
}

#[test]
fn modified_document_ciphertext_returns_authentication_error() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let record = identity("tenant-a", "record-a");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let vault = Vault::open(backend, b"correct horse battery staple").expect("vault opens");
    vault
        .store_document(&record, &mut Cursor::new(b"private document"))
        .expect("document seals");

    let path = document_blob(directory.path());
    let mut blob = fs::read(&path).expect("sealed document is readable");
    let last = blob.last_mut().expect("sealed document is not empty");
    *last ^= 0x01;
    fs::write(path, blob).expect("tampered document is written");

    assert!(matches!(
        vault.load_document(&record, &mut Vec::new()),
        Err(VaultError::AuthenticationFailed)
    ));
}

#[test]
fn truncated_document_is_rejected() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let record = identity("tenant-a", "record-a");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let vault = Vault::open(backend, b"correct horse battery staple").expect("vault opens");
    vault
        .store_document(&record, &mut Cursor::new(b"private document"))
        .expect("document seals");

    let path = document_blob(directory.path());
    let mut blob = fs::read(&path).expect("sealed document is readable");
    blob.truncate(blob.len() - 1);
    fs::write(path, blob).expect("truncated document is written");

    assert!(matches!(
        vault.load_document(&record, &mut Vec::new()),
        Err(VaultError::InvalidFormat)
    ));
}

#[test]
fn document_moved_to_another_identity_fails_authentication() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let source = identity("tenant-a", "record-a");
    let destination = identity("tenant-b", "record-b");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let vault = Vault::open(backend, b"correct horse battery staple").expect("vault opens");
    vault
        .store_document(&source, &mut Cursor::new(b"source private document"))
        .expect("source document seals");
    let source_path = document_blob(directory.path());
    let source_blob = fs::read(&source_path).expect("source blob is readable");

    vault
        .store_document(
            &destination,
            &mut Cursor::new(b"destination private document"),
        )
        .expect("destination document seals");
    let destination_path = fs::read_dir(directory.path().join("documents"))
        .expect("document directory exists")
        .map(|entry| entry.expect("entry is readable").path())
        .find(|path| path != &source_path)
        .expect("destination blob exists");
    fs::write(destination_path, source_blob).expect("ciphertext is moved");
    let mut output = Vec::new();

    assert!(matches!(
        vault.load_document(&destination, &mut output),
        Err(VaultError::AuthenticationFailed)
    ));
    assert!(output.is_empty());
}

#[test]
fn local_backend_file_never_contains_document_plaintext() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let backend = LocalBackend::open(directory.path()).expect("backend opens");
    let vault = Vault::open(backend, b"correct horse battery staple").expect("vault opens");
    let record = identity("tenant-a", "record-a");
    let marker = b"PRIVATE-MARKER-THAT-MUST-NOT-REACH-THE-BACKEND";
    let document = marker.repeat(4096);

    vault
        .store_document(&record, &mut Cursor::new(document))
        .expect("document seals");

    let blob = fs::read(document_blob(directory.path())).expect("sealed document is readable");
    assert!(!blob.windows(marker.len()).any(|window| window == marker));
}
