use std::fs;

use private_data_vault::{AdapterError, VaultAdapter};

const SECRET: &[u8] = b"correct horse battery staple";

#[test]
fn value_map_round_trip_accepts_and_returns_utf8_json_bytes() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = VaultAdapter::open(directory.path(), SECRET).expect("vault opens");

    vault
        .store_value_map(
            "tenant-a",
            "record-a",
            r#"{"z":"Grüße","a":"Ada"}"#.as_bytes(),
        )
        .expect("value map stores");

    let loaded = vault
        .load_value_map("tenant-a", "record-a")
        .expect("value map loads");
    assert_eq!(loaded.as_slice(), r#"{"a":"Ada","z":"Grüße"}"#.as_bytes());
}

#[test]
fn document_round_trip_preserves_arbitrary_bytes() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = VaultAdapter::open(directory.path(), SECRET).expect("vault opens");
    let payload = b"\x00\xffraw document\x80";

    vault
        .store_document("tenant-a", "record-a", payload)
        .expect("document stores");

    let loaded = vault
        .load_document("tenant-a", "record-a")
        .expect("document loads");
    assert_eq!(loaded.as_slice(), payload);
}

#[test]
fn missing_and_purged_entries_are_record_not_found() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = VaultAdapter::open(directory.path(), SECRET).expect("vault opens");

    assert!(matches!(
        vault.load_value_map("tenant-a", "record-a"),
        Err(AdapterError::RecordNotFound)
    ));
    assert!(matches!(
        vault.load_document("tenant-a", "record-a"),
        Err(AdapterError::RecordNotFound)
    ));

    vault
        .store_value_map("tenant-a", "record-a", br#"{"a":"Ada"}"#)
        .expect("value map stores");
    vault
        .store_document("tenant-a", "record-a", b"document")
        .expect("document stores");
    vault.purge("tenant-a", "record-a").expect("purge succeeds");

    assert!(matches!(
        vault.load_value_map("tenant-a", "record-a"),
        Err(AdapterError::RecordNotFound)
    ));
    assert!(matches!(
        vault.load_document("tenant-a", "record-a"),
        Err(AdapterError::RecordNotFound)
    ));
    vault
        .purge("tenant-a", "record-a")
        .expect("second purge succeeds");
}

#[test]
fn wrong_secret_is_authentication_failed() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    VaultAdapter::open(directory.path(), SECRET)
        .expect("vault opens")
        .store_value_map("tenant-a", "record-a", br#"{"a":"Ada"}"#)
        .expect("value map stores");
    let wrong_vault =
        VaultAdapter::open(directory.path(), b"incorrect secret").expect("vault opens");

    assert!(matches!(
        wrong_vault.load_value_map("tenant-a", "record-a"),
        Err(AdapterError::AuthenticationFailed)
    ));
}

#[test]
fn invalid_json_is_a_base_vault_error() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = VaultAdapter::open(directory.path(), SECRET).expect("vault opens");

    assert!(matches!(
        vault.store_value_map("tenant-a", "record-a", b"not json"),
        Err(AdapterError::Vault(_))
    ));
}

#[test]
fn inaccessible_storage_is_storage_unavailable() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let file = directory.path().join("not-a-directory");
    fs::write(&file, b"blocking file").expect("blocking file is written");

    assert!(matches!(
        VaultAdapter::open(file.join("vault"), SECRET),
        Err(AdapterError::StorageUnavailable(_))
    ));
}

#[test]
fn original_round_trip_and_wrong_namespace_substitution_are_refused() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = VaultAdapter::open(directory.path(), SECRET).expect("vault opens");
    let source = b"unredacted source";

    vault
        .store_original("tenant-a", "record-a", source)
        .expect("original stores");
    let loaded = vault
        .load_original("tenant-a", "record-a")
        .expect("original loads");
    assert_eq!(loaded.as_slice(), source);

    let source_path = fs::read_dir(directory.path().join("originals"))
        .expect("original directory is readable")
        .next()
        .expect("source original exists")
        .expect("directory entry is readable")
        .path();
    vault
        .store_original("tenant-b", "record-b", b"different original")
        .expect("target original stores");
    let target_path = fs::read_dir(directory.path().join("originals"))
        .expect("original directory is readable")
        .map(|entry| entry.expect("directory entry is readable").path())
        .find(|path| path != &source_path)
        .expect("target original exists");
    fs::copy(source_path, target_path).expect("test substitutes ciphertext across namespaces");

    assert!(matches!(
        vault.load_original("tenant-b", "record-b"),
        Err(AdapterError::AuthenticationFailed)
    ));
}

#[test]
fn atomic_record_replay_is_refused_by_the_binding() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = VaultAdapter::open(directory.path(), SECRET).expect("vault opens");
    vault
        .store_record(
            "tenant-a",
            "record-a",
            b"original one",
            b"redacted one",
            br#"{"private":"one"}"#,
        )
        .expect("generation one commits");
    let generation_one = fs::read_dir(directory.path().join("values"))
        .expect("value directory is readable")
        .map(|entry| entry.expect("directory entry is readable").path())
        .find(|path| path.to_string_lossy().contains("00000000000000000001"))
        .expect("generation-one value map exists");
    let replayed = fs::read(&generation_one).expect("generation one is readable");

    vault
        .store_record(
            "tenant-a",
            "record-a",
            b"original two",
            b"redacted two",
            br#"{"private":"two"}"#,
        )
        .expect("generation two commits");
    let generation_two = fs::read_dir(directory.path().join("values"))
        .expect("value directory is readable")
        .map(|entry| entry.expect("directory entry is readable").path())
        .find(|path| path.to_string_lossy().contains("00000000000000000002"))
        .expect("generation-two value map exists");
    fs::write(generation_two, replayed).expect("test restores older ciphertext");

    assert!(matches!(
        vault.load_value_map("tenant-a", "record-a"),
        Err(AdapterError::RollbackDetected)
    ));
}

#[test]
fn replacement_of_a_purged_record_is_not_found() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = VaultAdapter::open(directory.path(), SECRET).expect("vault opens");
    vault
        .store_record(
            "tenant-a",
            "record-a",
            b"original one",
            b"redacted one",
            br#"{"private":"one"}"#,
        )
        .expect("generation one commits");
    vault.purge("tenant-a", "record-a").expect("record purges");

    assert!(matches!(
        vault.replace_record(
            "tenant-a",
            "record-a",
            b"resurrected original",
            b"resurrected redacted document",
            br#"{"private":"resurrected"}"#,
        ),
        Err(AdapterError::RecordNotFound)
    ));
    for sub in ["values", "documents", "originals", "generations"] {
        assert_eq!(
            fs::read_dir(directory.path().join(sub))
                .expect("storage directory is readable")
                .count(),
            0,
            "{sub} remains empty after refused replacement"
        );
    }
}

#[test]
fn resumable_rotation_is_exposed_by_the_binding() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let first_secret = b"first tenant secret";
    let second_secret = b"second tenant secret";
    let first = VaultAdapter::open_keyring(directory.path(), 1, first_secret, &[])
        .expect("version-one vault opens");
    for index in 0..3 {
        first
            .store_record(
                "tenant-a",
                &format!("rotation-record-{index}"),
                format!("original-{index}").as_bytes(),
                format!("redacted-{index}").as_bytes(),
                format!(r#"{{"private":"{index}"}}"#).as_bytes(),
            )
            .expect("record commits");
    }
    drop(first);

    let rotated = VaultAdapter::open_keyring(
        directory.path(),
        2,
        second_secret,
        &[(1, first_secret.as_slice())],
    )
    .expect("rotated vault opens");
    let first_batch = rotated
        .reencrypt_batch(2, None, 2)
        .expect("first batch completes");
    assert_eq!((first_batch.visited, first_batch.rewritten), (2, 2));
    let cursor = first_batch.next_cursor.expect("one record remains");
    drop(rotated);

    let rotated = VaultAdapter::open_keyring(
        directory.path(),
        2,
        second_secret,
        &[(1, first_secret.as_slice())],
    )
    .expect("rotated vault reopens");
    let final_batch = rotated
        .reencrypt_batch(2, Some(&cursor), 2)
        .expect("final batch completes");
    assert_eq!((final_batch.visited, final_batch.rewritten), (1, 1));
    assert!(final_batch.next_cursor.is_none());
    let repeated = rotated
        .reencrypt_batch(2, None, 10)
        .expect("completed rotation is idempotent");
    assert_eq!((repeated.visited, repeated.rewritten), (3, 0));
    drop(rotated);

    let active_only = VaultAdapter::open_keyring(directory.path(), 2, second_secret, &[])
        .expect("historical key can be removed");
    let loaded = active_only
        .load_original("tenant-a", "rotation-record-0")
        .expect("migrated original opens");
    assert_eq!(loaded.as_slice(), b"original-0");
}

#[test]
fn late_original_frame_corruption_is_refused_by_the_binding() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = VaultAdapter::open(directory.path(), SECRET).expect("vault opens");
    let original = vec![b'p'; 2 * 64 * 1024 + 17];
    vault
        .store_record(
            "tenant-a",
            "late-frame-record",
            &original,
            b"redacted",
            br#"{"private":"value"}"#,
        )
        .expect("record commits");
    let original_path = fs::read_dir(directory.path().join("originals"))
        .expect("original directory is readable")
        .map(|entry| entry.expect("directory entry is readable").path())
        .find(|path| path.to_string_lossy().contains("00000000000000000001"))
        .expect("generation-one original exists");
    let mut ciphertext = fs::read(&original_path).expect("original ciphertext is readable");
    let last = ciphertext.last_mut().expect("ciphertext is not empty");
    *last ^= 0x80;
    fs::write(original_path, ciphertext).expect("late frame is corrupted");

    assert!(matches!(
        vault.load_original("tenant-a", "late-frame-record"),
        Err(AdapterError::AuthenticationFailed)
    ));
}
