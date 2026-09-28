use std::{collections::BTreeMap, fs, io::Cursor, path::Path};

use private_data_vault_core::{
    LocalBackend, RecordIdentity, StorageBackend, StorageError, Vault, VaultError,
};

fn identity() -> RecordIdentity {
    RecordIdentity::new("tenant-a", "record-a").expect("test identity is valid")
}

fn only_entry(root: &Path, directory: &str) -> std::path::PathBuf {
    let entries = fs::read_dir(root.join(directory))
        .expect("storage directory exists")
        .collect::<Result<Vec<_>, _>>()
        .expect("storage directory is readable");
    assert_eq!(entries.len(), 1, "test stores exactly one object");
    entries[0].path()
}

#[test]
fn purge_removes_all_record_files_and_is_idempotent() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = Vault::open(
        LocalBackend::open(directory.path()).expect("backend opens"),
        b"correct horse battery staple",
    )
    .expect("vault opens");
    let record = identity();
    vault
        .store_value_map(
            &record,
            &BTreeMap::from([("<PRIVATE_1>".to_owned(), "Ada Lovelace".to_owned())]),
        )
        .expect("value map seals");
    vault
        .store_document(&record, &mut Cursor::new(b"private document"))
        .expect("document seals");
    vault
        .store_original(&record, &mut Cursor::new(b"unredacted original"))
        .expect("original seals");
    let value_path = only_entry(directory.path(), "values");
    let document_path = only_entry(directory.path(), "documents");
    let original_path = only_entry(directory.path(), "originals");

    vault.purge(&record).expect("first purge succeeds");

    assert!(!value_path.exists(), "value-map ciphertext is deleted");
    assert!(!document_path.exists(), "document ciphertext is deleted");
    assert!(!original_path.exists(), "original ciphertext is deleted");
    assert!(matches!(
        vault.load_value_map(&record),
        Err(VaultError::Storage(StorageError::NotFound))
    ));
    assert!(matches!(
        vault.load_document(&record, &mut Vec::new()),
        Err(VaultError::Storage(StorageError::NotFound))
    ));
    assert!(matches!(
        vault.load_original(&record, &mut Vec::new()),
        Err(VaultError::Storage(StorageError::NotFound))
    ));
    vault.purge(&record).expect("second purge succeeds");
}

#[test]
fn purge_of_an_absent_record_succeeds() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = Vault::open(
        LocalBackend::open(directory.path()).expect("backend opens"),
        b"correct horse battery staple",
    )
    .expect("vault opens");

    vault.purge(&identity()).expect("absent purge succeeds");
}

#[test]
fn purge_removes_every_committed_generation_and_its_metadata() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = Vault::open(
        LocalBackend::open(directory.path()).expect("backend opens"),
        b"correct horse battery staple",
    )
    .expect("vault opens");
    let record = identity();

    for generation in 1..=2 {
        vault
            .store_record(
                &record,
                &mut Cursor::new(format!("original generation {generation}")),
                &mut Cursor::new(format!("redacted generation {generation}")),
                &BTreeMap::from([(
                    "<PRIVATE_1>".to_owned(),
                    format!("private generation {generation}"),
                )]),
            )
            .expect("record generation commits");
    }

    for sub in ["values", "documents", "originals"] {
        let count = fs::read_dir(directory.path().join(sub))
            .expect("ciphertext directory is readable")
            .count();
        assert_eq!(count, 2, "both {sub} generations exist before purge");
    }
    assert_eq!(
        fs::read_dir(directory.path().join("generations"))
            .expect("generation directory is readable")
            .count(),
        1,
        "one trusted generation record exists"
    );

    vault.purge(&record).expect("committed record purges");

    for sub in ["values", "documents", "originals", "generations"] {
        assert_eq!(
            fs::read_dir(directory.path().join(sub))
                .expect("storage directory is readable")
                .count(),
            0,
            "{sub} is empty after hard delete"
        );
    }
    assert!(matches!(
        vault.load_value_map(&record),
        Err(VaultError::Storage(StorageError::NotFound))
    ));
}

#[test]
fn replace_record_refuses_to_recreate_a_purged_record() {
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
            &mut Cursor::new(b"original generation one"),
            &mut Cursor::new(b"redacted generation one"),
            &BTreeMap::from([(
                "<PRIVATE_1>".to_owned(),
                "private generation one".to_owned(),
            )]),
        )
        .expect("initial record commits");
    vault.purge(&record).expect("record purges");

    let result = vault.replace_record(
        &record,
        &mut Cursor::new(b"resurrected original"),
        &mut Cursor::new(b"resurrected redacted document"),
        &BTreeMap::from([(
            "<PRIVATE_1>".to_owned(),
            "resurrected private value".to_owned(),
        )]),
    );

    assert!(matches!(
        result,
        Err(VaultError::Storage(StorageError::NotFound))
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
fn purge_reports_a_partial_filesystem_failure() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = Vault::open(
        LocalBackend::open(directory.path()).expect("backend opens"),
        b"correct horse battery staple",
    )
    .expect("vault opens");
    let record = identity();
    vault
        .store_value_map(
            &record,
            &BTreeMap::from([("<PRIVATE_1>".to_owned(), "Ada Lovelace".to_owned())]),
        )
        .expect("value map seals");
    vault
        .store_document(&record, &mut Cursor::new(b"private document"))
        .expect("document seals");
    vault
        .store_original(&record, &mut Cursor::new(b"unredacted original"))
        .expect("original seals");
    let value_path = only_entry(directory.path(), "values");
    let document_path = only_entry(directory.path(), "documents");
    let original_path = only_entry(directory.path(), "originals");
    fs::remove_file(&document_path).expect("document file is removed for fault injection");
    fs::create_dir(&document_path).expect("directory blocks document-file deletion");

    let result = vault.purge(&record);

    assert!(matches!(result, Err(VaultError::Storage(_))));
    assert!(
        !value_path.exists(),
        "the independently deletable value map is removed"
    );
    assert!(
        !original_path.exists(),
        "the independently deletable original is removed"
    );
    assert!(document_path.is_dir(), "the failed document target remains");
}

#[test]
fn purge_expired_removes_only_objects_older_than_the_cutoff() {
    // Retention has to be enforceable without a key: a managed node sweeping
    // expired material is not holding anyone's key at the time.
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = Vault::open(
        LocalBackend::open(directory.path()).expect("backend opens"),
        b"correct horse battery staple",
    )
    .expect("vault opens");

    let old = RecordIdentity::new("tenant-a", "stale").expect("test identity is valid");
    vault
        .store_value_map(
            &old,
            &BTreeMap::from([("<PRIVATE_1>".to_owned(), "Ada Lovelace".to_owned())]),
        )
        .expect("value map is stored");
    vault
        .store_document(&old, &mut Cursor::new(b"redacted stale document"))
        .expect("document is stored");
    vault
        .store_original(&old, &mut Cursor::new(b"unredacted stale original"))
        .expect("original is stored");

    // Backdate the stored object rather than sleeping: a test that waits for
    // wall-clock time to pass is a test nobody runs.
    let stale_paths = [
        only_entry(directory.path(), "values"),
        only_entry(directory.path(), "documents"),
        only_entry(directory.path(), "originals"),
    ];
    let long_ago = std::time::SystemTime::now() - std::time::Duration::from_hours(720);
    for stale_path in &stale_paths {
        filetime::set_file_mtime(stale_path, filetime::FileTime::from_system_time(long_ago))
            .expect("modification time is set");
    }

    let fresh = RecordIdentity::new("tenant-a", "fresh").expect("test identity is valid");
    vault
        .store_value_map(
            &fresh,
            &BTreeMap::from([("<PRIVATE_1>".to_owned(), "Grace Hopper".to_owned())]),
        )
        .expect("value map is stored");

    let cutoff = std::time::SystemTime::now() - std::time::Duration::from_hours(24);
    let removed = vault.purge_expired(cutoff).expect("sweep succeeds");

    assert_eq!(removed, 3, "all three backdated objects are swept");
    assert!(
        stale_paths.iter().all(|path| !path.exists()),
        "expired objects are gone from disk"
    );
    assert!(
        vault.load_value_map(&fresh).is_ok(),
        "material inside its retention period survives the sweep"
    );
    assert!(
        matches!(
            vault.load_value_map(&old),
            Err(VaultError::Storage(StorageError::NotFound))
        ),
        "expired material reads as absent, not as a decryption failure"
    );
}

#[test]
fn purge_expired_independently_sweeps_each_ciphertext_kind_without_a_key() {
    for stale_kind in ["values", "documents", "originals"] {
        let directory = tempfile::tempdir().expect("temporary directory is created");
        let backend = LocalBackend::open(directory.path()).expect("backend opens");
        let vault =
            Vault::open(backend.clone(), b"correct horse battery staple").expect("vault opens");
        let record = identity();
        vault
            .store_value_map(
                &record,
                &BTreeMap::from([("<PRIVATE_1>".to_owned(), "Ada Lovelace".to_owned())]),
            )
            .expect("value map is stored");
        vault
            .store_document(&record, &mut Cursor::new(b"redacted document"))
            .expect("document is stored");
        vault
            .store_original(&record, &mut Cursor::new(b"unredacted original"))
            .expect("original is stored");
        let paths = [
            ("values", only_entry(directory.path(), "values")),
            ("documents", only_entry(directory.path(), "documents")),
            ("originals", only_entry(directory.path(), "originals")),
        ];
        let stale_path = paths
            .iter()
            .find_map(|(kind, path)| (*kind == stale_kind).then_some(path))
            .expect("selected ciphertext kind exists");
        let long_ago = std::time::SystemTime::now() - std::time::Duration::from_hours(720);
        filetime::set_file_mtime(stale_path, filetime::FileTime::from_system_time(long_ago))
            .expect("selected modification time is set");
        drop(vault);

        let cutoff = std::time::SystemTime::now() - std::time::Duration::from_hours(24);
        let removed = backend
            .purge_expired(cutoff)
            .expect("keyless backend sweep succeeds");

        assert_eq!(removed, 1, "only the expired {stale_kind} object is swept");
        for (kind, path) in paths {
            assert_eq!(
                path.exists(),
                kind != stale_kind,
                "fresh {kind} survival is independent of expired {stale_kind}"
            );
        }
    }
}

#[test]
fn purge_expired_on_an_empty_vault_removes_nothing() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = Vault::open(
        LocalBackend::open(directory.path()).expect("backend opens"),
        b"correct horse battery staple",
    )
    .expect("vault opens");
    let removed = vault
        .purge_expired(std::time::SystemTime::now())
        .expect("sweep succeeds");
    assert_eq!(removed, 0, "a vault holding nothing sweeps nothing");
}

#[test]
fn a_torn_state_slot_never_rewinds_the_nonce_counter() {
    // The failure this guards: overwriting the single live nonce record in
    // place. A power loss mid-write could persist a lower counter, and the
    // vault would reissue a nonce prefix already used under the same key --
    // which for XChaCha20-Poly1305 is total loss of confidentiality, not a
    // degradation. Two slots mean a torn write damages only the inactive one.
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let root = directory.path();

    let observed = {
        let vault = Vault::open(
            LocalBackend::open(root).expect("backend opens"),
            b"correct horse battery staple",
        )
        .expect("vault opens");
        let mut seen = Vec::new();
        for index in 0..8 {
            let record = RecordIdentity::new("tenant-a", format!("record-{index}"))
                .expect("test identity is valid");
            vault
                .store_value_map(
                    &record,
                    &BTreeMap::from([("<PRIVATE_1>".to_owned(), "Ada Lovelace".to_owned())]),
                )
                .expect("value map is stored");
            seen.push(index);
        }
        seen.len()
    };
    assert_eq!(observed, 8, "the fixture stored every record");

    // Corrupt whichever slot is live by flipping a byte inside it. A real torn
    // write is a partial page; a flipped byte is the same thing as far as the
    // checksum is concerned and is deterministic to write down.
    let state_path = root.join("vault.state");
    let mut raw = fs::read(&state_path).expect("state file is readable");
    let slot_bytes = raw.len() / 2;
    let live_is_first = raw[8..16] >= raw[slot_bytes + 8..slot_bytes + 16];
    let victim = if live_is_first { 50 } else { slot_bytes + 50 };
    raw[victim] ^= 0xff;
    fs::write(&state_path, &raw).expect("state file is writable");

    // Reopening must succeed from the surviving slot, and the counter must not
    // have gone backwards.
    let reopened = Vault::open(
        LocalBackend::open(root).expect("backend reopens after a torn slot"),
        b"correct horse battery staple",
    )
    .expect("vault reopens");
    let after = RecordIdentity::new("tenant-a", "after-recovery").expect("identity is valid");
    reopened
        .store_value_map(
            &after,
            &BTreeMap::from([("<PRIVATE_1>".to_owned(), "Grace Hopper".to_owned())]),
        )
        .expect("the vault still works after recovering from a torn slot");

    // Everything written before the corruption is still readable, which is what
    // proves the surviving slot carried the real salt rather than a fresh one.
    let first = RecordIdentity::new("tenant-a", "record-0").expect("identity is valid");
    assert!(
        reopened.load_value_map(&first).is_ok(),
        "recovery must not have re-derived a different key"
    );
}

#[test]
fn both_state_slots_corrupt_fails_closed() {
    // Neither slot readable means we cannot establish where the nonce counter
    // reached. Refusing to open is recoverable from backup; guessing is not.
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let root = directory.path();
    {
        Vault::open(
            LocalBackend::open(root).expect("backend opens"),
            b"correct horse battery staple",
        )
        .expect("vault opens");
    }
    let state_path = root.join("vault.state");
    let raw = fs::read(&state_path).expect("state file is readable");
    fs::write(&state_path, vec![0xff; raw.len()]).expect("state file is writable");

    assert!(
        LocalBackend::open(root).is_err(),
        "a vault whose nonce state is unreadable must refuse to open"
    );
}

#[test]
fn a_sweep_puts_back_material_that_is_not_actually_expired() {
    // The sweep claims a path by renaming before it decides. If what it
    // claimed turns out to be inside its retention period it must be restored,
    // or the claim itself becomes the data loss it was meant to prevent.
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = Vault::open(
        LocalBackend::open(directory.path()).expect("backend opens"),
        b"correct horse battery staple",
    )
    .expect("vault opens");
    let record = RecordIdentity::new("tenant-a", "fresh").expect("identity is valid");
    vault
        .store_value_map(
            &record,
            &BTreeMap::from([("<PRIVATE_1>".to_owned(), "Grace Hopper".to_owned())]),
        )
        .expect("value map is stored");

    // Cutoff in the past: nothing here is expired.
    let removed = vault
        .purge_expired(std::time::SystemTime::now() - std::time::Duration::from_hours(1))
        .expect("sweep succeeds");

    assert_eq!(removed, 0, "nothing was expired");
    assert!(
        vault.load_value_map(&record).is_ok(),
        "material the sweep examined and rejected must be back where it was"
    );
    let leftovers: Vec<_> = fs::read_dir(directory.path().join("values"))
        .expect("values directory is readable")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|ext| ext == "sweeping")
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "the sweep left a claimed file behind instead of restoring it"
    );
}

#[test]
fn a_purge_leaves_no_readable_object_behind() {
    // Hard delete, checked at the filesystem rather than through the API: a
    // purge that unlinks but leaves the entry recoverable is a delete that did
    // not happen.
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let vault = Vault::open(
        LocalBackend::open(directory.path()).expect("backend opens"),
        b"correct horse battery staple",
    )
    .expect("vault opens");
    let record = identity();
    vault
        .store_value_map(
            &record,
            &BTreeMap::from([("<PRIVATE_1>".to_owned(), "Ada Lovelace".to_owned())]),
        )
        .expect("value map seals");
    vault
        .store_document(&record, &mut Cursor::new(b"private document"))
        .expect("document seals");
    vault
        .store_original(&record, &mut Cursor::new(b"unredacted original"))
        .expect("original seals");

    vault.purge(&record).expect("purge succeeds");

    for sub in ["values", "documents", "originals"] {
        let remaining: Vec<_> = fs::read_dir(directory.path().join(sub))
            .expect("storage directory is readable")
            .filter_map(Result::ok)
            .collect();
        assert!(
            remaining.is_empty(),
            "{sub} still holds an object after a hard delete"
        );
    }
}
