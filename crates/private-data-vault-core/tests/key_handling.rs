//! Key handling through the public API: identity validation and binding, key
//! versions, and keyring construction.

use std::{collections::BTreeMap, io::Cursor};

use private_data_vault_core::{
    KeyVersion, Keyring, MemoryBackend, RecordIdentity, StorageError, Vault, VaultError,
};

fn values(value: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("[NAME_1]".to_owned(), value.to_owned())])
}

fn version(value: u32) -> KeyVersion {
    KeyVersion::new(value).expect("non-zero version")
}

#[test]
fn an_identity_needs_both_a_tenant_and_a_record() {
    for (tenant, record) in [("", "record"), ("tenant", ""), ("", "")] {
        assert!(
            matches!(
                RecordIdentity::new(tenant, record),
                Err(VaultError::InvalidIdentity)
            ),
            "{tenant:?} / {record:?} must be refused"
        );
    }
    assert!(RecordIdentity::new("t", "r").is_ok());
}

#[test]
fn identities_that_concatenate_alike_never_share_a_record() {
    let vault = Vault::open(MemoryBackend::new([7; 16]), b"secret").expect("vault opens");
    let bundled = RecordIdentity::new("ab", "c").expect("identity");
    let standalone = RecordIdentity::new("ab", "d").expect("identity");
    vault
        .store_record(
            &bundled,
            &mut Cursor::new(b"original"),
            &mut Cursor::new(b"document"),
            &values("first"),
        )
        .expect("record stores");
    vault
        .store_value_map(&standalone, &values("second"))
        .expect("value map stores");

    for (lookalike, stored) in [("bc", &bundled), ("bd", &standalone)] {
        let lookalike = RecordIdentity::new("a", lookalike).expect("identity");
        assert!(matches!(
            vault.load_value_map(&lookalike),
            Err(VaultError::Storage(StorageError::NotFound))
        ));
        assert!(vault.load_value_map(stored).is_ok());
    }
}

#[test]
fn key_version_zero_is_reserved_and_others_round_trip() {
    assert!(matches!(
        KeyVersion::new(0),
        Err(VaultError::InvalidKeyVersion)
    ));
    assert_eq!(version(1).get(), 1);
    assert_eq!(version(u32::MAX).get(), u32::MAX);
}

#[test]
fn a_keyring_refuses_empty_secrets_and_duplicate_versions() {
    assert!(matches!(
        Keyring::new(version(1), b""),
        Err(VaultError::InvalidSecret)
    ));
    let keyring = || Keyring::new(version(2), b"active").expect("keyring");
    assert!(matches!(
        keyring().with_decrypt_only(version(1), b""),
        Err(VaultError::InvalidSecret)
    ));
    assert!(matches!(
        keyring().with_decrypt_only(version(2), b"other"),
        Err(VaultError::DuplicateKeyVersion(2))
    ));
    assert!(matches!(
        keyring()
            .with_decrypt_only(version(1), b"old")
            .and_then(|ring| ring.with_decrypt_only(version(1), b"older")),
        Err(VaultError::DuplicateKeyVersion(1))
    ));
}

#[test]
fn only_the_active_key_writes_and_a_missing_key_is_named() {
    let identity = RecordIdentity::new("tenant", "record").expect("identity");
    let salt = [3; 16];
    let keyring = Keyring::new(version(2), b"new secret")
        .and_then(|ring| ring.with_decrypt_only(version(1), b"old secret"))
        .expect("keyring");
    let writer = Vault::open_keyring(MemoryBackend::new(salt), keyring).expect("vault opens");
    writer
        .store_record(
            &identity,
            &mut Cursor::new(b"original"),
            &mut Cursor::new(b"document"),
            &values("Ada"),
        )
        .expect("record stores");
    let exported = writer
        .backend()
        .export_record(&identity)
        .expect("complete record");

    let reader = |version_number, secret: &[u8]| {
        let backend = MemoryBackend::new(salt);
        backend
            .import_record(&identity, &exported)
            .expect("imports");
        Vault::open_keyring(
            backend,
            Keyring::new(version(version_number), secret).expect("keyring"),
        )
        .expect("vault opens")
    };
    assert!(matches!(
        reader(1, b"old secret").load_value_map(&identity),
        Err(VaultError::UnknownKeyVersion(2))
    ));
    assert_eq!(
        reader(2, b"new secret")
            .load_value_map(&identity)
            .expect("active key opens"),
        values("Ada")
    );
    assert!(matches!(
        reader(2, b"wrong secret").load_value_map(&identity),
        Err(VaultError::AuthenticationFailed)
    ));
}
