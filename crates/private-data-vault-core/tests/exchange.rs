//! The managed exchange flow: seal in one process, open in another.
//!
//! The managed tier persists sealed objects in external storage between
//! operations. These tests prove the property that makes that safe: a record
//! exported from one `MemoryBackend` and imported into a completely fresh one
//! opens correctly — same sealing code, no filesystem, nothing process-local
//! smuggled inside the sealed bytes.

use std::{collections::BTreeMap, io::Cursor};

use private_data_vault_core::{MemoryBackend, RecordIdentity, Vault, VaultError};

const SECRET: &[u8] = b"managed-exchange-test-secret";
const SALT: [u8; 16] = *b"tenant-salt-0001";

fn identity() -> RecordIdentity {
    RecordIdentity::new("tenant-a", "doc0aa11bb22").expect("test identity is valid")
}

fn values(value: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("<PRIVATE_1>".to_owned(), value.to_owned())])
}

fn vault() -> Vault<MemoryBackend> {
    Vault::open(MemoryBackend::new(SALT), SECRET).expect("vault opens over a memory backend")
}

fn seal_one(value: &str) -> private_data_vault_core::ExchangeRecord {
    let sealing = vault();
    sealing
        .store_record(
            &identity(),
            &mut Cursor::new(b"original bytes".to_vec()),
            &mut Cursor::new(b"redacted bytes".to_vec()),
            &values(value),
        )
        .expect("record seals");
    sealing
        .backend()
        .export_record(&identity())
        .expect("complete record exports")
}

#[test]
fn a_record_sealed_in_one_backend_opens_from_a_fresh_one() {
    let exported = seal_one("secret-value");
    assert_eq!(exported.generation, 1, "first seal is generation one");

    // A completely fresh backend, as if another process had fetched the
    // sealed objects from the database.
    let opening = vault();
    opening.backend().import_record(&identity(), &exported);

    let mut document = Vec::new();
    opening
        .load_document(&identity(), &mut document)
        .expect("document opens after transport");
    assert_eq!(document, b"redacted bytes");

    let mut original = Vec::new();
    opening
        .load_original(&identity(), &mut original)
        .expect("original opens after transport");
    assert_eq!(original, b"original bytes");

    let restored = opening
        .load_value_map(&identity())
        .expect("value map opens after transport");
    assert_eq!(restored["<PRIVATE_1>"], "secret-value");
}

#[test]
fn replacement_advances_the_generation_and_the_old_export_is_refused() {
    let first = seal_one("first-value");

    let replacing = vault();
    replacing.backend().import_record(&identity(), &first);
    replacing
        .replace_record(
            &identity(),
            &mut Cursor::new(b"original two".to_vec()),
            &mut Cursor::new(b"redacted two".to_vec()),
            &values("second-value"),
        )
        .expect("replacement succeeds over the hydrated record");
    let second = replacing
        .backend()
        .export_record(&identity())
        .expect("replacement exports");
    assert_eq!(second.generation, 2, "replacement advances the generation");

    // Replaying the superseded export against a backend that has trusted the
    // newer generation must refuse to open: this is the replay protection the
    // generation column in the database row exists to carry.
    let replayed = vault();
    replayed.backend().import_record(&identity(), &second);
    replayed.backend().import_record(
        &identity(),
        &private_data_vault_core::ExchangeRecord {
            generation: second.generation,
            original: first.original.clone(),
            document: first.document.clone(),
            value_map: first.value_map.clone(),
        },
    );
    let mut sink = Vec::new();
    let refusal = replayed.load_document(&identity(), &mut sink);
    assert!(
        refusal.is_err(),
        "generation-one ciphertext presented as generation two must not open"
    );
}

#[test]
fn a_wrong_secret_cannot_open_a_transported_record() {
    let exported = seal_one("secret-value");

    let wrong = Vault::open(MemoryBackend::new(SALT), b"a-different-secret")
        .expect("vault opens with any secret");
    wrong.backend().import_record(&identity(), &exported);
    let mut sink = Vec::new();
    let refusal = wrong.load_document(&identity(), &mut sink);
    assert!(matches!(
        refusal,
        Err(VaultError::AuthenticationFailed | VaultError::Storage(_))
    ));
}

#[test]
fn an_incomplete_record_does_not_export() {
    let sealing = vault();
    sealing
        .store_record(
            &identity(),
            &mut Cursor::new(b"original bytes".to_vec()),
            &mut Cursor::new(b"redacted bytes".to_vec()),
            &values("secret-value"),
        )
        .expect("record seals");
    let absent = RecordIdentity::new("tenant-a", "doc99ff88ee77").expect("identity is valid");
    assert!(
        sealing.backend().export_record(&absent).is_none(),
        "a record that was never sealed exports nothing"
    );
}
