//! Damaged or foreign sealed objects are refused with a typed error. (A
//! stream can fail after earlier authenticated frames were written; that is
//! the documented contract of `load_document`.)

use std::{collections::BTreeMap, io::Cursor};

use private_data_vault_core::{ExchangeRecord, MemoryBackend, RecordIdentity, Vault, VaultError};

/// Bytes before the first frame of a version-2 stream:
/// magic, key version, generation, nonce prefix.
const STREAM_HEADER: usize = 8 + 4 + 8 + 19;

/// One way to damage a sealed object.
type Damage = fn(&mut Vec<u8>);

fn identity() -> RecordIdentity {
    RecordIdentity::new("tenant", "record").expect("identity")
}

fn vault() -> Vault<MemoryBackend> {
    Vault::open(MemoryBackend::new([6; 16]), b"secret").expect("vault opens")
}

fn sealed() -> ExchangeRecord {
    let vault = vault();
    vault
        .store_record(
            &identity(),
            &mut Cursor::new(b"original"),
            &mut Cursor::new(b"document"),
            &BTreeMap::from([("[NAME_1]".to_owned(), "Ada".to_owned())]),
        )
        .expect("stores");
    vault.backend().export_record(&identity()).expect("record")
}

/// Opens a damaged record: the value map and the document.
fn open(record: &ExchangeRecord) -> (Result<(), VaultError>, Result<(), VaultError>) {
    let vault = vault();
    vault
        .backend()
        .import_record(&identity(), record)
        .expect("imports");
    let values = vault.load_value_map(&identity()).map(drop);
    let document = vault.load_document(&identity(), &mut Vec::new());
    (values, document)
}

fn damaged_value_map(damage: impl FnOnce(&mut Vec<u8>)) -> Result<(), VaultError> {
    let mut record = sealed();
    damage(&mut record.value_map);
    open(&record).0
}

fn damaged_document(damage: impl FnOnce(&mut Vec<u8>)) -> Result<(), VaultError> {
    let mut record = sealed();
    damage(&mut record.document);
    open(&record).1
}

#[test]
fn malformed_value_map_envelopes_are_invalid_format() {
    let cases: [(&str, Damage); 6] = [
        ("shorter than its magic", |sealed| sealed.truncate(5)),
        ("unknown magic", |sealed| sealed[7] = b'9'),
        ("version-2 header cut short", |sealed| sealed.truncate(54)),
        ("key version zero", |sealed| sealed[8..12].fill(0)),
        ("generation zero", |sealed| sealed[12..20].fill(0)),
        ("version-1 object cut short", |sealed| {
            sealed.truncate(8 + 34);
            sealed[..8].copy_from_slice(b"PDVMAP01");
        }),
    ];
    for (label, damage) in cases {
        assert!(
            matches!(damaged_value_map(damage), Err(VaultError::InvalidFormat)),
            "{label}"
        );
    }
}

#[test]
fn a_version_one_object_cannot_stand_in_for_a_committed_generation() {
    let result = damaged_value_map(|sealed| {
        let prefix_and_ciphertext = sealed[20..].to_vec();
        sealed.clear();
        sealed.extend_from_slice(b"PDVMAP01");
        sealed.extend(prefix_and_ciphertext);
    });
    assert!(matches!(
        result,
        Err(VaultError::RollbackDetected {
            trusted: 1,
            envelope: 0
        })
    ));
    let result = damaged_document(|sealed| {
        let rest = sealed[20..].to_vec();
        sealed.clear();
        sealed.extend_from_slice(b"PDVDOC01");
        sealed.extend(rest);
    });
    assert!(matches!(
        result,
        Err(VaultError::RollbackDetected {
            trusted: 1,
            envelope: 0
        })
    ));
}

fn first_frame_length(sealed: &mut [u8]) -> &mut [u8] {
    &mut sealed[STREAM_HEADER + 1..STREAM_HEADER + 5]
}

#[test]
fn malformed_streams_are_invalid_format() {
    let cases: [(&str, Damage); 8] = [
        ("unknown magic", |sealed| sealed[7] = b'9'),
        ("header cut short", |sealed| {
            sealed.truncate(STREAM_HEADER - 1);
        }),
        ("key version zero", |sealed| sealed[8..12].fill(0)),
        ("generation zero", |sealed| sealed[12..20].fill(0)),
        ("unknown frame kind", |sealed| sealed[STREAM_HEADER] = 7),
        ("data frame without plaintext", |sealed| {
            first_frame_length(sealed).copy_from_slice(&16_u32.to_be_bytes());
        }),
        ("data frame beyond the chunk size", |sealed| {
            first_frame_length(sealed).copy_from_slice(&(64 * 1024 + 17_u32).to_be_bytes());
        }),
        ("bytes after the final frame", |sealed| sealed.push(0)),
    ];
    for (label, damage) in cases {
        assert!(
            matches!(damaged_document(damage), Err(VaultError::InvalidFormat)),
            "{label}"
        );
    }
}

#[test]
fn a_final_frame_must_carry_only_its_tag() {
    let result = damaged_document(|sealed| {
        // The document is one data frame then the final frame; lengthen the
        // final frame's declared size by one byte and supply that byte.
        let final_frame = sealed.len() - 21;
        sealed[final_frame + 1..final_frame + 5].copy_from_slice(&17_u32.to_be_bytes());
        sealed.push(0);
    });
    assert!(matches!(result, Err(VaultError::InvalidFormat)));
}
