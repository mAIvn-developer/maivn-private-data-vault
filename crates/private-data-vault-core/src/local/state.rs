//! `vault.state`: the key-derivation salt, the instance id and the persistent
//! nonce counter, kept in two checksummed slots.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
};

use sha2::{Digest, Sha256};

use crate::StorageError;

const STATE_MAGIC: &[u8; 8] = b"PDVST002";

/// One slot: magic, generation, salt, instance id, counter, checksum.
const SLOT_BYTES: usize = 8 + 8 + 16 + 11 + 8 + 32;

/// Two slots, written alternately.
///
/// The previous format kept ONE record and overwrote it in place, protected by
/// nothing but a magic string and a length check. That is a nonce-reuse hazard,
/// which for XChaCha20-Poly1305 is the one failure that destroys
/// confidentiality outright rather than degrading it: with `next_counter` at
/// 255, the update to 256 rewrites `..00ff` to `..0100`, and a power loss
/// during that write can leave `..0000` durable. Reopening would accept counter
/// zero and reissue a nonce prefix already used under the same key. Two
/// keystreams under one nonce are XOR-recoverable, and the Poly1305 key falls
/// out with them.
///
/// So: never overwrite the live record. Write the OTHER slot, checksum it,
/// sync it, and let the higher generation win. A torn write damages only the
/// slot being written, whose checksum then fails, and the previous generation
/// is still intact beside it. The counter can skip forward on a crash; it can
/// never go backwards.
const STATE_BYTES: usize = SLOT_BYTES * 2;

#[derive(Clone, Copy)]
pub(super) struct State {
    pub(super) salt: [u8; 16],
    pub(super) instance_id: [u8; 11],
    pub(super) next_counter: u64,
    /// Monotonic write generation. Decides which slot is live; never reused.
    pub(super) generation: u64,
}

/// Serialise one slot with its checksum.
fn encode_slot(state: &State) -> [u8; SLOT_BYTES] {
    let mut bytes = [0; SLOT_BYTES];
    bytes[..8].copy_from_slice(STATE_MAGIC);
    bytes[8..16].copy_from_slice(&state.generation.to_be_bytes());
    bytes[16..32].copy_from_slice(&state.salt);
    bytes[32..43].copy_from_slice(&state.instance_id);
    bytes[43..51].copy_from_slice(&state.next_counter.to_be_bytes());
    let digest = Sha256::digest(&bytes[..51]);
    bytes[51..].copy_from_slice(&digest);
    bytes
}

/// Parse one slot, returning `None` when it is absent, torn or corrupt.
///
/// A damaged slot is not an error. It is the expected state of the slot that
/// was mid-write when the power went, and the whole point of keeping two.
fn decode_slot(bytes: &[u8]) -> Option<State> {
    if bytes.len() < SLOT_BYTES || &bytes[..8] != STATE_MAGIC {
        return None;
    }
    let digest = Sha256::digest(&bytes[..51]);
    // Constant time is unnecessary here: this is an integrity check against
    // power loss, not a secret comparison, and the input is not attacker-chosen
    // in the sense that would make timing meaningful.
    if digest.as_slice() != &bytes[51..SLOT_BYTES] {
        return None;
    }
    let mut generation = [0; 8];
    generation.copy_from_slice(&bytes[8..16]);
    let mut salt = [0; 16];
    salt.copy_from_slice(&bytes[16..32]);
    let mut instance_id = [0; 11];
    instance_id.copy_from_slice(&bytes[32..43]);
    let mut counter = [0; 8];
    counter.copy_from_slice(&bytes[43..51]);
    Some(State {
        salt,
        instance_id,
        next_counter: u64::from_be_bytes(counter),
        generation: u64::from_be_bytes(generation),
    })
}

pub(super) fn read_state(file: &mut File) -> Result<State, StorageError> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = [0; STATE_BYTES];
    file.read_exact(&mut bytes)
        .map_err(|_| StorageError::InvalidMetadata)?;

    // Highest valid generation wins. One torn slot is survivable and expected;
    // both invalid means we cannot establish where the nonce counter had
    // reached, and continuing from a guess is how a nonce gets reissued. Fail
    // closed: a vault that will not open is recoverable from backup, a vault
    // that reuses a nonce is not.
    let first = decode_slot(&bytes[..SLOT_BYTES]);
    let second = decode_slot(&bytes[SLOT_BYTES..]);
    match (first, second) {
        (Some(a), Some(b)) => Ok(if a.generation >= b.generation { a } else { b }),
        (Some(only), None) | (None, Some(only)) => Ok(only),
        (None, None) => Err(StorageError::InvalidMetadata),
    }
}

pub(super) fn write_state(file: &mut File, state: &State) -> Result<(), StorageError> {
    // Write the slot the live record is NOT in, so a torn write cannot damage
    // the only copy of where the nonce counter had reached.
    let mut next = *state;
    next.generation = state.generation.wrapping_add(1);
    let offset = if next.generation.is_multiple_of(2) {
        0
    } else {
        SLOT_BYTES
    };

    let encoded = encode_slot(&next);
    file.seek(SeekFrom::Start(
        u64::try_from(offset).expect("slot offset fits in u64"),
    ))?;
    file.write_all(&encoded)?;
    // Sync before the caller is allowed to use the prefix. A returned nonce
    // whose increment is still in the page cache is a nonce this vault can
    // issue twice.
    file.sync_all()?;
    Ok(())
}
