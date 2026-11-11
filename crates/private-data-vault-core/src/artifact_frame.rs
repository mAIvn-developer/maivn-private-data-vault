//! The deployed MVN1 framing for the artifact vault's sealed records.

pub const MAGIC: &[u8; 4] = b"MVN1";
pub const HEADER_LEN: usize = MAGIC.len() + 8 + 4;

/// Start a frame using the caller's already-encoded big-endian generation counter.
#[must_use]
pub fn start(counter: &[u8], part_count: u32) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_LEN);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(counter);
    frame.extend_from_slice(&part_count.to_be_bytes());
    frame
}

/// Append a length-prefixed sealed part in frame order.
pub fn append_part(frame: &mut Vec<u8>, size: u32, part: &[u8]) {
    frame.extend_from_slice(&size.to_be_bytes());
    frame.extend_from_slice(part);
}

/// Decode a complete frame. A malformed or trailing byte has no partial result.
#[must_use]
pub fn unpack(blob: &[u8]) -> Option<(u64, Vec<&[u8]>)> {
    let (counter, payload) = blob.strip_prefix(MAGIC)?.split_first_chunk::<8>()?;
    let (count, mut payload) = payload.split_first_chunk::<4>()?;
    let count = u32::from_be_bytes(*count) as usize;
    if count > payload.len() / 4 {
        return None;
    }
    let mut parts = Vec::new();
    for _ in 0..count {
        let (size, after_size) = payload.split_first_chunk::<4>()?;
        let (part, after_part) = after_size.split_at_checked(u32::from_be_bytes(*size) as usize)?;
        parts.push(part);
        payload = after_part;
    }
    payload
        .is_empty()
        .then_some((u64::from_be_bytes(*counter), parts))
}
