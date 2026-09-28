use crate::{KeyVersion, VaultError};

const CURSOR_PREFIX: &str = "pdv-reencrypt-v2:";
const CURSOR_SCOPE_BYTES: usize = 16;
const CURSOR_TARGET_BYTES: usize = size_of::<u32>();
const CURSOR_KEY_BYTES: usize = 32;
const CURSOR_TAG_BYTES: usize = 32;
const CURSOR_PAYLOAD_BYTES: usize =
    CURSOR_SCOPE_BYTES + CURSOR_TARGET_BYTES + CURSOR_KEY_BYTES + CURSOR_TAG_BYTES;

/// Opaque resume position returned by a bounded re-encryption batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReencryptCursor {
    pub(crate) record_key: [u8; 32],
    pub(crate) scope: [u8; 16],
    pub(crate) target_version: KeyVersion,
    pub(crate) tag: [u8; 32],
}

impl ReencryptCursor {
    /// Serializes this cursor for durable job state without revealing tenant or
    /// record identifiers. The payload contains only non-secret vault scope and
    /// target metadata, the one-way record hash, and an authentication tag.
    #[must_use]
    pub fn to_token(&self) -> String {
        let mut payload = Vec::with_capacity(CURSOR_PAYLOAD_BYTES);
        payload.extend_from_slice(&self.scope);
        payload.extend_from_slice(&self.target_version.get().to_be_bytes());
        payload.extend_from_slice(&self.record_key);
        payload.extend_from_slice(&self.tag);
        format!("{CURSOR_PREFIX}{}", hex::encode(payload))
    }

    pub(crate) fn parse_token(token: &str) -> Result<Self, VaultError> {
        let encoded = token
            .strip_prefix(CURSOR_PREFIX)
            .ok_or(VaultError::InvalidReencryptCursor)?;
        if encoded.len() != CURSOR_PAYLOAD_BYTES * 2
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(VaultError::InvalidReencryptCursor);
        }
        let decoded = hex::decode(encoded).map_err(|_| VaultError::InvalidReencryptCursor)?;
        let payload: [u8; CURSOR_PAYLOAD_BYTES] = decoded
            .try_into()
            .map_err(|_| VaultError::InvalidReencryptCursor)?;
        let scope = payload[..16]
            .try_into()
            .map_err(|_| VaultError::InvalidReencryptCursor)?;
        let target_version = u32::from_be_bytes(
            payload[16..20]
                .try_into()
                .map_err(|_| VaultError::InvalidReencryptCursor)?,
        );
        let target_version =
            KeyVersion::new(target_version).map_err(|_| VaultError::InvalidReencryptCursor)?;
        let record_key = payload[20..52]
            .try_into()
            .map_err(|_| VaultError::InvalidReencryptCursor)?;
        let tag = payload[52..]
            .try_into()
            .map_err(|_| VaultError::InvalidReencryptCursor)?;
        Ok(Self {
            record_key,
            scope,
            target_version,
            tag,
        })
    }
}

/// Progress made by one bounded re-encryption call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReencryptOutcome {
    /// Records examined in this batch.
    pub visited: usize,
    /// Records rewritten because their active envelope key differed.
    pub rewritten: usize,
    /// Resume position when more records remain.
    pub next_cursor: Option<ReencryptCursor>,
}
