//! Standard integrity primitives for bytes already authorized by the Vault.

use hmac_chunk::{Hmac, KeyInit, Mac, digest::Output};
use sha2_chunk::{Digest, Sha256};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Incremental SHA-256 with the zeroizing SHA-2 feature enabled.
#[derive(Default)]
pub struct ArtifactSha256(Sha256);

impl ArtifactSha256 {
    /// Add the next already admitted bytes.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// Read a lower-case digest without changing the stream position.
    #[must_use]
    pub fn hexdigest(&self) -> String {
        encode(self.0.clone().finalize())
    }
}

/// Read the lower-case digest of a complete byte sequence.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    encode(Sha256::digest(bytes))
}

fn encode(mut digest: Output<Sha256>) -> String {
    let encoded = hex::encode(digest.as_slice());
    digest.as_mut_slice().zeroize();
    encoded
}

/// A keyed verifier initialized from the caller's canonical intake framing.
pub struct ArtifactIntakeCommitment(HmacSha256);

impl ArtifactIntakeCommitment {
    /// Start HMAC-SHA256 without keeping a separate copy of the key or prefix.
    #[must_use]
    pub fn new(key: &[u8], prefix: &[u8]) -> Option<Self> {
        let mut mac = HmacSha256::new_from_slice(key).ok()?;
        mac.update(prefix);
        Some(Self(mac))
    }

    /// Add the next already admitted bytes.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// Consume the state and compare one full canonical tag in constant time.
    #[must_use]
    pub fn verify(self, expected: &str) -> bool {
        let mut tag = Output::<HmacSha256>::default();
        let valid = expected.len() == 2 * tag.len()
            && expected
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            && hex::decode_to_slice(expected, tag.as_mut_slice()).is_ok()
            && self.0.verify(&tag).is_ok();
        tag.as_mut_slice().zeroize();
        valid
    }
}
