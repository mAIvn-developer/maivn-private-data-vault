//! The deployed MVC1 seal for immutable artifact chunks.

use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag, aead::AeadInPlace};
use hkdf::Hkdf;
use hmac_chunk::{Hmac, KeyInit as HmacKeyInit, Mac};
use sha2_chunk::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const DOMAIN: &[u8] = b"maivn-vault-chunk-v1";
const MAGIC: &[u8; 4] = b"MVC1";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = MAGIC.len() + NONCE_LEN;
const MAX_PLAINTEXT_LEN: usize = 65_536;
type HmacSha256 = Hmac<Sha256>;

/// Generation-scoped keys for deterministic chunk sealing.
pub struct ArtifactChunkCipher(Zeroizing<[u8; 2 * KEY_LEN]>);

impl ArtifactChunkCipher {
    /// Derive separate encryption and nonce keys from the existing generation key.
    #[must_use]
    pub fn new(salt: &[u8], secret: &[u8]) -> Option<Self> {
        let (mut prk, kdf) = Hkdf::<Sha256>::extract(Some(salt), secret);
        prk.as_mut_slice().zeroize();
        let mut keys = Zeroizing::new([0; 2 * KEY_LEN]);
        kdf.expand(DOMAIN, &mut *keys).ok()?;
        Some(Self(keys))
    }

    /// Seal bytes admitted by the caller, preserving the MVC1 layout and digest.
    #[must_use]
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Option<(Vec<u8>, String)> {
        let mut nonce_mac = self.nonce_mac(aad, plaintext)?.finalize().into_bytes();
        let nonce = Nonce::from(*nonce_mac.first_chunk::<NONCE_LEN>()?);
        nonce_mac.as_mut_slice().zeroize();
        let capacity = plaintext.len().checked_add(HEADER_LEN + TAG_LEN)?;
        let mut frame = Zeroizing::new(Vec::with_capacity(capacity));
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(plaintext);
        let tag = self
            .aead()?
            .encrypt_in_place_detached(&nonce, aad, &mut frame[HEADER_LEN..])
            .ok()?;
        frame.extend_from_slice(&tag);
        let digest = hex::encode(Sha256::digest(&*frame));
        Some((std::mem::take(&mut *frame), digest))
    }

    /// Open a complete chunk only if its AAD, tag, derived nonce and size agree.
    #[must_use]
    pub fn open(&self, aad: &[u8], frame: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let (nonce, body) = frame
            .strip_prefix(MAGIC)?
            .split_first_chunk::<NONCE_LEN>()?;
        let (encrypted, tag) = body.split_last_chunk::<TAG_LEN>()?;
        let mut plaintext = Zeroizing::new(encrypted.to_vec());
        self.aead()?
            .decrypt_in_place_detached(&Nonce::from(*nonce), aad, &mut plaintext, &Tag::from(*tag))
            .ok()?;
        self.nonce_mac(aad, &plaintext)?
            .verify_truncated_left(nonce)
            .ok()?;
        (1..=MAX_PLAINTEXT_LEN)
            .contains(&plaintext.len())
            .then_some(plaintext)
    }

    fn aead(&self) -> Option<ChaCha20Poly1305> {
        ChaCha20Poly1305::new_from_slice(&self.0[..KEY_LEN]).ok()
    }

    fn nonce_mac(&self, aad: &[u8], plaintext: &[u8]) -> Option<HmacSha256> {
        let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(&self.0[KEY_LEN..]).ok()?;
        let mut digest = Sha256::digest(plaintext);
        mac.update(aad);
        mac.update(&digest);
        digest.as_mut_slice().zeroize();
        Some(mac)
    }
}
