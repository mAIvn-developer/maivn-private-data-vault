//! AES-256-GCM for the existing staging software root. The service supplies
//! the nonce and authenticated context and owns key authorization and storage.

use aes_gcm::{
    Aes256Gcm, Key, Nonce, Tag,
    aead::{AeadInOut, KeyInit, inout::InOutBuf},
};
use zeroize::Zeroizing;

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const TAG_BYTES: usize = 16;
const WRAPPED_BYTES: usize = KEY_BYTES + TAG_BYTES;

pub struct SoftwareKmsCipher(Aes256Gcm);

#[derive(Debug, PartialEq, Eq)]
pub enum SoftwareKeyUnwrapError {
    Authentication,
    KeySize,
    BufferAllocation,
}

impl SoftwareKmsCipher {
    #[must_use]
    pub fn new(root: &[u8; KEY_BYTES]) -> Self {
        Self(Aes256Gcm::new(Key::<Aes256Gcm>::cast_from_core(root)))
    }

    #[must_use]
    pub fn wrap_key(
        &self,
        nonce: &[u8; NONCE_BYTES],
        key: &[u8; KEY_BYTES],
        aad: &[u8],
    ) -> Option<[u8; WRAPPED_BYTES]> {
        let mut wrapped = [0; WRAPPED_BYTES];
        let (ciphertext, suffix) = wrapped.split_at_mut(KEY_BYTES);
        let buffer = InOutBuf::new(key, ciphertext).ok()?;
        let tag = self
            .0
            .encrypt_inout_detached(Nonce::cast_from_core(nonce), aad, buffer)
            .ok()?;
        suffix.copy_from_slice(&tag);
        Some(wrapped)
    }

    /// Authenticate the ciphertext and return only an exact tenant key.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails, the authenticated plaintext
    /// has the wrong length, or scratch memory cannot be allocated.
    pub fn unwrap_key(
        &self,
        nonce: &[u8; NONCE_BYTES],
        wrapped: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SoftwareKeyUnwrapError> {
        use SoftwareKeyUnwrapError::{Authentication, BufferAllocation, KeySize};

        let ciphertext_len = wrapped.len().checked_sub(TAG_BYTES).ok_or(Authentication)?;
        let (ciphertext, raw_tag) = wrapped.split_at(ciphertext_len);
        let tag = <&Tag>::try_from(raw_tag).map_err(|_| Authentication)?;
        let mut plaintext = Zeroizing::new(Vec::new());
        plaintext
            .try_reserve_exact(ciphertext_len)
            .map_err(|_| BufferAllocation)?;
        plaintext.resize(ciphertext_len, 0);
        let buffer = InOutBuf::new(ciphertext, &mut plaintext).map_err(|_| Authentication)?;
        self.0
            .decrypt_inout_detached(Nonce::cast_from_core(nonce), aad, buffer, tag)
            .map_err(|_| Authentication)?;
        if plaintext.len() != KEY_BYTES {
            return Err(KeySize);
        }
        Ok(plaintext)
    }
}
