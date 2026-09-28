use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::VaultError;

const KEY_BYTES: usize = 32;
const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_LANES: u32 = 1;

pub(crate) struct KeyMaterial([u8; KEY_BYTES]);

impl KeyMaterial {
    pub(crate) fn derive(secret: &[u8], salt: &[u8; 16]) -> Result<Self, VaultError> {
        let parameters = Params::new(
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_LANES,
            Some(KEY_BYTES),
        )
        .map_err(|_| VaultError::KeyDerivation)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters);
        let mut key = Self([0_u8; KEY_BYTES]);
        argon2
            .hash_password_into(secret, salt, &mut key.0)
            .map_err(|_| VaultError::KeyDerivation)?;
        Ok(key)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }

    fn erase(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        // This overwrites this owned key buffer before Rust frees it. It cannot
        // erase copies made outside this type, CPU registers, allocator copies,
        // swap, core dumps, or memory captured before `drop` runs.
        self.erase();
    }
}

#[cfg(test)]
mod tests {
    use super::KeyMaterial;

    #[test]
    fn key_erase_overwrites_the_owned_buffer() {
        let mut key = KeyMaterial([0xA5; 32]);

        key.erase();

        assert_eq!(key.0, [0; 32]);
        // Safe Rust cannot inspect an allocation after drop. This exercises the
        // exact method called by `Drop`, proving the owned bytes are writable
        // and overwritten while acknowledging that post-drop inspection would
        // itself be undefined behavior.
    }
}
