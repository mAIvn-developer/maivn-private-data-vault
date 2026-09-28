use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::{VaultError, key::KeyMaterial};

/// Non-zero identifier serialized into every version-2 sealed object.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyVersion(u32);

impl KeyVersion {
    /// Creates a key version. Zero is reserved for malformed/unversioned data.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::InvalidKeyVersion`] when `value` is zero.
    pub const fn new(value: u32) -> Result<Self, VaultError> {
        if value == 0 {
            return Err(VaultError::InvalidKeyVersion);
        }
        Ok(Self(value))
    }

    /// Returns the stable integer written to the envelope header.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Caller-owned key configuration with one write key and optional read-only keys.
pub struct Keyring {
    active: KeyVersion,
    secrets: BTreeMap<KeyVersion, Zeroizing<Vec<u8>>>,
}

impl Keyring {
    /// Creates a keyring whose active key is used for every new write.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::InvalidSecret`] when `secret` is empty.
    pub fn new(active: KeyVersion, secret: &[u8]) -> Result<Self, VaultError> {
        if secret.is_empty() {
            return Err(VaultError::InvalidSecret);
        }
        Ok(Self {
            active,
            secrets: BTreeMap::from([(active, Zeroizing::new(secret.to_vec()))]),
        })
    }

    /// Adds a historical key that may decrypt but is never selected for writes.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::InvalidSecret`] for an empty secret or
    /// [`VaultError::DuplicateKeyVersion`] when the version is already present.
    pub fn with_decrypt_only(
        mut self,
        version: KeyVersion,
        secret: &[u8],
    ) -> Result<Self, VaultError> {
        if secret.is_empty() {
            return Err(VaultError::InvalidSecret);
        }
        if self.secrets.contains_key(&version) {
            return Err(VaultError::DuplicateKeyVersion(version.get()));
        }
        self.secrets
            .insert(version, Zeroizing::new(secret.to_vec()));
        Ok(self)
    }

    pub(crate) fn derive(self, salt: &[u8; 16]) -> Result<DerivedKeyring, VaultError> {
        let mut keys = BTreeMap::new();
        for (version, secret) in self.secrets {
            keys.insert(version, KeyMaterial::derive(secret.as_slice(), salt)?);
        }
        Ok(DerivedKeyring {
            active: self.active,
            keys,
        })
    }
}

pub(crate) struct DerivedKeyring {
    active: KeyVersion,
    keys: BTreeMap<KeyVersion, KeyMaterial>,
}

impl DerivedKeyring {
    pub(crate) const fn active_version(&self) -> KeyVersion {
        self.active
    }

    pub(crate) fn key(&self, version: KeyVersion) -> Result<&KeyMaterial, VaultError> {
        self.keys
            .get(&version)
            .ok_or(VaultError::UnknownKeyVersion(version.get()))
    }
}
