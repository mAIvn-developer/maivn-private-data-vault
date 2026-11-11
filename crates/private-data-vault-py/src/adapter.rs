//! The bytes-oriented adapter over the vault core, shared by the Python classes
//! and the Rust contract tests. Nothing here depends on Python.

use std::{
    collections::BTreeMap,
    io::Cursor,
    path::Path,
    time::{Duration, SystemTime},
};

use private_data_vault_core::{
    KeyVersion, Keyring, LocalBackend, RecordIdentity, StorageError, Vault,
    VaultError as CoreVaultError,
};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};
use zeroize::{Zeroize, Zeroizing};

/// Error categories exposed by the narrow language adapter.
#[derive(Debug)]
pub enum AdapterError {
    /// No sealed object exists for the requested record and content kind.
    RecordNotFound,
    /// The sealed object could not be authenticated.
    AuthenticationFailed,
    /// The sealed object is older than the trusted record generation.
    RollbackDetected,
    /// The storage backend could not complete an operation.
    StorageUnavailable(String),
    /// The caller or sealed value map violated the vault contract.
    Vault(String),
}

impl From<StorageError> for AdapterError {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::NotFound => Self::RecordNotFound,
            other => Self::StorageUnavailable(other.to_string()),
        }
    }
}

impl From<CoreVaultError> for AdapterError {
    fn from(error: CoreVaultError) -> Self {
        match error {
            CoreVaultError::AuthenticationFailed => Self::AuthenticationFailed,
            CoreVaultError::RollbackDetected { .. } => Self::RollbackDetected,
            CoreVaultError::Storage(StorageError::NotFound) => Self::RecordNotFound,
            CoreVaultError::Storage(storage) => Self::StorageUnavailable(storage.to_string()),
            other => Self::Vault(other.to_string()),
        }
    }
}

/// Bytes-oriented adapter shared by the Python class and Rust contract tests.
pub struct VaultAdapter {
    vault: Vault<LocalBackend>,
}

/// Progress from one bounded re-encryption call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterReencryptOutcome {
    /// Records examined in this batch.
    pub visited: usize,
    /// Records rewritten with the active key.
    pub rewritten: usize,
    /// Authenticated resume token when additional records remain.
    pub next_cursor: Option<String>,
}

pub(crate) struct SensitiveValueMap(pub(crate) BTreeMap<String, String>);

impl<'de> Deserialize<'de> for SensitiveValueMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SensitiveValueMapVisitor;

        impl<'de> Visitor<'de> for SensitiveValueMapVisitor {
            type Value = SensitiveValueMap;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object with unique string keys and string values")
            }

            fn visit_map<M>(self, mut entries: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut values = SensitiveValueMap(BTreeMap::new());
                while let Some(key) = entries.next_key::<String>()? {
                    if values.0.contains_key(&key) {
                        let mut duplicate = entries.next_value::<String>()?;
                        duplicate.zeroize();
                        return Err(de::Error::custom("duplicate value-map key"));
                    }
                    let value = entries.next_value::<String>()?;
                    values.0.insert(key, value);
                }
                Ok(values)
            }
        }

        deserializer.deserialize_map(SensitiveValueMapVisitor)
    }
}

impl Drop for SensitiveValueMap {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

pub(crate) fn parse_value_map(payload: &[u8]) -> Result<SensitiveValueMap, AdapterError> {
    serde_json::from_slice(payload).map_err(|error| AdapterError::Vault(error.to_string()))
}

impl VaultAdapter {
    /// Opens a local filesystem vault.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the local backend cannot open and a vault
    /// error when the secret cannot initialize the sealed store.
    pub fn open(path: impl AsRef<Path>, secret: &[u8]) -> Result<Self, AdapterError> {
        Self::open_keyring(path, 1, secret, &[])
    }

    /// Opens a local vault with an active write key and optional historical
    /// decrypt-only keys.
    ///
    /// # Errors
    ///
    /// Returns a typed vault error for invalid, duplicate, or empty key
    /// configuration and a storage error when the backend cannot open.
    pub fn open_keyring(
        path: impl AsRef<Path>,
        active_version: u32,
        active_secret: &[u8],
        decrypt_only: &[(u32, &[u8])],
    ) -> Result<Self, AdapterError> {
        let backend = LocalBackend::open(path).map_err(AdapterError::from)?;
        let keyring = build_keyring(active_version, active_secret, decrypt_only)?;
        let vault = Vault::open_keyring(backend, keyring).map_err(AdapterError::from)?;
        Ok(Self { vault })
    }

    /// Parses, seals, and stores a UTF-8 JSON value map.
    ///
    /// # Errors
    ///
    /// Returns a vault error for invalid JSON or identity input, and preserves
    /// authentication and storage error categories from the sealed store.
    pub fn store_value_map(
        &self,
        tenant: &str,
        record: &str,
        payload: &[u8],
    ) -> Result<(), AdapterError> {
        let values = parse_value_map(payload)?;
        let identity = identity(tenant, record)?;
        self.vault
            .store_value_map(&identity, &values.0)
            .map_err(AdapterError::from)
    }

    /// Atomically merges a UTF-8 JSON value map into one standalone record.
    ///
    /// # Errors
    ///
    /// Returns a typed identity, authentication, storage, or vault error.
    pub fn merge_value_map(
        &self,
        tenant: &str,
        record: &str,
        payload: &[u8],
    ) -> Result<(), AdapterError> {
        let values = parse_value_map(payload)?;
        let identity = identity(tenant, record)?;
        self.vault
            .merge_value_map(&identity, &values.0)
            .map_err(AdapterError::from)
    }

    /// Loads a value map as UTF-8 JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed missing, authentication, storage, or vault error.
    pub fn load_value_map(
        &self,
        tenant: &str,
        record: &str,
    ) -> Result<Zeroizing<Vec<u8>>, AdapterError> {
        let identity = identity(tenant, record)?;
        let values = SensitiveValueMap(
            self.vault
                .load_value_map(&identity)
                .map_err(AdapterError::from)?,
        );
        let mut payload = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *payload, &values.0)
            .map_err(|error| AdapterError::Vault(error.to_string()))?;
        Ok(payload)
    }

    /// Seals and stores arbitrary document bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed authentication, storage, or vault error.
    pub fn store_document(
        &self,
        tenant: &str,
        record: &str,
        payload: &[u8],
    ) -> Result<(), AdapterError> {
        let identity = identity(tenant, record)?;
        self.vault
            .store_document(&identity, &mut Cursor::new(payload))
            .map_err(AdapterError::from)
    }

    /// Loads arbitrary document bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed missing, authentication, storage, or vault error.
    pub fn load_document(
        &self,
        tenant: &str,
        record: &str,
    ) -> Result<Zeroizing<Vec<u8>>, AdapterError> {
        let identity = identity(tenant, record)?;
        let mut payload = Zeroizing::new(Vec::new());
        self.vault
            .load_document(&identity, &mut *payload)
            .map_err(AdapterError::from)?;
        Ok(payload)
    }

    /// Seals and stores arbitrary original bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed authentication, storage, or vault error.
    pub fn store_original(
        &self,
        tenant: &str,
        record: &str,
        payload: &[u8],
    ) -> Result<(), AdapterError> {
        let identity = identity(tenant, record)?;
        self.vault
            .store_original(&identity, &mut Cursor::new(payload))
            .map_err(AdapterError::from)
    }

    /// Loads arbitrary original bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed missing, authentication, storage, or vault error.
    pub fn load_original(
        &self,
        tenant: &str,
        record: &str,
    ) -> Result<Zeroizing<Vec<u8>>, AdapterError> {
        let identity = identity(tenant, record)?;
        let mut payload = Zeroizing::new(Vec::new());
        self.vault
            .load_original(&identity, &mut *payload)
            .map_err(AdapterError::from)?;
        Ok(payload)
    }

    /// Atomically seals an original, redacted document, and value map as one
    /// record generation.
    ///
    /// # Errors
    ///
    /// Returns a typed JSON, identity, authentication, generation, or storage
    /// error without publishing a partial record generation.
    pub fn store_record(
        &self,
        tenant: &str,
        record: &str,
        original: &[u8],
        document: &[u8],
        value_map: &[u8],
    ) -> Result<(), AdapterError> {
        let values = parse_value_map(value_map)?;
        let identity = identity(tenant, record)?;
        self.vault
            .store_record(
                &identity,
                &mut Cursor::new(original),
                &mut Cursor::new(document),
                &values.0,
            )
            .map_err(AdapterError::from)
    }

    /// Atomically replaces one existing complete record generation.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::RecordNotFound`] when the record is absent,
    /// without staging any bytes. Other typed adapter failures are preserved.
    pub fn replace_record(
        &self,
        tenant: &str,
        record: &str,
        original: &[u8],
        document: &[u8],
        value_map: &[u8],
    ) -> Result<(), AdapterError> {
        let values = parse_value_map(value_map)?;
        let identity = identity(tenant, record)?;
        self.vault
            .replace_record(
                &identity,
                &mut Cursor::new(original),
                &mut Cursor::new(document),
                &values.0,
            )
            .map_err(AdapterError::from)
    }

    /// Re-encrypts one bounded batch and returns an authenticated resume token.
    ///
    /// # Errors
    ///
    /// Returns a typed vault error for invalid target, cursor, or batch limit,
    /// corrupt ciphertext, unavailable historical keys, or storage failure.
    pub fn reencrypt_batch(
        &self,
        target_version: u32,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<AdapterReencryptOutcome, AdapterError> {
        let target_version = KeyVersion::new(target_version).map_err(AdapterError::from)?;
        let cursor = cursor
            .map(|token| {
                self.vault
                    .reencrypt_cursor_from_token(target_version, token)
            })
            .transpose()
            .map_err(AdapterError::from)?;
        let outcome = self
            .vault
            .reencrypt_batch(target_version, cursor.as_ref(), limit)
            .map_err(AdapterError::from)?;
        Ok(AdapterReencryptOutcome {
            visited: outcome.visited,
            rewritten: outcome.rewritten,
            next_cursor: outcome.next_cursor.map(|value| value.to_token()),
        })
    }

    /// Permanently removes every sealed object for a record.
    ///
    /// # Errors
    ///
    /// Returns a storage error when either sealed object cannot be removed,
    /// or a vault error when the identity is invalid.
    pub fn purge(&self, tenant: &str, record: &str) -> Result<(), AdapterError> {
        let identity = identity(tenant, record)?;
        self.vault.purge(&identity).map_err(AdapterError::from)
    }

    /// Removes every sealed object older than `max_age_seconds`.
    ///
    /// Takes an age rather than an instant so the caller does not have to
    /// agree with this process about what time it is; the cutoff is computed
    /// here against the same clock the filesystem stamped the objects with.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the store cannot be enumerated or swept.
    pub fn purge_expired(&self, max_age_seconds: u64) -> Result<usize, AdapterError> {
        let cutoff = SystemTime::now()
            .checked_sub(Duration::from_secs(max_age_seconds))
            .ok_or_else(|| {
                AdapterError::Vault("retention age is further back than the epoch".to_owned())
            })?;
        self.vault.purge_expired(cutoff).map_err(AdapterError::from)
    }
}

pub(crate) fn identity(tenant: &str, record: &str) -> Result<RecordIdentity, AdapterError> {
    RecordIdentity::new(tenant, record).map_err(AdapterError::from)
}

/// Builds a keyring from an active key plus parsed historical keys.
pub(crate) fn build_keyring<S: AsRef<[u8]>>(
    active_version: u32,
    active_secret: &[u8],
    historical_keys: &[(u32, S)],
) -> Result<Keyring, AdapterError> {
    let active_version = KeyVersion::new(active_version).map_err(AdapterError::from)?;
    let mut keyring = Keyring::new(active_version, active_secret).map_err(AdapterError::from)?;
    for (version, secret) in historical_keys {
        keyring = keyring
            .with_decrypt_only(
                KeyVersion::new(*version).map_err(AdapterError::from)?,
                secret.as_ref(),
            )
            .map_err(AdapterError::from)?;
    }
    Ok(keyring)
}
