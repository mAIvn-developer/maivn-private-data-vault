//! Python bindings for the local private-data vault.

mod default_vault;

use std::{
    collections::BTreeMap,
    io::Cursor,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use private_data_vault_core::{
    ExchangeRecord, KeyVersion, Keyring, LocalBackend, MemoryBackend, RecordIdentity, StorageError,
    Vault, VaultError as CoreVaultError,
};
use pyo3::{
    create_exception,
    exceptions::{PyException, PyTypeError},
    prelude::*,
    types::{PyBool, PyBytes, PyDict, PyInt, PyModule, PyType},
};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy)]
struct StrictU32(u32);

impl FromPyObject<'_, '_> for StrictU32 {
    type Error = PyErr;

    fn extract(value: Borrowed<'_, '_, PyAny>) -> PyResult<Self> {
        if value.is_instance_of::<PyBool>() || value.cast::<PyInt>().is_err() {
            return Err(PyTypeError::new_err(
                "expected an integer, not bool or __index__",
            ));
        }
        value.extract::<u32>().map(Self)
    }
}

#[derive(Clone, Copy)]
struct StrictU64(u64);

impl FromPyObject<'_, '_> for StrictU64 {
    type Error = PyErr;

    fn extract(value: Borrowed<'_, '_, PyAny>) -> PyResult<Self> {
        if value.is_instance_of::<PyBool>() || value.cast::<PyInt>().is_err() {
            return Err(PyTypeError::new_err(
                "expected an integer, not bool or __index__",
            ));
        }
        value.extract::<u64>().map(Self)
    }
}

#[derive(Clone, Copy)]
struct StrictUsize(usize);

impl FromPyObject<'_, '_> for StrictUsize {
    type Error = PyErr;

    fn extract(value: Borrowed<'_, '_, PyAny>) -> PyResult<Self> {
        if value.is_instance_of::<PyBool>() || value.cast::<PyInt>().is_err() {
            return Err(PyTypeError::new_err(
                "expected an integer, not bool or __index__",
            ));
        }
        value.extract::<usize>().map(Self)
    }
}

create_exception!(private_data_vault, VaultError, PyException);
create_exception!(private_data_vault, RecordNotFound, VaultError);
create_exception!(private_data_vault, AuthenticationFailed, VaultError);
create_exception!(private_data_vault, RollbackDetected, VaultError);
create_exception!(private_data_vault, StorageUnavailable, VaultError);

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

struct SensitiveValueMap(BTreeMap<String, String>);

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

fn parse_value_map(payload: &[u8]) -> Result<SensitiveValueMap, AdapterError> {
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
        let active_version = KeyVersion::new(active_version).map_err(AdapterError::from)?;
        let mut keyring =
            Keyring::new(active_version, active_secret).map_err(AdapterError::from)?;
        for (version, secret) in decrypt_only {
            keyring = keyring
                .with_decrypt_only(
                    KeyVersion::new(*version).map_err(AdapterError::from)?,
                    secret,
                )
                .map_err(AdapterError::from)?;
        }
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

fn identity(tenant: &str, record: &str) -> Result<RecordIdentity, AdapterError> {
    RecordIdentity::new(tenant, record).map_err(AdapterError::from)
}

fn python_error(error: AdapterError) -> PyErr {
    match error {
        AdapterError::RecordNotFound => RecordNotFound::new_err("record was not found"),
        AdapterError::AuthenticationFailed => {
            AuthenticationFailed::new_err("ciphertext authentication failed")
        }
        AdapterError::RollbackDetected => {
            RollbackDetected::new_err("ciphertext is older than the trusted record generation")
        }
        AdapterError::StorageUnavailable(message) => StorageUnavailable::new_err(message),
        AdapterError::Vault(message) => VaultError::new_err(message),
    }
}

/// Local filesystem vault exposed to Python.
/// Parses the `decrypt_only` keyword into (version, secret) pairs.
fn collect_historical_keys(
    decrypt_only: Option<&Bound<'_, PyDict>>,
) -> PyResult<Vec<(u32, Zeroizing<Vec<u8>>)>> {
    let mut historical_keys = Vec::new();
    if let Some(decrypt_only) = decrypt_only {
        for (version, secret) in decrypt_only {
            if version.is_instance_of::<PyBool>() {
                return Err(PyTypeError::new_err(
                    "decrypt_only keys must be integer key versions, not bool",
                ));
            }
            version.cast::<PyInt>().map_err(|_| {
                PyTypeError::new_err("decrypt_only keys must be integer key versions")
            })?;
            let version = version.extract::<u32>().map_err(|_| {
                PyTypeError::new_err(
                    "decrypt_only keys must be unsigned 32-bit integer key versions",
                )
            })?;
            let secret = secret
                .cast_exact::<PyBytes>()
                .map_err(|_| PyTypeError::new_err("decrypt_only values must be bytes"))?;
            historical_keys.push((version, Zeroizing::new(secret.as_bytes().to_vec())));
        }
    }
    Ok(historical_keys)
}

/// Builds a keyring from an active key plus parsed historical keys.
fn build_keyring(
    active_version: u32,
    active_secret: &[u8],
    historical_keys: &[(u32, Zeroizing<Vec<u8>>)],
) -> Result<Keyring, AdapterError> {
    let active_version = KeyVersion::new(active_version).map_err(AdapterError::from)?;
    let mut keyring = Keyring::new(active_version, active_secret).map_err(AdapterError::from)?;
    for (version, secret) in historical_keys {
        keyring = keyring
            .with_decrypt_only(
                KeyVersion::new(*version).map_err(AdapterError::from)?,
                secret,
            )
            .map_err(AdapterError::from)?;
    }
    Ok(keyring)
}

#[pyclass(module = "private_data_vault")]
pub struct LocalVault {
    adapter: VaultAdapter,
}

#[pymethods]
impl LocalVault {
    #[new]
    #[pyo3(
        signature = (path, secret, *, key_version=StrictU32(1), decrypt_only=None),
        text_signature = "(path, secret, *, key_version=1, decrypt_only=None)"
    )]
    fn new(
        path: &str,
        secret: &Bound<'_, PyBytes>,
        key_version: StrictU32,
        decrypt_only: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let historical_keys = collect_historical_keys(decrypt_only)?;
        let decrypt_only_refs = historical_keys
            .iter()
            .map(|(version, secret)| (*version, secret.as_slice()))
            .collect::<Vec<_>>();
        let adapter =
            VaultAdapter::open_keyring(path, key_version.0, secret.as_bytes(), &decrypt_only_refs)
                .map_err(python_error)?;
        Ok(Self { adapter })
    }

    #[classmethod]
    #[pyo3(
        signature = (scope, *, path=None, secret=None),
        text_signature = "(scope, *, path=None, secret=None)"
    )]
    fn open_default(
        _class: &Bound<'_, PyType>,
        py: Python<'_>,
        scope: &str,
        path: Option<&str>,
        secret: Option<&Bound<'_, PyBytes>>,
    ) -> PyResult<Self> {
        let scope = scope.to_owned();
        let path = path.map(PathBuf::from);
        let secret = secret.map(|value| Zeroizing::new(value.as_bytes().to_vec()));
        let adapter = py
            .detach(move || {
                default_vault::open_default(
                    &scope,
                    path.as_deref(),
                    secret.as_ref().map(|value| value.as_slice()),
                )
            })
            .map_err(python_error)?;
        Ok(Self { adapter })
    }

    #[staticmethod]
    #[pyo3(
        signature = (scope=None, *, path=None),
        text_signature = "(scope=None, *, path=None)"
    )]
    fn default_exists(py: Python<'_>, scope: Option<&str>, path: Option<&str>) -> PyResult<bool> {
        let scope = scope.map(str::to_owned);
        let path = path.map(PathBuf::from);
        py.detach(move || default_vault::default_exists(scope.as_deref(), path.as_deref()))
            .map_err(python_error)
    }

    fn store_value_map(&self, tenant: &str, record: &str, payload: &[u8]) -> PyResult<()> {
        self.adapter
            .store_value_map(tenant, record, payload)
            .map_err(python_error)
    }

    fn merge_value_map(
        &self,
        py: Python<'_>,
        tenant: &str,
        record: &str,
        payload: &[u8],
    ) -> PyResult<()> {
        py.detach(|| self.adapter.merge_value_map(tenant, record, payload))
            .map_err(python_error)
    }

    fn load_value_map<'py>(
        &self,
        py: Python<'py>,
        tenant: &str,
        record: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let payload = self
            .adapter
            .load_value_map(tenant, record)
            .map_err(python_error)?;
        Ok(PyBytes::new(py, &payload))
    }

    fn store_document(&self, tenant: &str, record: &str, payload: &[u8]) -> PyResult<()> {
        self.adapter
            .store_document(tenant, record, payload)
            .map_err(python_error)
    }

    fn load_document<'py>(
        &self,
        py: Python<'py>,
        tenant: &str,
        record: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let payload = self
            .adapter
            .load_document(tenant, record)
            .map_err(python_error)?;
        Ok(PyBytes::new(py, &payload))
    }

    fn store_original(&self, tenant: &str, record: &str, payload: &[u8]) -> PyResult<()> {
        self.adapter
            .store_original(tenant, record, payload)
            .map_err(python_error)
    }

    fn load_original<'py>(
        &self,
        py: Python<'py>,
        tenant: &str,
        record: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let payload = self
            .adapter
            .load_original(tenant, record)
            .map_err(python_error)?;
        Ok(PyBytes::new(py, &payload))
    }

    fn store_record(
        &self,
        tenant: &str,
        record: &str,
        original: &[u8],
        document: &[u8],
        value_map: &[u8],
    ) -> PyResult<()> {
        self.adapter
            .store_record(tenant, record, original, document, value_map)
            .map_err(python_error)
    }

    fn replace_record(
        &self,
        tenant: &str,
        record: &str,
        original: &[u8],
        document: &[u8],
        value_map: &[u8],
    ) -> PyResult<()> {
        self.adapter
            .replace_record(tenant, record, original, document, value_map)
            .map_err(python_error)
    }

    fn reencrypt_batch(
        &self,
        target_version: StrictU32,
        cursor: Option<&str>,
        limit: StrictUsize,
    ) -> PyResult<(usize, usize, Option<String>)> {
        let outcome = self
            .adapter
            .reencrypt_batch(target_version.0, cursor, limit.0)
            .map_err(python_error)?;
        Ok((outcome.visited, outcome.rewritten, outcome.next_cursor))
    }

    fn purge(&self, tenant: &str, record: &str) -> PyResult<()> {
        self.adapter.purge(tenant, record).map_err(python_error)
    }

    fn purge_expired(&self, max_age_seconds: StrictU64) -> PyResult<usize> {
        self.adapter
            .purge_expired(max_age_seconds.0)
            .map_err(python_error)
    }
}

/// In-process exchange vault for the managed tier.
///
/// Holds one record's sealed material for one operation: the managed adapter
/// hydrates it with previously persisted sealed objects, drives the ordinary
/// vault operations, and extracts the sealed results for external storage.
/// Sealing and opening happen in the vault core; Python only ever holds
/// ciphertext.
/// One sealed record as returned to Python: `(generation, original, document, value_map)`.
type SealedRecordTuple<'py> = (
    u64,
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
);

#[pyclass(module = "private_data_vault")]
pub struct ExchangeVault {
    vault: Vault<MemoryBackend>,
}

#[pymethods]
impl ExchangeVault {
    #[new]
    #[pyo3(
        signature = (salt, secret, *, key_version=StrictU32(1), decrypt_only=None),
        text_signature = "(salt, secret, *, key_version=1, decrypt_only=None)"
    )]
    fn new(
        salt: &[u8],
        secret: &Bound<'_, PyBytes>,
        key_version: StrictU32,
        decrypt_only: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let salt: [u8; 16] = salt
            .try_into()
            .map_err(|_| VaultError::new_err("the key-derivation salt must be exactly 16 bytes"))?;
        let historical_keys = collect_historical_keys(decrypt_only)?;
        let keyring = build_keyring(key_version.0, secret.as_bytes(), &historical_keys)
            .map_err(python_error)?;
        let vault = Vault::open_keyring(MemoryBackend::new(salt), keyring)
            .map_err(|error| python_error(AdapterError::from(error)))?;
        Ok(Self { vault })
    }

    /// Seals a new record and returns `(generation, original, document, value_map)`
    /// as sealed bytes for external persistence.
    fn seal_record<'py>(
        &self,
        py: Python<'py>,
        tenant: &str,
        record: &str,
        original: &[u8],
        document: &[u8],
        value_map: &[u8],
    ) -> PyResult<SealedRecordTuple<'py>> {
        let values = parse_value_map(value_map).map_err(python_error)?;
        let identity = identity(tenant, record).map_err(python_error)?;
        self.vault
            .store_record(
                &identity,
                &mut Cursor::new(original),
                &mut Cursor::new(document),
                &values.0,
            )
            .map_err(|error| python_error(AdapterError::from(error)))?;
        self.export(py, &identity)
            .ok_or_else(|| VaultError::new_err("the sealed record did not export completely"))
    }

    /// Replaces the hydrated record and returns the next generation's sealed bytes.
    fn replace_record<'py>(
        &self,
        py: Python<'py>,
        tenant: &str,
        record: &str,
        original: &[u8],
        document: &[u8],
        value_map: &[u8],
    ) -> PyResult<SealedRecordTuple<'py>> {
        let values = parse_value_map(value_map).map_err(python_error)?;
        let identity = identity(tenant, record).map_err(python_error)?;
        self.vault
            .replace_record(
                &identity,
                &mut Cursor::new(original),
                &mut Cursor::new(document),
                &values.0,
            )
            .map_err(|error| python_error(AdapterError::from(error)))?;
        self.export(py, &identity)
            .ok_or_else(|| VaultError::new_err("the replaced record did not export completely"))
    }

    /// Hydrates one record's sealed state exactly as previously exported.
    fn import_record(
        &self,
        tenant: &str,
        record: &str,
        generation: u64,
        original: &[u8],
        document: &[u8],
        value_map: &[u8],
    ) -> PyResult<()> {
        let identity = identity(tenant, record).map_err(python_error)?;
        self.vault.backend().import_record(
            &identity,
            &ExchangeRecord {
                generation,
                original: original.to_vec(),
                document: document.to_vec(),
                value_map: value_map.to_vec(),
            },
        );
        Ok(())
    }

    /// Opens the hydrated redacted document.
    fn load_document<'py>(
        &self,
        py: Python<'py>,
        tenant: &str,
        record: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let identity = identity(tenant, record).map_err(python_error)?;
        let mut payload = Vec::new();
        self.vault
            .load_document(&identity, &mut payload)
            .map_err(|error| python_error(AdapterError::from(error)))?;
        Ok(PyBytes::new(py, &payload))
    }

    /// Opens the hydrated as-uploaded original.
    fn load_original<'py>(
        &self,
        py: Python<'py>,
        tenant: &str,
        record: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let identity = identity(tenant, record).map_err(python_error)?;
        let mut payload = Vec::new();
        self.vault
            .load_original(&identity, &mut payload)
            .map_err(|error| python_error(AdapterError::from(error)))?;
        Ok(PyBytes::new(py, &payload))
    }

    /// Opens the hydrated value map as canonical UTF-8 JSON bytes.
    fn load_value_map<'py>(
        &self,
        py: Python<'py>,
        tenant: &str,
        record: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let identity = identity(tenant, record).map_err(python_error)?;
        let values = self
            .vault
            .load_value_map(&identity)
            .map_err(|error| python_error(AdapterError::from(error)))?;
        let mut payload = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *payload, &values)
            .map_err(|error| python_error(AdapterError::Vault(error.to_string())))?;
        Ok(PyBytes::new(py, &payload))
    }
}

impl ExchangeVault {
    fn export<'py>(
        &self,
        py: Python<'py>,
        identity: &RecordIdentity,
    ) -> Option<SealedRecordTuple<'py>> {
        self.vault.backend().export_record(identity).map(|record| {
            (
                record.generation,
                PyBytes::new(py, &record.original),
                PyBytes::new(py, &record.document),
                PyBytes::new(py, &record.value_map),
            )
        })
    }
}

// Preserve the existing GIL requirement; free-threaded support is not qualified.
#[pymodule(gil_used = true)]
fn private_data_vault(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<LocalVault>()?;
    module.add_class::<ExchangeVault>()?;
    module.add("VaultError", py.get_type::<VaultError>())?;
    module.add("RecordNotFound", py.get_type::<RecordNotFound>())?;
    module.add(
        "AuthenticationFailed",
        py.get_type::<AuthenticationFailed>(),
    )?;
    module.add("RollbackDetected", py.get_type::<RollbackDetected>())?;
    module.add("StorageUnavailable", py.get_type::<StorageUnavailable>())?;
    Ok(())
}
