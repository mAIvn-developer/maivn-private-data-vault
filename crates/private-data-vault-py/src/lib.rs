//! Python bindings for the local private-data vault.

mod adapter;
mod artifact_chunk;
mod artifact_frame;
mod artifact_integrity;
mod default_vault;
mod software_kms;

pub use adapter::{AdapterError, AdapterReencryptOutcome, VaultAdapter};

use std::{io::Cursor, path::PathBuf};

use private_data_vault_core::{
    ExchangeRecord, MemoryBackend, RecordIdentity, Vault, VaultError as CoreVaultError,
};
use pyo3::{
    create_exception,
    exceptions::{PyException, PyTypeError},
    prelude::*,
    types::{PyBool, PyBytes, PyDict, PyInt, PyModule, PyType},
};
use zeroize::Zeroizing;

use crate::adapter::{build_keyring, identity, parse_value_map};

/// Integer arguments accept a Python `int` only: a `bool` or an object that
/// merely implements `__index__` is a `TypeError`.
macro_rules! strict_int {
    ($name:ident, $int:ty) => {
        #[derive(Clone, Copy)]
        struct $name($int);

        impl FromPyObject<'_, '_> for $name {
            type Error = PyErr;

            fn extract(value: Borrowed<'_, '_, PyAny>) -> PyResult<Self> {
                if value.is_instance_of::<PyBool>() || value.cast::<PyInt>().is_err() {
                    return Err(PyTypeError::new_err(
                        "expected an integer, not bool or __index__",
                    ));
                }
                value.extract::<$int>().map(Self)
            }
        }
    };
}

strict_int!(StrictU32, u32);
strict_int!(StrictU64, u64);
strict_int!(StrictUsize, usize);

create_exception!(private_data_vault, VaultError, PyException);
create_exception!(private_data_vault, RecordNotFound, VaultError);
create_exception!(private_data_vault, AuthenticationFailed, VaultError);
create_exception!(private_data_vault, RollbackDetected, VaultError);
create_exception!(private_data_vault, StorageUnavailable, VaultError);

fn core_error(error: CoreVaultError) -> PyErr {
    python_error(error.into())
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

// Local filesystem vault exposed to Python.
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

    /// Check for established or ambiguous storage without using credentials.
    #[staticmethod]
    #[pyo3(
        signature = (scope=None, *, path=None),
        text_signature = "(scope=None, *, path=None)"
    )]
    fn default_requires_open(
        py: Python<'_>,
        scope: Option<&str>,
        path: Option<&str>,
    ) -> PyResult<bool> {
        let scope = scope.map(str::to_owned);
        let path = path.map(PathBuf::from);
        py.detach(move || default_vault::default_requires_open(scope.as_deref(), path.as_deref()))
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

/// One sealed record as returned to Python: `(generation, original, document, value_map)`.
type SealedRecordTuple<'py> = (
    u64,
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
);

// In-process exchange vault for the managed tier.
//
// Holds one record's sealed material for one operation: the managed adapter
// hydrates it with previously persisted sealed objects, drives the ordinary
// vault operations, and extracts the sealed results for external storage.
// Sealing and opening happen in the vault core; Python only ever holds
// ciphertext.
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
        let vault = Vault::open_keyring(MemoryBackend::new(salt), keyring).map_err(core_error)?;
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
            .map_err(core_error)?;
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
            .map_err(core_error)?;
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
        self.vault
            .backend()
            .import_record(
                &identity,
                &ExchangeRecord {
                    generation,
                    original: original.to_vec(),
                    document: document.to_vec(),
                    value_map: value_map.to_vec(),
                },
            )
            .map_err(core_error)
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
            .map_err(core_error)?;
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
            .map_err(core_error)?;
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
        let values = self.vault.load_value_map(&identity).map_err(core_error)?;
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
    module.add_class::<artifact_chunk::ArtifactChunkCipher>()?;
    module.add_class::<artifact_integrity::ArtifactSha256>()?;
    module.add_class::<artifact_integrity::ArtifactIntakeCommitment>()?;
    module.add_function(wrap_pyfunction!(
        artifact_integrity::artifact_sha256_hex,
        module
    )?)?;
    module.add_class::<software_kms::SoftwareKmsCipher>()?;
    module.add_function(wrap_pyfunction!(
        artifact_frame::pack_artifact_frame,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        artifact_frame::unpack_artifact_frame,
        module
    )?)?;
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
