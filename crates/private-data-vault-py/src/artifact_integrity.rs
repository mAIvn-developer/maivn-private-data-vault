use private_data_vault_core::artifact_integrity::{
    ArtifactIntakeCommitment as IntakeCommitment, ArtifactSha256 as Sha256, sha256_hex,
};
use pyo3::{
    exceptions::{PyBufferError, PyException, PyTypeError, PyValueError},
    prelude::*,
    types::{PyByteArray, PyBytes, PyString},
};
use zeroize::Zeroizing;

const INVALID: &str = "vault_integrity_input";

fn fixed_buffer_error(py: Python<'_>, error: PyErr) -> PyErr {
    if !error.is_instance_of::<PyException>(py) {
        error
    } else if error.is_instance_of::<PyBufferError>(py) {
        PyBufferError::new_err(INVALID)
    } else if error.is_instance_of::<PyTypeError>(py) {
        PyTypeError::new_err(INVALID)
    } else {
        PyValueError::new_err(INVALID)
    }
}

fn with_input<T>(input: &Bound<'_, PyAny>, use_bytes: impl FnOnce(&[u8]) -> T) -> PyResult<T> {
    if let Ok(bytes) = input.cast_exact::<PyBytes>() {
        return Ok(use_bytes(bytes.as_bytes()));
    }
    if let Ok(bytes) = input.cast_exact::<PyByteArray>() {
        return Ok(use_bytes(&Zeroizing::new(bytes.to_vec())));
    }
    // The ABI3 floor precedes stable Py_buffer. struct's iterator owns a
    // PyBUF_SIMPLE view, as hashlib/HMAC require, including for bytes subclasses
    // and exporters whose item size exceeds one byte.
    let py = input.py();
    let unpacked = py
        .import("struct")?
        .call_method1("iter_unpack", ("B", input))
        .map_err(|error| fixed_buffer_error(py, error))?;
    let capacity = unpacked.call_method0("__length_hint__")?.extract()?;
    let mut snapshot = Zeroizing::new(Vec::with_capacity(capacity));
    for item in unpacked.try_iter()? {
        let (byte,): (u8,) = item?.extract()?;
        snapshot.push(byte);
    }
    Ok(use_bytes(&snapshot))
}

#[pyfunction]
pub(crate) fn artifact_sha256_hex(input: &Bound<'_, PyAny>) -> PyResult<String> {
    with_input(input, |bytes| input.py().detach(|| sha256_hex(bytes)))
}

#[pyclass(module = "private_data_vault")]
pub(crate) struct ArtifactSha256(Sha256);

#[pymethods]
impl ArtifactSha256 {
    #[new]
    fn new() -> Self {
        Self(Sha256::default())
    }

    fn update(&mut self, input: &Bound<'_, PyAny>) -> PyResult<()> {
        with_input(input, |bytes| input.py().detach(|| self.0.update(bytes)))
    }

    fn hexdigest(&self) -> String {
        self.0.hexdigest()
    }
}

#[pyclass(module = "private_data_vault")]
pub(crate) struct ArtifactIntakeCommitment(Option<IntakeCommitment>);

#[pymethods]
impl ArtifactIntakeCommitment {
    #[new]
    fn new(key: &Bound<'_, PyAny>, prefix: &Bound<'_, PyAny>) -> PyResult<Self> {
        let state = with_input(key, |key| {
            with_input(prefix, |prefix| IntakeCommitment::new(key, prefix))
        })??;
        state
            .map(|state| Self(Some(state)))
            .ok_or_else(|| PyValueError::new_err(INVALID))
    }

    fn update(&mut self, input: &Bound<'_, PyAny>) -> PyResult<()> {
        let state = self
            .0
            .as_mut()
            .ok_or_else(|| PyValueError::new_err(INVALID))?;
        with_input(input, |bytes| input.py().detach(|| state.update(bytes)))
    }

    fn verify(&mut self, expected: &Bound<'_, PyString>) -> PyResult<bool> {
        let state = self
            .0
            .take()
            .ok_or_else(|| PyValueError::new_err(INVALID))?;
        let expected = expected
            .to_str()
            .map_err(|_| PyValueError::new_err(INVALID))?;
        Ok(state.verify(expected))
    }

    fn discard(&mut self) {
        self.0 = None;
    }
}
