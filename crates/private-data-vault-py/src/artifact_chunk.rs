use private_data_vault_core::artifact_chunk::ArtifactChunkCipher as CoreCipher;
use pyo3::{
    exceptions::{PyBufferError, PyTypeError, PyValueError},
    prelude::*,
    types::{PyByteArray, PyBytes, PyMemoryView, PyString},
};
use zeroize::Zeroizing;

fn invalid() -> PyErr {
    PyValueError::new_err("vault_chunk_invalid")
}

fn with_input<T>(input: &Bound<'_, PyAny>, use_bytes: impl FnOnce(&[u8]) -> T) -> PyResult<T> {
    if let Ok(bytes) = input.cast::<PyBytes>() {
        return Ok(use_bytes(bytes.as_bytes()));
    }
    if let Ok(bytes) = input.cast::<PyByteArray>() {
        return Ok(use_bytes(&Zeroizing::new(bytes.to_vec())));
    }
    if input.is_instance_of::<PyString>() {
        return Err(PyTypeError::new_err(
            "Strings must be encoded before hashing",
        ));
    }
    let view = PyMemoryView::from(input)
        .map_err(|_| PyTypeError::new_err("object supporting the buffer API required"))?;
    if !view.getattr("c_contiguous")?.is_truthy()? {
        return Err(PyBufferError::new_err(
            "memoryview: underlying buffer is not C-contiguous",
        ));
    }
    if view.getattr("format")?.extract::<&str>()? != "B" {
        return Err(PyTypeError::new_err(format!(
            "Cannot convert \"{}\" instance to a buffer.",
            input.get_type().str()?
        )));
    }
    // The ABI3 floor predates the stable Rust buffer API. Copy uncommon buffer
    // inputs directly into zeroizing Rust memory, without creating a Python
    // bytes object containing another copy of the plaintext.
    let flat = view.call_method1("cast", ("B",))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(flat.len()?));
    for byte in flat.try_iter()? {
        bytes.push(byte?.extract()?);
    }
    Ok(use_bytes(&bytes))
}

#[pyclass(frozen, module = "private_data_vault")]
pub(crate) struct ArtifactChunkCipher(CoreCipher);

#[pymethods]
impl ArtifactChunkCipher {
    #[new]
    fn new(salt: &Bound<'_, PyBytes>, secret: &Bound<'_, PyAny>) -> PyResult<Self> {
        with_input(secret, |secret| CoreCipher::new(salt.as_bytes(), secret))?
            .map(Self)
            .ok_or_else(invalid)
    }

    fn seal<'py>(
        &self,
        py: Python<'py>,
        aad: &Bound<'_, PyBytes>,
        plaintext: &Bound<'_, PyAny>,
    ) -> PyResult<(Bound<'py, PyBytes>, String)> {
        let (ciphertext, digest) = with_input(plaintext, |plaintext| {
            self.0.seal(aad.as_bytes(), plaintext)
        })?
        .ok_or_else(invalid)?;
        Ok((PyBytes::new(py, &ciphertext), digest))
    }

    fn open<'py>(
        &self,
        py: Python<'py>,
        aad: &Bound<'_, PyBytes>,
        ciphertext: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let plaintext = with_input(ciphertext, |ciphertext| {
            self.0.open(aad.as_bytes(), ciphertext)
        })?
        .ok_or_else(invalid)?;
        Ok(PyBytes::new(py, &plaintext))
    }
}
