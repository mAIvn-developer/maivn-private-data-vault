use private_data_vault_core::software_kms::{
    KEY_BYTES, NONCE_BYTES, SoftwareKeyUnwrapError, SoftwareKmsCipher as CoreCipher, TAG_BYTES,
};
use pyo3::{
    exceptions::{PyBufferError, PyMemoryError, PyOverflowError, PyTypeError, PyValueError},
    prelude::*,
    types::{PyBytes, PyMemoryView, PyString, PyType},
};
use zeroize::Zeroizing;

fn root_length_error() -> PyErr {
    PyValueError::new_err("AESGCM key must be 128, 192, or 256 bits.")
}

fn buffer_error(root: &Bound<'_, PyAny>) -> PyResult<PyErr> {
    let hint = if root.is_instance_of::<PyString>() {
        "\nDid you mean to pass a bytestring instead?"
    } else {
        ""
    };
    Ok(PyTypeError::new_err(format!(
        "Cannot convert \"{}\" instance to a buffer.{hint}",
        root.get_type().str()?
    )))
}

fn is_unsigned_byte_format(format: &str) -> bool {
    let format = match format.as_bytes() {
        // Keep the pinned PyCA buffer reader's accepted unsigned byte formats.
        [b'@' | b'=' | b'>', element] | [element] => *element,
        [b'!', element] if cfg!(target_endian = "big") => *element,
        _ => return false,
    };
    matches!(format, b'B' | b'c')
}

fn nonce(bytes: &[u8]) -> PyResult<&[u8; NONCE_BYTES]> {
    bytes
        .try_into()
        .map_err(|_| PyValueError::new_err("Software KMS nonce must be 12 bytes"))
}

fn check_aad_length(aad: &[u8]) -> PyResult<()> {
    if aad.len() > i32::MAX as usize {
        return Err(PyOverflowError::new_err(
            "Data or associated data too long. Max 2**31 - 1 bytes",
        ));
    }
    Ok(())
}

#[pyclass(frozen, module = "private_data_vault")]
pub(crate) struct SoftwareKmsCipher(CoreCipher);

#[pymethods]
impl SoftwareKmsCipher {
    #[new]
    fn new(root: &Bound<'_, PyAny>) -> PyResult<Self> {
        if let Ok(bytes) = root.cast::<PyBytes>() {
            let key = bytes
                .as_bytes()
                .try_into()
                .map_err(|_| root_length_error())?;
            return Ok(Self(CoreCipher::new(key)));
        }
        let Ok(view) = PyMemoryView::from(root) else {
            return Err(buffer_error(root)?);
        };
        if !is_unsigned_byte_format(view.getattr("format")?.extract::<&str>()?) {
            return Err(buffer_error(root)?);
        }
        if !view.getattr("c_contiguous")?.is_truthy()? {
            return Err(PyBufferError::new_err("Buffer is not contiguous."));
        }
        // ABI3 Python 3.10 cannot use PyO3's stable PyBuffer API. Copy the
        // uncommon inputs directly into zeroizing memory, without Python bytes.
        let flat = view.call_method1("cast", ("B",))?;
        if flat.len()? != KEY_BYTES {
            return Err(root_length_error());
        }
        let mut key = Zeroizing::new([0; KEY_BYTES]);
        for (slot, byte) in key.iter_mut().zip(flat.try_iter()?) {
            *slot = byte?.extract()?;
        }
        Ok(Self(CoreCipher::new(&key)))
    }

    fn wrap_key<'py>(
        &self,
        py: Python<'py>,
        nonce_bytes: &[u8],
        key: &[u8],
        aad: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let nonce = nonce(nonce_bytes)?;
        let key = key
            .try_into()
            .map_err(|_| PyValueError::new_err("Software KMS tenant key must be 32 bytes"))?;
        check_aad_length(aad)?;
        let wrapped = self
            .0
            .wrap_key(nonce, key, aad)
            .ok_or_else(|| PyValueError::new_err("Software KMS key wrapping failed"))?;
        Ok(PyBytes::new(py, &wrapped))
    }

    fn unwrap_key<'py>(
        &self,
        py: Python<'py>,
        nonce_bytes: &[u8],
        wrapped: &[u8],
        aad: &[u8],
        invalid_tag: &Bound<'py, PyType>,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let nonce = nonce(nonce_bytes)?;
        if wrapped.len() >= TAG_BYTES {
            check_aad_length(aad)?;
        }
        // The adapter supplies its existing authentication exception type to
        // preserve its hidden exception chain without a dependency on PyCA here.
        match py.detach(|| self.0.unwrap_key(nonce, wrapped, aad)) {
            Ok(plaintext) => Ok(Some(PyBytes::new(py, &plaintext))),
            Err(SoftwareKeyUnwrapError::Authentication) => {
                Err(PyErr::from_type(invalid_tag.clone(), ()))
            }
            Err(SoftwareKeyUnwrapError::KeySize) => Ok(None),
            Err(SoftwareKeyUnwrapError::BufferAllocation) => Err(PyMemoryError::new_err(())),
        }
    }
}
