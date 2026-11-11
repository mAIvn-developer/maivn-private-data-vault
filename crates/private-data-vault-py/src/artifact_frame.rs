use std::borrow::Cow;

use private_data_vault_core::artifact_frame;
use pyo3::{
    exceptions::{PyOverflowError, PyTypeError},
    prelude::*,
    types::{PyByteArray, PyBytes, PyTuple},
};

fn byte_values<'a>(value: &'a Bound<'_, PyAny>) -> PyResult<Cow<'a, [u8]>> {
    if let Ok(bytes) = value.cast::<PyBytes>() {
        return Ok(Cow::Borrowed(bytes.as_bytes()));
    }
    // The Python packer extended a bytearray, including for mutable buffers.
    let buffer = PyByteArray::new(value.py(), &[]);
    buffer.call_method1("extend", (value,))?;
    Ok(Cow::Owned(buffer.to_vec()))
}

fn frame_length(value: &Bound<'_, PyAny>) -> PyResult<u32> {
    u32::try_from(value.len()?).map_err(|_| PyOverflowError::new_err("int too big to convert"))
}

#[pyfunction]
pub(crate) fn pack_artifact_frame<'py>(
    py: Python<'py>,
    counter: &Bound<'py, PyAny>,
    parts: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    let counter = byte_values(counter)?;
    let mut frame = artifact_frame::start(&counter, frame_length(parts)?);
    for part in parts.try_iter()? {
        let part = part?;
        artifact_frame::append_part(&mut frame, frame_length(&part)?, &byte_values(&part)?);
    }
    Ok(PyBytes::new(py, &frame))
}

#[pyfunction]
pub(crate) fn unpack_artifact_frame<'py>(
    py: Python<'py>,
    blob: &Bound<'py, PyAny>,
) -> PyResult<Option<(u64, Bound<'py, PyTuple>)>> {
    if !blob.is_exact_instance_of::<PyBytes>()
        && !blob.is_exact_instance_of::<PyByteArray>()
        && (!blob
            .call_method1("startswith", (PyBytes::new(py, artifact_frame::MAGIC),))?
            .is_truthy()?
            || blob.len()? < artifact_frame::HEADER_LEN)
    {
        return Ok(None);
    }
    let (bytes, mutable) = if let Ok(bytes) = blob.cast::<PyBytes>() {
        (Cow::Borrowed(bytes.as_bytes()), false)
    } else if let Ok(bytes) = blob.cast::<PyByteArray>() {
        (Cow::Owned(bytes.to_vec()), true)
    } else {
        return Err(PyTypeError::new_err("frame must be bytes or bytearray"));
    };
    let Some((counter, parts)) = artifact_frame::unpack(&bytes) else {
        return Ok(None);
    };
    let parts = PyTuple::new(
        py,
        parts.into_iter().map(|part| {
            if mutable {
                PyByteArray::new(py, part).into_any()
            } else {
                PyBytes::new(py, part).into_any()
            }
        }),
    )?;
    Ok(Some((counter, parts)))
}
