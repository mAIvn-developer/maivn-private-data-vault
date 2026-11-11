//! The sealed byte formats: value-map envelopes, stream headers and frames,
//! their nonces and associated data, and the generation check that binds
//! them to trusted metadata.

use std::io::{ErrorKind, Read};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use zeroize::Zeroizing;

use crate::{ContentKind, KeyVersion, RecordIdentity, VaultError};

pub(super) const VALUE_MAP_MAGIC_V1: &[u8; 8] = b"PDVMAP01";
pub(super) const VALUE_MAP_MAGIC_V2: &[u8; 8] = b"PDVMAP02";
pub(super) const DOCUMENT_MAGIC_V1: &[u8; 8] = b"PDVDOC01";
pub(super) const DOCUMENT_MAGIC_V2: &[u8; 8] = b"PDVDOC02";
pub(super) const NONCE_PREFIX_BYTES: usize = 19;
pub(super) const KEY_VERSION_BYTES: usize = size_of::<u32>();
pub(super) const GENERATION_BYTES: usize = size_of::<u64>();
pub(super) const VALUE_MAP_NONCE_DOMAIN: u8 = 2;
pub(super) const DOCUMENT_CHUNK_BYTES: usize = 64 * 1024;
pub(super) const TAG_BYTES: usize = 16;
pub(super) const DATA_FRAME: u8 = 0;
pub(super) const FINAL_FRAME: u8 = 1;

pub(super) fn encrypt_document_frame(
    cipher: &XChaCha20Poly1305,
    prefix: &[u8; NONCE_PREFIX_BYTES],
    base_aad: &[u8],
    index: u32,
    kind: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    cipher
        .encrypt(
            XNonce::from_slice(&document_nonce(prefix, index, kind)),
            Payload {
                msg: plaintext,
                aad: &document_aad(base_aad, index, kind),
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)
}

pub(super) fn decrypt_document_frame(
    cipher: &XChaCha20Poly1305,
    prefix: &[u8; NONCE_PREFIX_BYTES],
    base_aad: &[u8],
    index: u32,
    kind: u8,
    ciphertext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    cipher
        .decrypt(
            XNonce::from_slice(&document_nonce(prefix, index, kind)),
            Payload {
                msg: ciphertext,
                aad: &document_aad(base_aad, index, kind),
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)
}

/// Authenticates every frame after a stream header, passing each data frame's
/// index and plaintext to `on_data`, and requires the final frame to close the
/// stream with nothing after it. Returns the final frame's index.
pub(super) fn open_frames(
    cipher: &XChaCha20Poly1305,
    prefix: &[u8; NONCE_PREFIX_BYTES],
    base_aad: &[u8],
    source: &mut Box<dyn Read + Send>,
    mut on_data: impl FnMut(u32, &[u8]) -> Result<(), VaultError>,
) -> Result<u32, VaultError> {
    let mut chunk_index = 0_u32;
    loop {
        let (kind, ciphertext) = read_frame(source)?;
        let plaintext = Zeroizing::new(decrypt_document_frame(
            cipher,
            prefix,
            base_aad,
            chunk_index,
            kind,
            &ciphertext,
        )?);
        match kind {
            DATA_FRAME => {
                if plaintext.is_empty() {
                    return Err(VaultError::InvalidFormat);
                }
                on_data(chunk_index, &plaintext)?;
                chunk_index = chunk_index
                    .checked_add(1)
                    .ok_or(VaultError::DocumentTooLarge)?;
            }
            FINAL_FRAME => {
                if !plaintext.is_empty() || has_trailing_bytes(source)? {
                    return Err(VaultError::InvalidFormat);
                }
                return Ok(chunk_index);
            }
            _ => return Err(VaultError::InvalidFormat),
        }
    }
}

pub(super) fn document_nonce(prefix: &[u8; NONCE_PREFIX_BYTES], index: u32, kind: u8) -> [u8; 24] {
    let mut nonce = [0; 24];
    nonce[..NONCE_PREFIX_BYTES].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_BYTES..23].copy_from_slice(&index.to_be_bytes());
    nonce[23] = kind;
    nonce
}

pub(super) fn document_aad(base: &[u8], index: u32, kind: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(base.len() + size_of::<u32>() + 1);
    aad.extend_from_slice(base);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(kind);
    aad
}

/// `PDVDOC02 | key version | generation | nonce prefix`.
pub(super) fn write_stream_header(
    destination: &mut Box<dyn crate::PendingDocument>,
    version: KeyVersion,
    generation: u64,
    prefix: &[u8; NONCE_PREFIX_BYTES],
) -> Result<(), VaultError> {
    write_backend(destination, DOCUMENT_MAGIC_V2)?;
    write_backend(destination, &version.get().to_be_bytes())?;
    write_backend(destination, &generation.to_be_bytes())?;
    write_backend(destination, prefix)
}

pub(super) fn write_frame(
    destination: &mut Box<dyn crate::PendingDocument>,
    kind: u8,
    ciphertext: &[u8],
) -> Result<(), VaultError> {
    let length = u32::try_from(ciphertext.len()).map_err(|_| VaultError::DocumentTooLarge)?;
    write_backend(destination, &[kind])?;
    write_backend(destination, &length.to_be_bytes())?;
    write_backend(destination, ciphertext)
}

pub(super) fn write_backend(
    destination: &mut Box<dyn crate::PendingDocument>,
    bytes: &[u8],
) -> Result<(), VaultError> {
    destination
        .write_all(bytes)
        .map_err(|error| VaultError::Storage(error.into()))
}

pub(super) fn read_frame(source: &mut Box<dyn Read + Send>) -> Result<(u8, Vec<u8>), VaultError> {
    let mut header = [0_u8; 5];
    read_backend_exact(source, &mut header)?;
    let length = usize::try_from(u32::from_be_bytes(
        header[1..]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    ))
    .map_err(|_| VaultError::InvalidFormat)?;
    validate_frame_length(header[0], length)?;
    let mut ciphertext = vec![0; length];
    read_backend_exact(source, &mut ciphertext)?;
    Ok((header[0], ciphertext))
}

pub(super) fn read_backend_exact(
    source: &mut Box<dyn Read + Send>,
    bytes: &mut [u8],
) -> Result<(), VaultError> {
    source.read_exact(bytes).map_err(|error| {
        if error.kind() == ErrorKind::UnexpectedEof {
            VaultError::InvalidFormat
        } else {
            VaultError::Storage(error.into())
        }
    })
}

pub(super) fn validate_frame_length(kind: u8, length: usize) -> Result<(), VaultError> {
    match kind {
        DATA_FRAME if (TAG_BYTES + 1..=DOCUMENT_CHUNK_BYTES + TAG_BYTES).contains(&length) => {
            Ok(())
        }
        FINAL_FRAME if length == TAG_BYTES => Ok(()),
        _ => Err(VaultError::InvalidFormat),
    }
}

pub(super) fn has_trailing_bytes(source: &mut Box<dyn Read + Send>) -> Result<bool, VaultError> {
    let mut byte = [0];
    loop {
        match source.read(&mut byte) {
            Ok(0) => return Ok(false),
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(VaultError::Storage(error.into())),
        }
    }
}

pub(super) fn value_map_nonce(prefix: &[u8; NONCE_PREFIX_BYTES]) -> [u8; 24] {
    let mut nonce = [0; 24];
    nonce[..NONCE_PREFIX_BYTES].copy_from_slice(prefix);
    nonce[23] = VALUE_MAP_NONCE_DOMAIN;
    nonce
}

pub(super) struct ParsedValueMap<'a> {
    pub(super) version: KeyVersion,
    pub(super) generation: u64,
    pub(super) prefix: &'a [u8; NONCE_PREFIX_BYTES],
    pub(super) ciphertext: &'a [u8],
    pub(super) legacy: bool,
}

pub(super) fn parse_value_map(sealed: &[u8]) -> Result<ParsedValueMap<'_>, VaultError> {
    let Some(magic) = sealed.get(..8) else {
        return Err(VaultError::InvalidFormat);
    };
    if magic == VALUE_MAP_MAGIC_V1 {
        if sealed.len() < 8 + NONCE_PREFIX_BYTES + TAG_BYTES {
            return Err(VaultError::InvalidFormat);
        }
        return Ok(ParsedValueMap {
            version: KeyVersion::new(1).expect("version one is non-zero"),
            generation: 0,
            prefix: sealed[8..27]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
            ciphertext: &sealed[27..],
            legacy: true,
        });
    }
    if magic != VALUE_MAP_MAGIC_V2
        || sealed.len() < 8 + KEY_VERSION_BYTES + GENERATION_BYTES + NONCE_PREFIX_BYTES + TAG_BYTES
    {
        return Err(VaultError::InvalidFormat);
    }
    let version = u32::from_be_bytes(
        sealed[8..12]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    );
    let version = KeyVersion::new(version).map_err(|_| VaultError::InvalidFormat)?;
    let generation = u64::from_be_bytes(
        sealed[12..20]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    );
    if generation == 0 {
        return Err(VaultError::InvalidFormat);
    }
    Ok(ParsedValueMap {
        version,
        generation,
        prefix: sealed[20..39]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
        ciphertext: &sealed[39..],
        legacy: false,
    })
}

pub(super) fn versioned_aad(
    record_key: &[u8; 32],
    kind: ContentKind,
    version: KeyVersion,
    generation: u64,
) -> Vec<u8> {
    let mut aad = RecordIdentity::versioned_associated_data_for(record_key, kind);
    aad.extend_from_slice(&version.get().to_be_bytes());
    aad.extend_from_slice(&generation.to_be_bytes());
    aad
}

/// A version-1 object parses with generation 0, so it can stand in only for a
/// record whose trusted generation is 0, which neither backend accepts: the
/// local backend refuses to commit it and the memory backend to hydrate it.
pub(super) fn verify_generation(trusted: Option<u64>, envelope: u64) -> Result<(), VaultError> {
    let Some(trusted) = trusted else {
        return Ok(());
    };
    if envelope != trusted {
        return Err(VaultError::RollbackDetected { trusted, envelope });
    }
    Ok(())
}

pub(super) struct StreamHeader {
    pub(super) version: KeyVersion,
    pub(super) generation: u64,
    pub(super) prefix: [u8; NONCE_PREFIX_BYTES],
    pub(super) legacy: bool,
}

pub(super) fn read_stream_header(
    source: &mut Box<dyn Read + Send>,
) -> Result<StreamHeader, VaultError> {
    let mut magic = [0_u8; 8];
    read_backend_exact(source, &mut magic)?;
    if &magic == DOCUMENT_MAGIC_V1 {
        let mut prefix = [0_u8; NONCE_PREFIX_BYTES];
        read_backend_exact(source, &mut prefix)?;
        return Ok(StreamHeader {
            version: KeyVersion::new(1).expect("version one is non-zero"),
            generation: 0,
            prefix,
            legacy: true,
        });
    }
    if &magic != DOCUMENT_MAGIC_V2 {
        return Err(VaultError::InvalidFormat);
    }
    let mut serialized = [0_u8; KEY_VERSION_BYTES + GENERATION_BYTES + NONCE_PREFIX_BYTES];
    read_backend_exact(source, &mut serialized)?;
    let version = u32::from_be_bytes(
        serialized[..4]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    );
    let version = KeyVersion::new(version).map_err(|_| VaultError::InvalidFormat)?;
    let generation = u64::from_be_bytes(
        serialized[4..12]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    );
    if generation == 0 {
        return Err(VaultError::InvalidFormat);
    }
    Ok(StreamHeader {
        version,
        generation,
        prefix: serialized[12..]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
        legacy: false,
    })
}
