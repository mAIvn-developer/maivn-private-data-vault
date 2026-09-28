use sha2::{Digest, Sha256};

use crate::VaultError;

const AAD_DOMAIN: &[u8] = b"maivn-private-data-vault:aad:v1";
const VERSIONED_AAD_DOMAIN: &[u8] = b"maivn-private-data-vault:aad:v2";
const RECORD_KEY_DOMAIN: &[u8] = b"maivn-private-data-vault:record-key:v1";
const VERSIONED_STORAGE_DOMAIN: &[u8] = b"maivn-private-data-vault:storage-key:v2";

/// The tenant and logical record bound into authenticated encryption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordIdentity {
    tenant: String,
    record: String,
}

impl RecordIdentity {
    /// Creates an identity. Both components are authenticated and therefore
    /// cannot be substituted without making decryption fail.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::InvalidIdentity`] when either component is empty.
    pub fn new(tenant: impl Into<String>, record: impl Into<String>) -> Result<Self, VaultError> {
        let tenant = tenant.into();
        let record = record.into();
        if tenant.is_empty() || record.is_empty() {
            return Err(VaultError::InvalidIdentity);
        }
        Ok(Self { tenant, record })
    }

    pub(crate) fn associated_data(&self, kind: ContentKind) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            AAD_DOMAIN.len() + self.tenant.len() + self.record.len() + 2 * size_of::<u64>() + 1,
        );
        aad.extend_from_slice(AAD_DOMAIN);
        aad.push(kind as u8);
        append_field(&mut aad, self.tenant.as_bytes());
        append_field(&mut aad, self.record.as_bytes());
        aad
    }

    pub(crate) fn storage_key(&self, kind: ContentKind) -> [u8; 32] {
        Sha256::digest(self.associated_data(kind)).into()
    }

    pub(crate) fn record_key(&self) -> [u8; 32] {
        let mut encoded = Vec::with_capacity(
            RECORD_KEY_DOMAIN.len() + self.tenant.len() + self.record.len() + 2 * size_of::<u64>(),
        );
        encoded.extend_from_slice(RECORD_KEY_DOMAIN);
        append_field(&mut encoded, self.tenant.as_bytes());
        append_field(&mut encoded, self.record.as_bytes());
        Sha256::digest(encoded).into()
    }

    pub(crate) fn versioned_storage_key(&self, kind: ContentKind) -> [u8; 32] {
        Self::versioned_storage_key_for(&self.record_key(), kind)
    }

    pub(crate) fn versioned_storage_key_for(record_key: &[u8; 32], kind: ContentKind) -> [u8; 32] {
        let mut encoded = Vec::with_capacity(VERSIONED_STORAGE_DOMAIN.len() + 33);
        encoded.extend_from_slice(VERSIONED_STORAGE_DOMAIN);
        encoded.extend_from_slice(record_key);
        encoded.push(kind as u8);
        Sha256::digest(encoded).into()
    }

    pub(crate) fn versioned_associated_data_for(
        record_key: &[u8; 32],
        kind: ContentKind,
    ) -> Vec<u8> {
        let mut aad = Vec::with_capacity(VERSIONED_AAD_DOMAIN.len() + 33);
        aad.extend_from_slice(VERSIONED_AAD_DOMAIN);
        aad.extend_from_slice(record_key);
        aad.push(kind as u8);
        aad
    }
}

/// Stable content discriminator bound into storage keys and authenticated data.
///
/// Existing numeric values are part of the sealed-object format and must never
/// be renumbered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ContentKind {
    /// Placeholder-to-private-value mapping.
    ValueMap = 1,
    /// Redacted document made safe for model and navigation use.
    Document = 2,
    /// Unredacted source document retained only in the private vault.
    Original = 3,
}

fn append_field(output: &mut Vec<u8>, field: &[u8]) {
    let length = u64::try_from(field.len()).expect("usize always fits in u64 on supported targets");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(field);
}
