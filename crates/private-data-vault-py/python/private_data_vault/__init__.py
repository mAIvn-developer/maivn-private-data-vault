"""Sealed storage for private documents and the values redacted out of them.

Everything here is implemented in Rust. This module only lifts the compiled
symbols into the package namespace so ``from private_data_vault import
LocalVault`` works, and so the type stubs beside it describe something that
actually exists at that path.
"""

from private_data_vault.private_data_vault import (
    ArtifactChunkCipher,
    ArtifactIntakeCommitment,
    ArtifactSha256,
    AuthenticationFailed,
    ExchangeVault,
    LocalVault,
    RecordNotFound,
    RollbackDetected,
    SoftwareKmsCipher,
    StorageUnavailable,
    VaultError,
    artifact_sha256_hex,
    pack_artifact_frame,
    unpack_artifact_frame,
)

__all__ = [
    "ArtifactChunkCipher",
    "ArtifactIntakeCommitment",
    "ArtifactSha256",
    "AuthenticationFailed",
    "ExchangeVault",
    "LocalVault",
    "RecordNotFound",
    "RollbackDetected",
    "SoftwareKmsCipher",
    "StorageUnavailable",
    "VaultError",
    "artifact_sha256_hex",
    "pack_artifact_frame",
    "unpack_artifact_frame",
]
