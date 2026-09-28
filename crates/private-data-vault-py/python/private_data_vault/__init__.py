"""Sealed storage for private documents and the values redacted out of them.

Everything here is implemented in Rust. This module only lifts the compiled
symbols into the package namespace so ``from private_data_vault import
LocalVault`` works, and so the type stubs beside it describe something that
actually exists at that path.
"""

from private_data_vault.private_data_vault import (
    AuthenticationFailed,
    ExchangeVault,
    LocalVault,
    RecordNotFound,
    RollbackDetected,
    StorageUnavailable,
    VaultError,
)

__all__ = [
    "AuthenticationFailed",
    "ExchangeVault",
    "LocalVault",
    "RecordNotFound",
    "RollbackDetected",
    "StorageUnavailable",
    "VaultError",
]
