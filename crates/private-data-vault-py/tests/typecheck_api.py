from private_data_vault import (
    LocalVault,
    RollbackDetected,
    VaultError,
)


def exercise_public_contract(vault: LocalVault) -> None:
    vault.merge_value_map("tenant", "standalone-record", b'{"code":"12"}')
    original: bytes = vault.load_original("tenant", "record")
    vault.store_original("tenant", "record", original)
    vault.store_record("tenant", "record", original, b"redacted", b"{}")
    vault.replace_record("tenant", "record", original, b"redacted", b"{}")
    progress: tuple[int, int, str | None] = vault.reencrypt_batch(2, None, 100)
    cursor = progress[2]
    if cursor is not None:
        _: tuple[int, int, str | None] = vault.reencrypt_batch(2, cursor, 100)


def construct_versioned_vault() -> LocalVault:
    return LocalVault(
        "vault-path",
        b"active secret",
        key_version=2,
        decrypt_only={1: b"historical secret"},
    )


def construct_default_vault() -> LocalVault:
    if LocalVault.default_exists("account-scope", path="vault-path"):
        return LocalVault.open_default(
            "account-scope",
            path="vault-path",
            secret=b"0123456789abcdef0123456789abcdef",
        )
    return LocalVault.open_default("account-scope")


def exception_contract(error: VaultError) -> bool:
    return isinstance(error, RollbackDetected)
