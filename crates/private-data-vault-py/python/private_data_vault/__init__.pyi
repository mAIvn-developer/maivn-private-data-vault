"""Type stubs for the compiled PrivateDataVault bindings.

Shipped in the wheel so consumers can type-check against this boundary. Without
them every call into the vault degrades to Unknown, and a type checker stops
being able to say anything about the one seam it should be watching hardest.

Kept deliberately narrow, matching the Rust surface exactly: bytes in, bytes
out, and a distinct exception per failure mode. If this file and the Rust ever
disagree, the Rust is right and this is a bug.
"""

class VaultError(Exception):
    """Base class for every vault failure."""

class RecordNotFound(VaultError):
    """No entry exists under this tenant and record.

    An answer, not a fault. The entry was never stored, or it has been purged.
    Callers translate this to "nothing here"; they must NOT translate any other
    error the same way, because an unreachable vault reported as "nothing here"
    turns an outage into silent data loss.
    """

class AuthenticationFailed(VaultError):
    """The sealed material did not authenticate.

    Wrong key, tampered ciphertext, or material sealed for a different tenant or
    record. Deliberately one exception rather than three: distinguishing them for
    the caller would tell an attacker which part of their guess was right.
    """

class RollbackDetected(VaultError):
    """Ciphertext is older than the trusted current record generation."""

class StorageUnavailable(VaultError):
    """The vault could not be read or written."""

class LocalVault:
    """A sealed vault rooted at a directory on this machine."""

    def __init__(
        self,
        path: str,
        secret: bytes,
        *,
        key_version: int = 1,
        decrypt_only: dict[int, bytes] | None = None,
    ) -> None:
        """Open or create a vault with an active and optional historical keys."""

    @classmethod
    def open_default(
        cls,
        scope: str,
        *,
        path: str | None = None,
        secret: bytes | None = None,
    ) -> LocalVault:
        """Open automatic local storage or an explicitly keyed durable path."""

    @staticmethod
    def default_exists(scope: str | None = None, *, path: str | None = None) -> bool:
        """Check persisted vault metadata without reading or creating a credential."""

    def store_value_map(self, tenant: str, record: str, payload: bytes) -> None:
        """Seal a placeholder-to-value map, as UTF-8 JSON bytes."""

    def load_value_map(self, tenant: str, record: str) -> bytes:
        """Return the sealed map, raising RecordNotFound when absent."""

    def merge_value_map(self, tenant: str, record: str, payload: bytes) -> None:
        """Atomically merge UTF-8 JSON pairs under the backend's shared record lock."""

    def store_document(self, tenant: str, record: str, payload: bytes) -> None:
        """Seal a document body."""

    def load_document(self, tenant: str, record: str) -> bytes:
        """Return the sealed document, raising RecordNotFound when absent."""

    def store_original(self, tenant: str, record: str, payload: bytes) -> None:
        """Seal an unredacted original document."""

    def load_original(self, tenant: str, record: str) -> bytes:
        """Return the sealed unredacted original, raising RecordNotFound when absent."""

    def store_record(
        self,
        tenant: str,
        record: str,
        original: bytes,
        document: bytes,
        value_map: bytes,
    ) -> None:
        """Atomically seal all three private-record objects as one generation."""

    def replace_record(
        self,
        tenant: str,
        record: str,
        original: bytes,
        document: bytes,
        value_map: bytes,
    ) -> None:
        """Atomically replace an existing generation, raising RecordNotFound when absent."""

    def reencrypt_batch(
        self,
        target_version: int,
        cursor: str | None,
        limit: int,
    ) -> tuple[int, int, str | None]:
        """Re-encrypt one bounded batch and return visited, rewritten, and cursor."""

    def purge(self, tenant: str, record: str) -> None:
        """Remove the value map, redacted document, and original permanently.

        Idempotent: purging what is not there succeeds, so a retried delete is
        not punished for the first attempt having worked.
        """

    def purge_expired(self, max_age_seconds: int) -> int:
        """Remove every sealed object older than the given age, returning the count.

        Retention rather than deletion. ``purge`` says one record is gone; this
        says nothing outlives its policy. Without it, material nobody ever
        deletes stays until the disk does, which makes any retention statement
        untrue.

        Sweeps the whole vault, not one tenant: storage keys are hashes of the
        record identity and cannot be reversed, so age is the only signal
        available and no caller can enumerate what is held. Nothing is
        decrypted; no key is needed.
        """

class ExchangeVault:
    """An in-process exchange vault for the managed tier.

    Holds one record's sealed material for one operation. The managed adapter
    hydrates it with sealed objects fetched from external storage, drives the
    ordinary vault operations, and extracts the sealed results to persist.
    Sealing and opening happen in the Rust core; Python only ever holds
    ciphertext.
    """

    def __init__(
        self,
        salt: bytes,
        secret: bytes,
        *,
        key_version: int = 1,
        decrypt_only: dict[int, bytes] | None = None,
    ) -> None:
        """Open over a caller-supplied 16-byte derivation salt.

        The salt must be stable for a tenant across processes: derivation
        binds the key to it, so a changed salt makes every previously sealed
        record unopenable.
        """

    def seal_record(
        self,
        tenant: str,
        record: str,
        original: bytes,
        document: bytes,
        value_map: bytes,
    ) -> tuple[int, bytes, bytes, bytes]:
        """Seal a new record; return (generation, original, document, value_map) sealed."""

    def replace_record(
        self,
        tenant: str,
        record: str,
        original: bytes,
        document: bytes,
        value_map: bytes,
    ) -> tuple[int, bytes, bytes, bytes]:
        """Replace the hydrated record; return the next generation's sealed bytes."""

    def import_record(
        self,
        tenant: str,
        record: str,
        generation: int,
        original: bytes,
        document: bytes,
        value_map: bytes,
    ) -> None:
        """Hydrate one record's sealed state exactly as previously exported."""

    def load_document(self, tenant: str, record: str) -> bytes:
        """Open the hydrated redacted document."""

    def load_original(self, tenant: str, record: str) -> bytes:
        """Open the hydrated as-uploaded original."""

    def load_value_map(self, tenant: str, record: str) -> bytes:
        """Open the hydrated value map as canonical UTF-8 JSON bytes."""
