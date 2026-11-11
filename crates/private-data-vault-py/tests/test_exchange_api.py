"""The managed exchange flow, exercised exactly as the managed adapter will.

Seal in one ExchangeVault, carry only the sealed bytes (as the database and
bucket will), hydrate a completely fresh ExchangeVault, and open. Nothing
process-local may be needed to open what was sealed elsewhere.
"""

import importlib
import json
import unittest

SALT = b"tenant-salt-0001"
SECRET = b"managed-exchange-test-secret"
TENANT = "acct_a:sdk"
RECORD = "doc0aa11bb22"
VALUE_MAP = json.dumps({"<PRIVATE_1>": "secret-value"}).encode()


class ExchangeVaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = importlib.import_module("private_data_vault")

    def _seal(self) -> tuple[int, bytes, bytes, bytes]:
        sealing = self.module.ExchangeVault(SALT, SECRET)
        return sealing.seal_record(
            TENANT, RECORD, b"original bytes", b"redacted bytes", VALUE_MAP
        )

    def test_sealed_bytes_open_from_a_fresh_vault(self) -> None:
        generation, original, document, value_map = self._seal()
        self.assertEqual(generation, 1)
        for sealed in (original, document, value_map):
            self.assertNotIn(b"secret-value", sealed)
            self.assertNotIn(b"original bytes", sealed)

        opening = self.module.ExchangeVault(SALT, SECRET)
        opening.import_record(TENANT, RECORD, generation, original, document, value_map)
        self.assertEqual(opening.load_document(TENANT, RECORD), b"redacted bytes")
        self.assertEqual(opening.load_original(TENANT, RECORD), b"original bytes")
        self.assertEqual(
            json.loads(opening.load_value_map(TENANT, RECORD)),
            {"<PRIVATE_1>": "secret-value"},
        )

    def test_replacement_advances_the_generation(self) -> None:
        generation, original, document, value_map = self._seal()

        replacing = self.module.ExchangeVault(SALT, SECRET)
        replacing.import_record(
            TENANT, RECORD, generation, original, document, value_map
        )
        next_generation, *_sealed = replacing.replace_record(
            TENANT,
            RECORD,
            b"original two",
            b"redacted two",
            json.dumps({"<PRIVATE_1>": "second-value"}).encode(),
        )
        self.assertEqual(next_generation, generation + 1)

    def test_a_wrong_secret_refuses(self) -> None:
        generation, original, document, value_map = self._seal()
        wrong = self.module.ExchangeVault(SALT, b"a-different-secret")
        wrong.import_record(TENANT, RECORD, generation, original, document, value_map)
        with self.assertRaises(self.module.VaultError):
            wrong.load_document(TENANT, RECORD)

    def test_a_wrong_salt_refuses(self) -> None:
        generation, original, document, value_map = self._seal()
        wrong = self.module.ExchangeVault(b"tenant-salt-9999", SECRET)
        wrong.import_record(TENANT, RECORD, generation, original, document, value_map)
        with self.assertRaises(self.module.VaultError):
            wrong.load_document(TENANT, RECORD)

    def test_a_replayed_older_generation_refuses(self) -> None:
        generation, original, document, value_map = self._seal()

        replacing = self.module.ExchangeVault(SALT, SECRET)
        replacing.import_record(
            TENANT, RECORD, generation, original, document, value_map
        )
        next_generation, *_sealed = replacing.replace_record(
            TENANT,
            RECORD,
            b"original two",
            b"redacted two",
            json.dumps({"<PRIVATE_1>": "second-value"}).encode(),
        )

        # Generation-one ciphertext presented as the newer generation must not
        # open: this is the replay protection the database generation column
        # exists to carry.
        replayed = self.module.ExchangeVault(SALT, SECRET)
        replayed.import_record(
            TENANT, RECORD, next_generation, original, document, value_map
        )
        with self.assertRaises(self.module.VaultError):
            replayed.load_document(TENANT, RECORD)

    def test_generation_zero_is_never_imported(self) -> None:
        _generation, original, document, value_map = self._seal()
        importing = self.module.ExchangeVault(SALT, SECRET)
        with self.assertRaises(self.module.VaultError):
            importing.import_record(TENANT, RECORD, 0, original, document, value_map)
        with self.assertRaises(self.module.RecordNotFound):
            importing.load_document(TENANT, RECORD)

    def test_a_short_salt_is_rejected_at_construction(self) -> None:
        with self.assertRaises(self.module.VaultError):
            self.module.ExchangeVault(b"short", SECRET)

    def test_failures_map_to_their_exception_classes(self) -> None:
        generation, original, document, value_map = self._seal()
        wrong = self.module.ExchangeVault(SALT, b"a-different-secret")
        wrong.import_record(TENANT, RECORD, generation, original, document, value_map)
        for load in (wrong.load_document, wrong.load_original, wrong.load_value_map):
            with (
                self.subTest(load=load.__name__),
                self.assertRaises(self.module.AuthenticationFailed),
            ):
                load(TENANT, RECORD)

        replayed = self.module.ExchangeVault(SALT, SECRET)
        replayed.import_record(
            TENANT, RECORD, generation + 1, original, document, value_map
        )
        with self.assertRaises(self.module.RollbackDetected):
            replayed.load_value_map(TENANT, RECORD)

        empty = self.module.ExchangeVault(SALT, SECRET)
        for load in (empty.load_document, empty.load_original, empty.load_value_map):
            with (
                self.subTest(load=load.__name__),
                self.assertRaises(self.module.RecordNotFound),
            ):
                load(TENANT, RECORD)
        with self.assertRaises(self.module.RecordNotFound):
            empty.replace_record(TENANT, RECORD, b"o", b"d", b"{}")
        with self.assertRaises(self.module.VaultError):
            empty.seal_record(TENANT, RECORD, b"o", b"d", b"not json")
        with self.assertRaises(self.module.VaultError):
            empty.seal_record("", RECORD, b"o", b"d", b"{}")

    def test_a_rotated_key_opens_old_records_and_seals_new_ones(self) -> None:
        generation, original, document, value_map = self._seal()
        rotated = self.module.ExchangeVault(
            SALT, b"rotated-secret", key_version=2, decrypt_only={1: SECRET}
        )
        rotated.import_record(TENANT, RECORD, generation, original, document, value_map)
        self.assertEqual(rotated.load_document(TENANT, RECORD), b"redacted bytes")
        next_generation, *sealed = rotated.replace_record(
            TENANT, RECORD, b"original two", b"redacted two", b"{}"
        )

        old_key_only = self.module.ExchangeVault(SALT, SECRET)
        old_key_only.import_record(TENANT, RECORD, next_generation, *sealed)
        with self.assertRaisesRegex(self.module.VaultError, "version 2 is unavailable"):
            old_key_only.load_document(TENANT, RECORD)
        with self.assertRaises(self.module.VaultError):
            self.module.ExchangeVault(
                SALT, b"rotated-secret", key_version=2, decrypt_only={2: SECRET}
            )

    def test_a_replacement_after_rotation_opens_with_the_active_key_alone(self) -> None:
        # The managed adapter's rotation contract: a record sealed under a
        # retired version is replaced through a vault whose ACTIVE key is the
        # current one, and the new generation needs no historical key to open.
        generation, original, document, value_map = self._seal()
        rotated = self.module.ExchangeVault(
            SALT, b"rotated-secret", key_version=2, decrypt_only={1: SECRET}
        )
        rotated.import_record(TENANT, RECORD, generation, original, document, value_map)
        next_generation, *sealed = rotated.replace_record(
            TENANT, RECORD, b"original two", b"redacted two", b'{"k":"v"}'
        )
        self.assertEqual(next_generation, generation + 1)
        self.assertTrue(all(item[8:12] == (2).to_bytes(4, "big") for item in sealed))

        active_only = self.module.ExchangeVault(SALT, b"rotated-secret", key_version=2)
        active_only.import_record(TENANT, RECORD, next_generation, *sealed)
        self.assertEqual(active_only.load_original(TENANT, RECORD), b"original two")
        self.assertEqual(active_only.load_document(TENANT, RECORD), b"redacted two")
        self.assertEqual(
            json.loads(active_only.load_value_map(TENANT, RECORD)), {"k": "v"}
        )


if __name__ == "__main__":
    unittest.main()
