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

    def test_a_short_salt_is_rejected_at_construction(self) -> None:
        with self.assertRaises(self.module.VaultError):
            self.module.ExchangeVault(b"short", SECRET)


if __name__ == "__main__":
    unittest.main()
