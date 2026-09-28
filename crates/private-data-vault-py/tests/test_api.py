import importlib
import inspect
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

EXPLICIT_SECRET = b"0123456789abcdef0123456789abcdef"


class PublicApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = importlib.import_module("private_data_vault")

    def test_explicit_default_factory_persists_without_using_the_os_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(
                self.module.LocalVault.default_exists("scope-a", path=directory)
            )
            first = self.module.LocalVault.open_default(
                "scope-a", path=directory, secret=EXPLICIT_SECRET
            )
            first.store_value_map("tenant", "record", b'{"private":"value"}')
            self.assertTrue(
                self.module.LocalVault.default_exists("scope-a", path=directory)
            )
            self.assertFalse(
                self.module.LocalVault.default_exists("scope-b", path=directory)
            )
            second = self.module.LocalVault.open_default(
                "scope-a", path=directory, secret=EXPLICIT_SECRET
            )
            self.assertEqual(
                second.load_value_map("tenant", "record"), b'{"private":"value"}'
            )

    def test_default_factory_requires_a_path_for_an_explicit_secret(self) -> None:
        with self.assertRaisesRegex(self.module.VaultError, "explicit path"):
            self.module.LocalVault.open_default("scope-a", secret=EXPLICIT_SECRET)

    def test_concurrent_merge_uses_shared_storage_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vaults = [
                self.module.LocalVault(directory, b"test-secret") for _ in range(8)
            ]
            barrier = Barrier(len(vaults))

            def merge(index: int) -> None:
                barrier.wait(timeout=5)
                vaults[index].merge_value_map(
                    "tenant",
                    "record",
                    json.dumps({str(index): f"value-{index}"}).encode(),
                )

            with ThreadPoolExecutor(max_workers=len(vaults)) as executor:
                list(executor.map(merge, range(len(vaults))))
            self.assertEqual(
                json.loads(vaults[0].load_value_map("tenant", "record")),
                {str(index): f"value-{index}" for index in range(len(vaults))},
            )

    def test_merge_refuses_to_partially_update_a_versioned_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = self.module.LocalVault(directory, b"test-secret")
            vault.store_record(
                "tenant", "record", b"original", b"document", b'{"a":"one"}'
            )
            with self.assertRaises(self.module.VaultError):
                vault.merge_value_map("tenant", "record", b'{"b":"two"}')
            self.assertEqual(
                json.loads(vault.load_value_map("tenant", "record")), {"a": "one"}
            )

    def test_exact_public_names_and_round_trips(self) -> None:
        for name in (
            "LocalVault",
            "ExchangeVault",
            "VaultError",
            "RecordNotFound",
            "AuthenticationFailed",
            "RollbackDetected",
            "StorageUnavailable",
        ):
            self.assertTrue(hasattr(self.module, name), name)
        self.assertEqual(
            str(inspect.signature(self.module.LocalVault)),
            "(path, secret, *, key_version=1, decrypt_only=None)",
        )
        self.assertEqual(
            str(inspect.signature(self.module.LocalVault.store_record)),
            "(self, /, tenant, record, original, document, value_map)",
        )
        self.assertEqual(
            str(inspect.signature(self.module.LocalVault.reencrypt_batch)),
            "(self, /, target_version, cursor, limit)",
        )

        with tempfile.TemporaryDirectory() as directory:
            vault = self.module.LocalVault(directory, b"correct horse battery staple")
            value_map = json.dumps(
                {"name": "Ada", "city": "Zürich"}, ensure_ascii=False
            ).encode()
            document = b"\x00\xffraw document\x80"
            vault.store_value_map("tenant-a", "record-a", value_map)
            vault.store_document("tenant-a", "record-a", document)
            self.assertEqual(
                json.loads(vault.load_value_map("tenant-a", "record-a")),
                json.loads(value_map),
            )
            self.assertEqual(vault.load_document("tenant-a", "record-a"), document)
            vault.purge("tenant-a", "record-a")
            with self.assertRaises(self.module.RecordNotFound):
                vault.load_value_map("tenant-a", "record-a")
            with self.assertRaises(self.module.RecordNotFound):
                vault.load_document("tenant-a", "record-a")

    def test_wrong_secret_raises_authentication_failed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.module.LocalVault(directory, b"correct secret").store_value_map(
                "tenant-a", "record-a", b'{"name":"Ada"}'
            )
            wrong_vault = self.module.LocalVault(directory, b"wrong secret")
            with self.assertRaises(self.module.AuthenticationFailed):
                wrong_vault.load_value_map("tenant-a", "record-a")

    def test_original_atomic_record_and_replay_refusal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = self.module.LocalVault(directory, b"correct secret")
            vault.store_original("tenant-source", "record-source", b"source original")
            source_path = next(Path(directory, "originals").glob("*.pvo"))
            vault.store_original("tenant-target", "record-target", b"target original")
            target_path = next(
                path
                for path in Path(directory, "originals").glob("*.pvo")
                if path != source_path
            )
            target_path.write_bytes(source_path.read_bytes())
            with self.assertRaises(self.module.AuthenticationFailed):
                vault.load_original("tenant-target", "record-target")

            vault.store_record(
                "tenant-a",
                "record-a",
                b"original one",
                b"redacted one",
                b'{"private":"one"}',
            )
            self.assertEqual(
                vault.load_original("tenant-a", "record-a"), b"original one"
            )

            generation_one = next(
                Path(directory, "values").glob("*.00000000000000000001.pvm")
            )
            replayed = generation_one.read_bytes()
            vault.store_record(
                "tenant-a",
                "record-a",
                b"original two",
                b"redacted two",
                b'{"private":"two"}',
            )
            generation_two = next(
                Path(directory, "values").glob("*.00000000000000000002.pvm")
            )
            generation_two.write_bytes(replayed)
            with self.assertRaises(self.module.RollbackDetected):
                vault.load_value_map("tenant-a", "record-a")

    def test_rotation_resumes_from_an_authenticated_cursor(self) -> None:
        first_secret = b"first tenant secret"
        second_secret = b"second tenant secret"
        with tempfile.TemporaryDirectory() as directory:
            first = self.module.LocalVault(directory, first_secret, key_version=1)
            for index in range(3):
                first.store_record(
                    "tenant-a",
                    f"rotation-record-{index}",
                    f"original-{index}".encode(),
                    f"redacted-{index}".encode(),
                    json.dumps({"private": str(index)}).encode(),
                )
            del first

            rotated = self.module.LocalVault(
                directory,
                second_secret,
                key_version=2,
                decrypt_only={1: first_secret},
            )
            visited, rewritten, cursor = rotated.reencrypt_batch(2, None, 2)
            self.assertEqual((visited, rewritten), (2, 2))
            self.assertIsInstance(cursor, str)
            del rotated

            rotated = self.module.LocalVault(
                directory,
                second_secret,
                key_version=2,
                decrypt_only={1: first_secret},
            )
            self.assertEqual(rotated.reencrypt_batch(2, cursor, 2), (1, 1, None))
            self.assertEqual(rotated.reencrypt_batch(2, None, 10), (3, 0, None))
            with self.assertRaises(self.module.VaultError):
                rotated.reencrypt_batch(2, "pdv-reencrypt-v2:00", 2)
            del rotated

            active_only = self.module.LocalVault(
                directory, second_secret, key_version=2
            )
            self.assertEqual(
                active_only.load_original("tenant-a", "rotation-record-0"),
                b"original-0",
            )

    def test_key_cursor_batch_and_value_validation(self) -> None:
        class IndexLike:
            def __index__(self) -> int:
                return 1

        with tempfile.TemporaryDirectory() as directory:
            for invalid_secret in (
                [115, 101, 99, 114, 101, 116],
                (115, 101, 99, 114, 101, 116),
                bytearray(b"secret"),
            ):
                with (
                    self.subTest(invalid_secret=invalid_secret),
                    self.assertRaises(TypeError),
                ):
                    self.module.LocalVault(directory, invalid_secret)
            for invalid_version in (True, IndexLike()):
                with (
                    self.subTest(invalid_version=invalid_version),
                    self.assertRaises(TypeError),
                ):
                    self.module.LocalVault(
                        directory,
                        b"secret",
                        key_version=invalid_version,
                    )
            with self.assertRaises(self.module.VaultError):
                self.module.LocalVault(directory, b"secret", key_version=0)
            with self.assertRaises(self.module.VaultError):
                self.module.LocalVault(
                    directory,
                    b"secret",
                    key_version=2,
                    decrypt_only={2: b"duplicate"},
                )
            for invalid_keys in (
                {1: [115, 101, 99, 114, 101, 116]},
                {1: (115, 101, 99, 114, 101, 116)},
                {1: bytearray(b"secret")},
                {1: b"valid", 2: [110, 111, 116, 45, 98, 121, 116, 101, 115]},
                {"1": b"secret"},
                {True: b"secret"},
            ):
                with (
                    self.subTest(invalid_keys=invalid_keys),
                    self.assertRaises(TypeError),
                ):
                    self.module.LocalVault(
                        directory,
                        b"secret",
                        key_version=2,
                        decrypt_only=invalid_keys,
                    )

            vault = self.module.LocalVault(directory, b"secret", key_version=2)
            with self.assertRaises(self.module.VaultError):
                vault.store_record(
                    "tenant", "record", b"original", b"redacted", b"not json"
                )
            with self.assertRaises(self.module.VaultError):
                vault.store_record(
                    "tenant",
                    "record",
                    b"original",
                    b"redacted",
                    b'{"private":"first","private":"second"}',
                )
            with self.assertRaises(self.module.VaultError):
                vault.reencrypt_batch(2, None, 0)
            with self.assertRaises(self.module.VaultError):
                vault.reencrypt_batch(2, "pdv-reencrypt-v2:00", 1)
            for invalid_target in (True, IndexLike()):
                with (
                    self.subTest(invalid_target=invalid_target),
                    self.assertRaises(TypeError),
                ):
                    vault.reencrypt_batch(invalid_target, None, 1)
            for invalid_limit in (True, IndexLike()):
                with (
                    self.subTest(invalid_limit=invalid_limit),
                    self.assertRaises(TypeError),
                ):
                    vault.reencrypt_batch(2, None, invalid_limit)
            for invalid_age in (True, IndexLike()):
                with (
                    self.subTest(invalid_age=invalid_age),
                    self.assertRaises(TypeError),
                ):
                    vault.purge_expired(invalid_age)
            with self.assertRaises(TypeError):
                vault.store_original("tenant", "record", "not bytes")


if __name__ == "__main__":
    unittest.main()
