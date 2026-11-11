import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from verify_sdist_lock import verify


class VerifyLockTests(unittest.TestCase):
    def test_archive_lock_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock = root / "Cargo.lock"
            lock.write_bytes(b"locked\n")
            archive = root / "package-1.tar.gz"

            def make(entries):
                with tarfile.open(archive, "w:gz") as tar:
                    for name, data in entries:
                        item = tarfile.TarInfo(name)
                        item.size = len(data)
                        tar.addfile(item, io.BytesIO(data))

            make([("package-1/Cargo.lock", b"locked\n")])
            verify(archive, lock)
            for entries in (
                [],
                [("package-1/Cargo.lock", b"wrong")],
                [("package-1/Cargo.lock", b"locked\n")] * 2,
                [("package-1/./Cargo.lock", b"locked\n")],
                [
                    ("package-1/Cargo.lock", b"locked\n"),
                    ("other/Cargo.lock", b"locked\n"),
                ],
            ):
                make(entries)
                with self.subTest(entries=entries), self.assertRaises(ValueError):
                    verify(archive, lock)


if __name__ == "__main__":
    unittest.main()
