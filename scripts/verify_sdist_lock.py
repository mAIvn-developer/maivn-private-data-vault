"""Verify an sdist embeds exactly the checked-in root Cargo.lock."""

import sys
import tarfile
from pathlib import Path, PurePosixPath


def verify(archive: Path, lock: Path) -> None:
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        if any(
            "\\" in m.name or any(part in (".", "..") for part in m.name.split("/"))
            for m in members
        ):
            raise ValueError("sdist contains an ambiguous path")
        candidates = [m for m in members if PurePosixPath(m.name).name == "Cargo.lock"]
        if len(candidates) != 1:
            raise ValueError("sdist must contain exactly one Cargo.lock")
        member = candidates[0]
        parts = member.name.split("/")
        if (
            len(parts) != 2
            or parts[0] != archive.name.removesuffix(".tar.gz")
            or parts[1] != "Cargo.lock"
            or not member.isfile()
        ):
            raise ValueError("Cargo.lock must be a regular file at the archive root")
        content = tar.extractfile(member)
        if content is None or content.read() != lock.read_bytes():
            raise ValueError("sdist Cargo.lock differs from checked-in lock")


if __name__ == "__main__":
    archives = list(Path(sys.argv[1]).glob("*.tar.gz"))
    if len(archives) != 1:
        raise SystemExit("expected exactly one sdist")
    verify(archives[0], Path("Cargo.lock"))
