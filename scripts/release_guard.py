"""Release guard for private-data-vault: exact release tag only, version newer than PyPI's.

The Python package version is dynamic (maturin reads it from the Cargo workspace),
so the version comes from [workspace.package] in the repository's Cargo.toml and the
project name from the Python crate's pyproject.toml. The ref checks run before any
network call: the workflow must run on a tag, and GITHUB_REF must be exactly
refs/tags/v<version>; a branch named like a tag or a workflow_dispatch from a branch
is refused.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import tomllib
from packaging.version import InvalidVersion, Version

CRATE = Path("crates/private-data-vault-py")


def read_project_metadata(project_root: Path) -> tuple[str, str]:
    pyproject = cast(
        Mapping[str, object],
        tomllib.loads(project_root.joinpath(CRATE, "pyproject.toml").read_text(encoding="utf-8")),
    )
    project = cast(Mapping[str, object], pyproject["project"])
    project_name = project["name"]
    if not isinstance(project_name, str):
        raise RuntimeError("pyproject.toml project.name must be a string.")
    cargo = cast(
        Mapping[str, object],
        tomllib.loads(project_root.joinpath("Cargo.toml").read_text(encoding="utf-8")),
    )
    workspace = cast(Mapping[str, object], cargo.get("workspace", {}))
    package = cast(Mapping[str, object], workspace.get("package", {}))
    version = package.get("version")
    if not isinstance(version, str) or not version:
        raise RuntimeError("Cargo.toml [workspace.package].version must be a string.")
    return project_name, version


def check_release_ref(environ: Mapping[str, str], project_version: str) -> str | None:
    """Return why this run may not publish, or None when it runs on the exact release tag."""
    expected_tag = f"v{project_version}"
    ref_type = environ.get("GITHUB_REF_TYPE", "").strip()
    ref = environ.get("GITHUB_REF", "").strip()
    ref_name = environ.get("GITHUB_REF_NAME", "").strip()
    if ref_type != "tag":
        return f"Releases publish only from a tag; GITHUB_REF_TYPE is {ref_type or 'unset'!r}."
    if ref != f"refs/tags/{expected_tag}":
        return f"GITHUB_REF is {ref or 'unset'!r}; expected 'refs/tags/{expected_tag}'."
    if ref_name != expected_tag:
        return f"GITHUB_REF_NAME is {ref_name or 'unset'!r}; expected {expected_tag!r}."
    return None


def fetch_published_versions(project_name: str) -> list[Version]:
    url = f"https://pypi.org/pypi/{project_name}/json"
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        response = urllib.request.urlopen(request, timeout=15)  # noqa: S310  # nosec B310
        try:
            payload_obj = cast(object, json.loads(response.read().decode("utf-8")))
        finally:
            response.close()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []
        raise
    payload = cast(Mapping[str, object], payload_obj)
    releases_obj = payload.get("releases", {})
    if not isinstance(releases_obj, Mapping):
        return []
    versions: list[Version] = []
    for raw_version in cast(Mapping[object, object], releases_obj):
        if isinstance(raw_version, str):
            try:
                versions.append(Version(raw_version))
            except InvalidVersion:
                continue
    return versions


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    project_name, project_version = read_project_metadata(project_root)
    refusal = check_release_ref(os.environ, project_version)
    if refusal:
        print(refusal, file=sys.stderr)
        return 1
    current_version = Version(project_version)
    published_versions = fetch_published_versions(project_name)
    if published_versions and current_version <= max(published_versions):
        print(
            f"{project_name} version {project_version} is not greater than the latest published version "
            f"{max(published_versions)}.",
            file=sys.stderr,
        )
        return 1
    print(f"{project_name} {project_version} is releasable from refs/tags/v{project_version}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
