"""Select the one version-matched, abi3 wheel compatible with this interpreter."""

import re
import sys
from pathlib import Path
from packaging.tags import sys_tags
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version

root = Path(__file__).resolve().parents[1]
cargo = (root / "Cargo.toml").read_text(encoding="utf-8")
workspace = cargo.split("[workspace.package]", 1)[1].split("\n[", 1)[0]
version = Version(re.search(r'^version\s*=\s*"([^"]+)"', workspace, re.M).group(1))
wheels = list(Path(sys.argv[1]).glob("*.whl"))
if len(wheels) != 1:
    raise SystemExit("expected exactly one wheel")
name, wheel_version, _, tags = parse_wheel_filename(wheels[0].name)
if (
    canonicalize_name(name) != "private-data-vault"
    or wheel_version != version
    or not any(tag.abi == "abi3" and tag in set(sys_tags()) for tag in tags)
):
    raise SystemExit("wheel name, version, abi3, or platform does not match")
print(wheels[0].resolve())
