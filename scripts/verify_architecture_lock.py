from __future__ import annotations

import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from aladdin_mev_engine.canonical import canonical_sha256, strict_json_loads

_MILESTONE = re.compile(r"^F[0-9]+$")


def main() -> int:
    manifest_path = ROOT / "governance" / "architecture.json"
    lock_path = ROOT / "governance" / "architecture.lock.json"
    manifest = strict_json_loads(manifest_path.read_bytes())
    lock = strict_json_loads(lock_path.read_bytes())
    errors: list[str] = []
    if type(manifest) is not dict:
        errors.append("architecture manifest must be an exact object")
        milestone = "INVALID"
    else:
        milestone = manifest.get("milestone")
        if type(milestone) is not str or _MILESTONE.fullmatch(milestone) is None:
            errors.append("architecture milestone is not governed")
            milestone = "INVALID"
    if type(lock) is not dict or set(lock) != {
        "schema",
        "architecture_id",
        "manifest_path",
        "manifest_sha256",
    }:
        errors.append("architecture lock must be a closed object")
    digest = canonical_sha256(manifest)
    expected_id = f"AMEV-{milestone}-ARCH-v1-{digest[:12]}"
    if type(lock) is dict:
        if lock.get("schema") != "aladdin-mev-architecture-lock/v1":
            errors.append("architecture lock schema is not governed")
        if lock.get("manifest_sha256") != digest:
            errors.append("manifest_sha256 does not match canonical architecture manifest")
        if lock.get("architecture_id") != expected_id:
            errors.append("architecture_id does not match canonical architecture manifest")
        if lock.get("manifest_path") != "governance/architecture.json":
            errors.append("manifest_path is not governed")
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"architecture_id": expected_id, "manifest_sha256": digest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
