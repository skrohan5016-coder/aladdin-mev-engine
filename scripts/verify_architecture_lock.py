from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from aladdin_mev_engine.canonical import canonical_sha256, strict_json_loads


def main() -> int:
    manifest_path = ROOT / "governance" / "architecture.json"
    lock_path = ROOT / "governance" / "architecture.lock.json"
    manifest = strict_json_loads(manifest_path.read_bytes())
    lock = strict_json_loads(lock_path.read_bytes())
    digest = canonical_sha256(manifest)
    expected_id = f"AMEV-F0-ARCH-v1-{digest[:12]}"
    errors: list[str] = []
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
