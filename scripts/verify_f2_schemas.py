from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
LOCK_PATH = ROOT / "governance" / "f2-schemas.lock.json"
REQUIRED = (
    "evm-block-state-payload-v1.schema.json",
    "evm-state-proof-payload-v1.schema.json",
    "evm-state-proof-evidence-v1.schema.json",
    "evm-state-snapshot-v1.schema.json",
    "observation-envelope-v1.schema.json",
    "source-contract-v1.schema.json",
)
NEW_KINDS = {"evm-block-state", "evm-state-proof"}


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _references(value: object) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref" and isinstance(child, str):
                found.append(child)
            else:
                found.extend(_references(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_references(child))
    return found


def main() -> int:
    errors: list[str] = []
    loaded: dict[str, dict[str, object]] = {}
    for name in REQUIRED:
        path = SCHEMA_DIR / name
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            errors.append(f"{name}: invalid or unreadable schema: {error}")
            continue
        if not isinstance(value, dict):
            errors.append(f"{name}: schema root must be an object")
            continue
        loaded[name] = value
        if value.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            errors.append(f"{name}: unexpected JSON Schema dialect")
        if value.get("type") != "object" or value.get("additionalProperties") is not False:
            errors.append(f"{name}: top-level object must be closed")
        properties = value.get("properties")
        required = value.get("required")
        if not isinstance(properties, dict) or not isinstance(required, list):
            errors.append(f"{name}: properties/required authority is missing")
        elif set(properties) != set(required):
            errors.append(f"{name}: required keys do not exactly match properties")
        for reference in _references(value):
            if reference.startswith("https://") or reference.startswith("#"):
                continue
            if not (SCHEMA_DIR / reference).is_file():
                errors.append(f"{name}: unresolved relative schema reference {reference}")

    for name in ("observation-envelope-v1.schema.json", "source-contract-v1.schema.json"):
        schema = loaded.get(name)
        if schema is None:
            continue
        try:
            if name.startswith("observation"):
                kinds = schema["properties"]["kind"]["enum"]  # type: ignore[index]
            else:
                kinds = schema["properties"]["allowed_events"]["items"]["properties"]["kind"]["enum"]  # type: ignore[index]
        except (KeyError, TypeError):
            errors.append(f"{name}: observation-kind enum is missing")
            continue
        if not isinstance(kinds, list) or not NEW_KINDS.issubset(kinds):
            errors.append(f"{name}: F2 observation kinds are missing")

    digests = {
        f"schemas/{name}": _canonical_sha256(value)
        for name, value in sorted(loaded.items())
    }
    try:
        lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"F2 schema lock is invalid or unreadable: {error}")
        lock = None
    if type(lock) is not dict or set(lock) != {"schema", "files"}:
        errors.append("F2 schema lock must be a closed object")
    else:
        if lock.get("schema") != "aladdin-mev-f2-schema-lock/v1":
            errors.append("F2 schema lock has an unknown schema")
        if lock.get("files") != digests:
            errors.append("F2 schema lock does not bind the exact schema digests")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"schemas": len(loaded), "sha256": digests}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
