from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
LOCK_PATH = ROOT / "governance" / "f5-schemas.lock.json"
REQUIRED = (
    "authenticated-executor-deployment-v1.schema.json",
    "execution-constraint-policy-v1.schema.json",
    "executor-deployment-registry-v1.schema.json",
    "executor-deployment-spec-v1.schema.json",
    "executor-interface-v1.schema.json",
    "governed-executor-call-v1.schema.json",
    "private-bundle-intent-v1.schema.json",
    "route-command-v1.schema.json",
    "sender-state-evidence-v1.schema.json",
    "transaction-simulation-result-v1.schema.json",
    "unsigned-eip1559-transaction-v1.schema.json",
    "unsigned-execution-package-v1.schema.json",
)


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


def _check_closed_objects(name: str, value: object, path: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        if value.get("type") == "object":
            if value.get("additionalProperties") is not False:
                errors.append(f"{name}: object is not closed at {path}")
            properties = value.get("properties")
            required = value.get("required")
            if not isinstance(properties, dict) or not isinstance(required, list):
                errors.append(f"{name}: object contract is incomplete at {path}")
            elif set(properties) != set(required):
                errors.append(
                    f"{name}: required keys do not exactly match properties at {path}"
                )
        for key, child in value.items():
            _check_closed_objects(name, child, f"{path}/{key}", errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_closed_objects(name, child, f"{path}/{index}", errors)


def main() -> int:
    errors: list[str] = []
    loaded: dict[str, dict[str, object]] = {}
    identifiers: set[str] = set()
    for name in REQUIRED:
        path = SCHEMA_DIR / name
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            errors.append(f"{name}: invalid or unreadable schema: {error}")
            continue
        if type(value) is not dict:
            errors.append(f"{name}: schema root must be an object")
            continue
        loaded[name] = value
        if value.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            errors.append(f"{name}: unexpected JSON Schema dialect")
        identifier = value.get("$id")
        if not isinstance(identifier, str) or not identifier.startswith(
            "https://schemas.aladdin.invalid/mev/"
        ):
            errors.append(f"{name}: schema identifier is not governed")
        elif identifier in identifiers:
            errors.append(f"{name}: duplicate schema identifier")
        else:
            identifiers.add(identifier)
        if value.get("type") != "object" or value.get("additionalProperties") is not False:
            errors.append(f"{name}: top-level object must be closed")
        properties = value.get("properties")
        required = value.get("required")
        if not isinstance(properties, dict) or not isinstance(required, list):
            errors.append(f"{name}: properties/required authority is missing")
        elif set(properties) != set(required):
            errors.append(f"{name}: required keys do not exactly match properties")
        _check_closed_objects(name, value, "#", errors)
        for reference in _references(value):
            if reference.startswith(("https://", "#")):
                continue
            relative = reference.split("#", 1)[0]
            if not relative or not (SCHEMA_DIR / relative).is_file():
                errors.append(f"{name}: unresolved relative schema reference {reference}")

    digests = {
        f"schemas/{name}": _canonical_sha256(value)
        for name, value in sorted(loaded.items())
    }
    try:
        lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"F5 schema lock is invalid or unreadable: {error}")
        lock = None
    if type(lock) is not dict or set(lock) != {"schema", "files"}:
        errors.append("F5 schema lock must be a closed object")
    else:
        if lock.get("schema") != "aladdin-mev-f5-schema-lock/v1":
            errors.append("F5 schema lock has an unknown schema")
        if lock.get("files") != digests:
            errors.append("F5 schema lock does not bind the exact schema digests")
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"schemas": len(loaded), "sha256": digests}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
