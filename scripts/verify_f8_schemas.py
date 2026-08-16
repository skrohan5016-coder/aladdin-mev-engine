from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import urljoin

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
LOCK_PATH = ROOT / "governance" / "f8-schemas.lock.json"
REQUIRED = (
    "calibration-bucket-v1.schema.json",
    "calibration-policy-v1.schema.json",
    "historical-attempt-reference-v1.schema.json",
    "historical-calibration-report-v1.schema.json",
    "historical-cohort-key-v1.schema.json",
    "historical-corpus-source-manifest-v1.schema.json",
    "historical-economic-scoreboard-v1.schema.json",
    "historical-execution-record-v1.schema.json",
    "historical-expected-value-v1.schema.json",
    "historical-outcome-corpus-v1.schema.json",
    "historical-valuation-policy-v1.schema.json",
    "research-promotion-decision-v1.schema.json",
    "research-promotion-policy-v1.schema.json",
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
                errors.append(f"{name}: required keys do not exactly match properties at {path}")
        for key, child in value.items():
            _check_closed_objects(name, child, f"{path}/{key}", errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_closed_objects(name, child, f"{path}/{index}", errors)


def main() -> int:
    errors: list[str] = []
    loaded: dict[str, dict[str, object]] = {}
    identifiers: set[str] = set()
    schema_by_identifier: dict[str, str] = {}
    for path in sorted(SCHEMA_DIR.glob("*.json")):
        try:
            candidate = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if type(candidate) is dict and isinstance(candidate.get("$id"), str):
            identifier = candidate["$id"]
            previous = schema_by_identifier.get(identifier)
            if previous is not None and previous != path.name:
                errors.append(
                    f"duplicate schema identifier {identifier}: {previous}, {path.name}"
                )
            schema_by_identifier[identifier] = path.name

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
        expected_identifier = f"https://schemas.aladdin-mev.dev/{name}"
        if identifier != expected_identifier:
            errors.append(f"{name}: schema identifier is not the exact governed identifier")
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
        if isinstance(identifier, str):
            for reference in _references(value):
                if reference.startswith("#"):
                    continue
                resolved = urljoin(identifier, reference).split("#", 1)[0]
                if resolved not in schema_by_identifier:
                    errors.append(
                        f"{name}: schema reference does not resolve by declared $id: "
                        f"{reference} -> {resolved}"
                    )

    digests = {
        f"schemas/{name}": _canonical_sha256(value)
        for name, value in sorted(loaded.items())
    }
    try:
        lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"F8 schema lock is invalid or unreadable: {error}")
        lock = None
    if type(lock) is not dict or set(lock) != {"schema", "files"}:
        errors.append("F8 schema lock must be a closed object")
    else:
        if lock.get("schema") != "aladdin-mev-f8-schema-lock/v1":
            errors.append("F8 schema lock has an unknown schema")
        if lock.get("files") != digests:
            errors.append("F8 schema lock does not bind the exact schema digests")
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"schemas": len(loaded), "sha256": digests}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
