from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.canonical import canonical_sha256

from f6_helpers import (
    f6_package,
    f6_relay_registry,
    f6_relay_request,
    f6_relay_response,
    f6_signed_bundle,
    f6_signed_transaction,
)

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "eip1559-signature-v1.schema.json",
    "externally-signed-execution-package-v1.schema.json",
    "relay-endpoint-registry-v1.schema.json",
    "relay-endpoint-spec-v1.schema.json",
    "relay-response-evidence-v1.schema.json",
    "relay-submission-request-v1.schema.json",
    "signed-eip1559-transaction-v1.schema.json",
    "signed-private-bundle-v1.schema.json",
)


def references(value: object) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref" and isinstance(child, str):
                found.append(child)
            else:
                found.extend(references(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(references(child))
    return found


def assert_closed_objects(test: unittest.TestCase, value: object, path: str = "#") -> None:
    if isinstance(value, dict):
        if value.get("type") == "object":
            test.assertIs(value.get("additionalProperties"), False, msg=path)
            test.assertEqual(set(value.get("properties", {})), set(value.get("required", [])), msg=path)
        for key, child in value.items():
            assert_closed_objects(test, child, f"{path}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_closed_objects(test, child, f"{path}/{index}")


class F6SchemaContractTests(unittest.TestCase):
    def test_schemas_are_closed_and_relative_references_resolve(self) -> None:
        identifiers: set[str] = set()
        for name in REQUIRED:
            value = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(value["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertNotIn(value["$id"], identifiers)
            identifiers.add(value["$id"])
            assert_closed_objects(self, value)
            for reference in references(value):
                if reference.startswith(("https://", "#")):
                    continue
                self.assertTrue((ROOT / "schemas" / reference.split("#", 1)[0]).is_file())

    def test_f6_schema_lock_binds_exact_canonical_digests(self) -> None:
        lock = json.loads((ROOT / "governance" / "f6-schemas.lock.json").read_text(encoding="utf-8"))
        expected = {
            f"schemas/{name}": canonical_sha256(
                json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            )
            for name in REQUIRED
        }
        self.assertEqual(lock, {"schema": "aladdin-mev-f6-schema-lock/v1", "files": dict(sorted(expected.items()))})

    def test_runtime_output_keys_match_governed_schemas(self) -> None:
        signed = f6_signed_transaction()
        registry = f6_relay_registry()
        pairs = (
            ("eip1559-signature-v1.schema.json", signed.signature.to_json_value()),
            ("signed-eip1559-transaction-v1.schema.json", signed.to_json_value()),
            ("signed-private-bundle-v1.schema.json", f6_signed_bundle().to_json_value()),
            ("relay-endpoint-spec-v1.schema.json", registry.endpoints[0].to_json_value()),
            ("relay-endpoint-registry-v1.schema.json", registry.to_json_value()),
            ("relay-submission-request-v1.schema.json", f6_relay_request().to_json_value()),
            ("relay-response-evidence-v1.schema.json", f6_relay_response().to_json_value()),
            ("externally-signed-execution-package-v1.schema.json", f6_package().to_json_value()),
        )
        for name, value in pairs:
            schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(set(value), set(schema["properties"]), msg=name)

    def test_signature_and_raw_transaction_widths_are_exact(self) -> None:
        signature_schema = json.loads((ROOT / "schemas" / "eip1559-signature-v1.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(signature_schema["properties"]["signature_bytes"]["pattern"], "^0x[0-9a-f]{130}$")
        signed_schema = json.loads((ROOT / "schemas" / "signed-eip1559-transaction-v1.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(signed_schema["properties"]["transaction_hash"]["pattern"], "^0x[0-9a-f]{64}$")
        self.assertEqual(signed_schema["properties"]["raw_transaction"]["pattern"], "^0x(?:[0-9a-f]{2})*$")


if __name__ == "__main__":
    unittest.main()
