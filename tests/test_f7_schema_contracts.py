from __future__ import annotations

import json
from pathlib import Path
import unittest
from urllib.parse import urljoin

from aladdin_mev_engine.canonical import canonical_sha256

from f7_helpers import f7_inclusion, f7_outcome

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "authenticated-execution-block-v1.schema.json",
    "authenticated-transaction-receipt-inclusion-v1.schema.json",
    "evm-block-state-anchor-v1.schema.json",
    "evm-log-entry-v1.schema.json",
    "executor-settlement-event-registry-v1.schema.json",
    "executor-settlement-event-spec-v1.schema.json",
    "executor-settlement-event-v1.schema.json",
    "indexed-trie-proof-v1.schema.json",
    "realized-execution-outcome-v1.schema.json",
    "recorded-execution-block-v1.schema.json",
    "recorded-rollup-fee-v1.schema.json",
    "transaction-receipt-v1.schema.json",
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


def assert_closed_objects(
    test: unittest.TestCase,
    value: object,
    path: str = "#",
) -> None:
    if isinstance(value, dict):
        if value.get("type") == "object":
            test.assertIs(value.get("additionalProperties"), False, msg=path)
            test.assertEqual(
                set(value.get("properties", {})),
                set(value.get("required", [])),
                msg=path,
            )
        for key, child in value.items():
            assert_closed_objects(test, child, f"{path}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_closed_objects(test, child, f"{path}/{index}")


class F7SchemaContractTests(unittest.TestCase):
    def test_schemas_are_closed_and_relative_references_resolve(self) -> None:
        identifiers: set[str] = set()
        for name in REQUIRED:
            value = json.loads(
                (ROOT / "schemas" / name).read_text(encoding="utf-8")
            )
            self.assertEqual(
                value["$schema"],
                "https://json-schema.org/draft/2020-12/schema",
            )
            self.assertNotIn(value["$id"], identifiers)
            identifiers.add(value["$id"])
            assert_closed_objects(self, value)
            schema_ids = {
                json.loads(path.read_text(encoding="utf-8"))["$id"]: path.name
                for path in (ROOT / "schemas").glob("*.json")
            }
            for reference in references(value):
                if reference.startswith("#"):
                    continue
                resolved = urljoin(value["$id"], reference).split("#", 1)[0]
                self.assertIn(resolved, schema_ids, msg=f"{reference} -> {resolved}")

    def test_f7_schema_lock_binds_exact_canonical_digests(self) -> None:
        lock = json.loads(
            (ROOT / "governance" / "f7-schemas.lock.json").read_text(
                encoding="utf-8"
            )
        )
        expected = {
            f"schemas/{name}": canonical_sha256(
                json.loads(
                    (ROOT / "schemas" / name).read_text(encoding="utf-8")
                )
            )
            for name in REQUIRED
        }
        self.assertEqual(
            lock,
            {
                "schema": "aladdin-mev-f7-schema-lock/v1",
                "files": dict(sorted(expected.items())),
            },
        )

    def test_runtime_output_keys_match_governed_schemas(self) -> None:
        inclusion = f7_inclusion()
        outcome = f7_outcome()
        log = inclusion.receipt.logs[0]
        pairs = (
            ("evm-log-entry-v1.schema.json", log.to_json_value()),
            ("transaction-receipt-v1.schema.json", inclusion.receipt.to_json_value()),
            (
                "evm-block-state-anchor-v1.schema.json",
                inclusion.block.state_anchor.to_json_value(),
            ),
            (
                "recorded-execution-block-v1.schema.json",
                inclusion.block.block.to_json_value(),
            ),
            (
                "authenticated-execution-block-v1.schema.json",
                inclusion.block.to_json_value(),
            ),
            (
                "indexed-trie-proof-v1.schema.json",
                inclusion.transaction_proof.to_json_value(),
            ),
            (
                "authenticated-transaction-receipt-inclusion-v1.schema.json",
                inclusion.to_json_value(),
            ),
            (
                "executor-settlement-event-spec-v1.schema.json",
                outcome.settlement_spec.to_json_value(),
            ),
            (
                "executor-settlement-event-registry-v1.schema.json",
                outcome.settlement_registry.to_json_value(),
            ),
            (
                "executor-settlement-event-v1.schema.json",
                outcome.settlement_event.to_json_value(),
            ),
            (
                "recorded-rollup-fee-v1.schema.json",
                outcome.rollup_fee.to_json_value(),
            ),
            (
                "realized-execution-outcome-v1.schema.json",
                outcome.to_json_value(),
            ),
        )
        for name, value in pairs:
            schema = json.loads(
                (ROOT / "schemas" / name).read_text(encoding="utf-8")
            )
            self.assertEqual(set(value), set(schema["properties"]), msg=name)

    def test_hash_header_receipt_and_proof_widths_are_governed(self) -> None:
        anchor = json.loads(
            (ROOT / "schemas" / "evm-block-state-anchor-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            anchor["properties"]["block_hash"]["pattern"],
            "^0x(?!0{64}$)[0-9a-f]{64}$",
        )
        self.assertEqual(
            anchor["properties"]["state_root"]["pattern"],
            "^0x(?!0{64}$)[0-9a-f]{64}$",
        )
        block = json.loads(
            (ROOT / "schemas" / "recorded-execution-block-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(block["properties"]["block_hash"]["pattern"], "^0x(?!0{64}$)[0-9a-f]{64}$")
        self.assertEqual(block["properties"]["raw_header"]["pattern"], "^0x(?:[0-9a-f]{2})*$")
        receipt = json.loads(
            (ROOT / "schemas" / "transaction-receipt-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(receipt["properties"]["logs_bloom"]["pattern"], "^0x[0-9a-f]{512}$")
        self.assertEqual(receipt["properties"]["raw_receipt"]["pattern"], "^0x(?:[0-9a-f]{2})*$")
        proof = json.loads(
            (ROOT / "schemas" / "indexed-trie-proof-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(proof["properties"]["trie_key"]["pattern"], "^0x(?:[0-9a-f]{2})*$")
        self.assertEqual(proof["properties"]["source_sha256"]["pattern"], "^[0-9a-f]{64}$")

    def test_cross_schema_ids_and_runtime_narrowing_are_standard_resolvable(self) -> None:
        inclusion = json.loads(
            (ROOT / "schemas" / "authenticated-transaction-receipt-inclusion-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            inclusion["$id"],
            "https://schemas.aladdin-mev.dev/authenticated-transaction-receipt-inclusion-v1.schema.json",
        )
        self.assertEqual(
            inclusion["properties"]["executor_state"]["$ref"],
            "evm-state-proof-evidence-v1.schema.json",
        )
        self.assertEqual(
            inclusion["properties"]["receipt"]["properties"]["transaction_type"]["const"],
            "2",
        )
        self.assertEqual(
            inclusion["properties"]["transaction_proof"]["properties"]["kind"]["const"],
            "transaction",
        )
        receipt = json.loads(
            (ROOT / "schemas" / "transaction-receipt-v1.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(receipt["allOf"]), 2)
        event = json.loads(
            (ROOT / "schemas" / "executor-settlement-event-v1.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            event["properties"]["log"]["properties"]["topics"]["prefixItems"][0]["const"],
            "0x1b6b6668bee41d2b8a4b5f7487b22305e77995a51f843da784ad8436abec07a3",
        )
        log_schema = json.loads(
            (ROOT / "schemas" / "evm-log-entry-v1.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(log_schema["properties"]["address"]["pattern"], "^0x[0-9a-f]{40}$")
        spec = json.loads(
            (ROOT / "schemas" / "executor-settlement-event-spec-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            spec["properties"]["topic0"]["const"],
            "0x1b6b6668bee41d2b8a4b5f7487b22305e77995a51f843da784ad8436abec07a3",
        )
        self.assertEqual(
            spec["properties"]["runtime_code_hash"]["not"]["const"],
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )


if __name__ == "__main__":
    unittest.main()
