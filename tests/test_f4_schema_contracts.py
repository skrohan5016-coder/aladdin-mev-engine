from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.assets import AssetAmount
from aladdin_mev_engine.canonical import canonical_sha256

from f4_helpers import cost_envelope, net_evidence, simulations

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "asset-amount-v1.schema.json",
    "asset-id-v1.schema.json",
    "atomic-execution-plan-v1.schema.json",
    "chain-health-evidence-v1.schema.json",
    "conservative-net-profit-evidence-v1.schema.json",
    "conservative-valuation-rate-v1.schema.json",
    "eip1559-cost-envelope-v1.schema.json",
    "execution-cost-envelope-v1.schema.json",
    "execution-decision-v1.schema.json",
    "funding-plan-v1.schema.json",
    "reserve-cost-component-v1.schema.json",
    "risk-budget-evidence-v1.schema.json",
    "route-simulation-result-v1.schema.json",
    "valuation-book-v1.schema.json",
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


def assert_closed(test: unittest.TestCase, value: object, path: str = "#") -> None:
    if isinstance(value, dict):
        if value.get("type") == "object":
            test.assertIs(value.get("additionalProperties"), False, msg=path)
            test.assertEqual(set(value.get("properties", {})), set(value.get("required", [])), msg=path)
        for key, child in value.items():
            assert_closed(test, child, f"{path}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_closed(test, child, f"{path}/{index}")


class F4SchemaContractTests(unittest.TestCase):
    def test_schemas_are_closed_and_relative_references_resolve(self) -> None:
        identifiers: set[str] = set()
        for name in REQUIRED:
            value = json.loads((ROOT / "schemas" / name).read_text())
            self.assertEqual(value["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertNotIn(value["$id"], identifiers)
            identifiers.add(value["$id"])
            assert_closed(self, value)
            for reference in references(value):
                if reference.startswith(("https://", "#")):
                    continue
                self.assertTrue((ROOT / "schemas" / reference.split("#", 1)[0]).is_file())

    def test_f4_schema_lock_binds_exact_canonical_digests(self) -> None:
        lock = json.loads((ROOT / "governance" / "f4-schemas.lock.json").read_text())
        expected = {
            f"schemas/{name}": canonical_sha256(json.loads((ROOT / "schemas" / name).read_text()))
            for name in REQUIRED
        }
        self.assertEqual(lock, {"schema": "aladdin-mev-f4-schema-lock/v1", "files": dict(sorted(expected.items()))})

    def test_runtime_output_keys_match_governed_schemas(self) -> None:
        envelope = cost_envelope()
        evidence = net_evidence(envelope)
        plan = envelope.plan
        rate = envelope.valuation_book.rates[0]
        reserve = envelope.reserve_components[0]
        simulation = simulations(plan)[0]
        pairs = (
            ("asset-id-v1.schema.json", plan.base_asset.to_json_value()),
            ("asset-amount-v1.schema.json", AssetAmount(plan.base_asset, 1).to_json_value()),
            ("conservative-valuation-rate-v1.schema.json", rate.to_json_value()),
            ("valuation-book-v1.schema.json", envelope.valuation_book.to_json_value()),
            ("funding-plan-v1.schema.json", plan.funding.to_json_value()),
            ("atomic-execution-plan-v1.schema.json", plan.to_json_value()),
            ("eip1559-cost-envelope-v1.schema.json", envelope.fee_envelope.to_json_value()),
            ("reserve-cost-component-v1.schema.json", reserve.to_json_value()),
            (
                "chain-health-evidence-v1.schema.json",
                evidence.chain_health_evidence.to_json_value(),
            ),
            (
                "risk-budget-evidence-v1.schema.json",
                evidence.risk_budget_evidence.to_json_value(),
            ),
            ("route-simulation-result-v1.schema.json", simulation.to_json_value()),
            ("execution-cost-envelope-v1.schema.json", envelope.to_json_value()),
            ("conservative-net-profit-evidence-v1.schema.json", evidence.to_json_value()),
            ("execution-decision-v1.schema.json", evidence.decision.to_json_value()),
        )
        for name, value in pairs:
            schema = json.loads((ROOT / "schemas" / name).read_text())
            self.assertEqual(set(value), set(schema["properties"]), msg=name)


if __name__ == "__main__":
    unittest.main()
