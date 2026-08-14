from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.domain import Chain, ChainHealth, StateReference, Strategy
from aladdin_mev_engine.evidence import EvidenceRecord, SimulationResult
from aladdin_mev_engine.profit import CostBreakdown, ProfitPolicy

ROOT = Path(__file__).resolve().parents[1]


class SchemaContractTests(unittest.TestCase):
    def test_evidence_output_keys_match_governed_schema(self) -> None:
        schema = json.loads((ROOT / "schemas" / "simulation-evidence-v1.schema.json").read_text())
        record = EvidenceRecord(
            opportunity_id="schema-contract",
            strategy=Strategy.ATOMIC_DEX_ARBITRAGE,
            state_reference=StateReference(Chain.ETHEREUM, 1, "0x01", 10, "a" * 64),
            capital_at_risk=0,
            costs=CostBreakdown(100, 10, 0, 0, 0, 0, 10, 10, 10, 10, 0),
            simulations=(
                SimulationResult("a", True, 1, 1, "b" * 64),
                SimulationResult("b", True, 1, 1, "b" * 64),
            ),
            profit_policy=ProfitPolicy("schema", 1, 0, 10_000, 100),
            chain_health=ChainHealth.HEALTHY,
            risk_budget_available=True,
            created_at_unix_ms=11,
        )
        value = record.to_json_value()
        self.assertEqual(set(value), set(schema["required"]))
        self.assertEqual(set(value["costs"]), set(schema["$defs"]["costs"]["required"]))
        self.assertEqual(set(value["decision"]), set(schema["$defs"]["decision"]["required"]))
        self.assertEqual(set(value["profit_policy"]), set(schema["$defs"]["profitPolicy"]["required"]))
        self.assertEqual(set(value["state_reference"]), set(schema["$defs"]["stateReference"]["required"]))
        for simulation in value["simulations"]:
            self.assertEqual(set(simulation), set(schema["$defs"]["simulation"]["required"]))

    def test_all_top_level_schemas_are_closed(self) -> None:
        for path in sorted((ROOT / "schemas").glob("*.json")):
            with self.subTest(path=path.name):
                schema = json.loads(path.read_text())
                self.assertIs(schema["additionalProperties"], False)
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")


if __name__ == "__main__":
    unittest.main()
