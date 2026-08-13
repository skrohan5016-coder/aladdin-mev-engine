from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.domain import Chain, StateReference
from aladdin_mev_engine.liquidation import LiquidationSnapshot, discover_liquidation
from aladdin_mev_engine.liquidation_contracts import (
    LIQUIDATION_MECHANISMS,
    WAD,
    LiquidationProtocol,
)

ROOT = Path(__file__).resolve().parents[1]


def snapshot() -> LiquidationSnapshot:
    return LiquidationSnapshot(
        protocol=LiquidationProtocol.AAVE_V3,
        chain=Chain.ETHEREUM,
        deployment_address="0x1111111111111111111111111111111111111111",
        deployment_evidence_sha256="a" * 64,
        market_id="aave-pool-market",
        borrower="0x2222222222222222222222222222222222222222",
        debt_asset="0x3333333333333333333333333333333333333333",
        collateral_asset="0x4444444444444444444444444444444444444444",
        state_reference=StateReference(Chain.ETHEREUM, 1, "0x01", 2, "b" * 64),
        observation_digests=("c" * 64,),
        metric_numerator=WAD - 1,
        metric_denominator=WAD,
        repay_amount=100,
        seize_amount=106,
        valuation_unit="usd-8",
        repay_value=100,
        seize_value=106,
        valuation_evidence_sha256="d" * 64,
    )


class F2SchemaContractTests(unittest.TestCase):
    def test_snapshot_candidate_and_decision_keys_match_schemas(self) -> None:
        value = snapshot()
        decision = discover_liquidation(value)
        candidate = decision.candidate
        assert candidate is not None
        cases = (
            ("liquidation-snapshot-v1.schema.json", value.to_json_value()),
            ("liquidation-candidate-v1.schema.json", candidate.to_json_value()),
            ("liquidation-discovery-decision-v1.schema.json", decision.to_json_value()),
        )
        for filename, document in cases:
            with self.subTest(filename=filename):
                schema = json.loads((ROOT / "schemas" / filename).read_text())
                self.assertEqual(set(document), set(schema["required"]))

    def test_mechanism_keys_match_schema(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "liquidation-mechanism-v1.schema.json").read_text()
        )
        for mechanism in LIQUIDATION_MECHANISMS.values():
            self.assertEqual(set(mechanism.to_json_value()), set(schema["required"]))

    def test_new_top_level_schemas_are_closed_and_current_draft(self) -> None:
        for path in sorted((ROOT / "schemas").glob("liquidation-*.schema.json")):
            with self.subTest(path=path.name):
                schema = json.loads(path.read_text())
                self.assertIs(schema["additionalProperties"], False)
                self.assertEqual(
                    schema["$schema"],
                    "https://json-schema.org/draft/2020-12/schema",
                )


if __name__ == "__main__":
    unittest.main()
