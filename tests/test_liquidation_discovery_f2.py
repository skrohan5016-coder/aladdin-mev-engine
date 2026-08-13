from __future__ import annotations

import unittest

from aladdin_mev_engine.domain import Chain, ChainHealth, StateReference
from aladdin_mev_engine.liquidation import (
    DiscoveryReason,
    LiquidationCandidate,
    LiquidationSnapshot,
    discover_liquidation,
)
from aladdin_mev_engine.liquidation_contracts import WAD, LiquidationProtocol
from aladdin_mev_engine.profit import CostBreakdown, ProfitPolicy, ProfitReason, assess_profit


ADDR = {
    "deployment": "0x1111111111111111111111111111111111111111",
    "borrower": "0x2222222222222222222222222222222222222222",
    "debt": "0x3333333333333333333333333333333333333333",
    "collateral": "0x4444444444444444444444444444444444444444",
}


def state(chain: Chain = Chain.ETHEREUM) -> StateReference:
    return StateReference(
        chain=chain,
        sequence_number=42,
        sequence_hash="0xabc",
        observed_at_unix_ms=1_786_579_200_000,
        state_digest="a" * 64,
    )


def snapshot(**overrides: object) -> LiquidationSnapshot:
    values: dict[str, object] = {
        "protocol": LiquidationProtocol.AAVE_V3,
        "chain": Chain.ETHEREUM,
        "deployment_address": ADDR["deployment"],
        "deployment_evidence_sha256": "b" * 64,
        "market_id": "pool-main-debt-collateral",
        "borrower": ADDR["borrower"],
        "debt_asset": ADDR["debt"],
        "collateral_asset": ADDR["collateral"],
        "state_reference": state(),
        "observation_digests": ("c" * 64, "d" * 64),
        "metric_numerator": WAD - 1,
        "metric_denominator": WAD,
        "repay_amount": 100_000,
        "seize_amount": 106_000,
        "valuation_unit": "usd-8",
        "repay_value": 100_000,
        "seize_value": 106_000,
        "valuation_evidence_sha256": "e" * 64,
    }
    values.update(overrides)
    return LiquidationSnapshot(**values)


class LiquidationDiscoveryF2Tests(unittest.TestCase):
    def test_liquidatable_positive_edge_emits_deterministic_candidate(self) -> None:
        decision = discover_liquidation(snapshot())
        self.assertIs(decision.reason, DiscoveryReason.CANDIDATE)
        candidate = decision.candidate
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.gross_profit, 6_000)
        self.assertEqual(candidate.capital_at_risk, 100_000)
        self.assertTrue(candidate.opportunity_id.startswith("liq-"))
        repeated = discover_liquidation(snapshot()).candidate
        assert repeated is not None
        self.assertEqual(candidate.opportunity_id, repeated.opportunity_id)
        self.assertEqual(decision.to_json_value()["execution_authority"], "none")

    def test_aave_threshold_equality_is_not_a_candidate(self) -> None:
        decision = discover_liquidation(snapshot(metric_numerator=WAD))
        self.assertIs(decision.reason, DiscoveryReason.NOT_LIQUIDATABLE)
        self.assertIsNone(decision.candidate)

    def test_morpho_uses_source_exact_strict_above_boundary(self) -> None:
        base = {
            "protocol": LiquidationProtocol.MORPHO_BLUE,
            "metric_numerator": 101,
            "metric_denominator": 100,
        }
        decision = discover_liquidation(snapshot(**base))
        self.assertIs(decision.reason, DiscoveryReason.CANDIDATE)
        equal = discover_liquidation(snapshot(**{**base, "metric_numerator": 100}))
        self.assertIs(equal.reason, DiscoveryReason.NOT_LIQUIDATABLE)

    def test_non_positive_same_unit_edge_is_rejected_before_candidate_creation(self) -> None:
        decision = discover_liquidation(snapshot(seize_value=100_000))
        self.assertIs(decision.reason, DiscoveryReason.NON_POSITIVE_GROSS_EDGE)
        self.assertIsNone(decision.candidate)
        with self.assertRaises(ValueError):
            LiquidationCandidate(decision.snapshot)

    def test_state_chain_mismatch_and_solana_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            snapshot(chain=Chain.BASE, state_reference=state(Chain.ETHEREUM))
        with self.assertRaises(ValueError):
            snapshot(chain=Chain.SOLANA, state_reference=state(Chain.SOLANA))

    def test_addresses_and_observation_digest_set_are_canonical(self) -> None:
        with self.assertRaises(ValueError):
            snapshot(borrower=ADDR["borrower"].upper())
        with self.assertRaises(ValueError):
            snapshot(observation_digests=("d" * 64, "c" * 64))
        with self.assertRaises(ValueError):
            snapshot(observation_digests=("c" * 64, "c" * 64))
        with self.assertRaises(ValueError):
            snapshot(observation_digests=())

    def test_candidate_identity_binds_state_quote_and_mechanism_evidence(self) -> None:
        first = discover_liquidation(snapshot()).candidate
        second = discover_liquidation(snapshot(valuation_evidence_sha256="f" * 64)).candidate
        third = discover_liquidation(snapshot(metric_numerator=WAD - 2)).candidate
        assert first is not None and second is not None and third is not None
        self.assertNotEqual(first.opportunity_id, second.opportunity_id)
        self.assertNotEqual(first.opportunity_id, third.opportunity_id)

    def test_json_money_and_metrics_are_decimal_strings(self) -> None:
        candidate = discover_liquidation(snapshot()).candidate
        assert candidate is not None
        value = candidate.to_json_value()
        for field in (
            "metric_numerator",
            "metric_denominator",
            "repay_amount",
            "seize_amount",
            "repay_value",
            "seize_value",
            "gross_profit",
            "capital_at_risk",
        ):
            self.assertIs(type(value[field]), str)
            self.assertRegex(value[field], r"^(0|[1-9][0-9]*)$")

    def test_candidate_is_only_gross_edge_and_profit_firewall_still_can_reject(self) -> None:
        candidate = discover_liquidation(snapshot()).candidate
        assert candidate is not None
        costs = CostBreakdown(
            gross_profit=candidate.gross_profit,
            execution_gas_cost=5_000,
            l1_data_fee=1_000,
            flash_loan_fee=500,
            inclusion_bid=500,
            slippage_reserve=500,
            stale_state_reserve=500,
            failure_risk_reserve=500,
            infrastructure_cost=100,
            inventory_hedge_cost=0,
        )
        assessment = assess_profit(
            costs,
            ProfitPolicy("f2-regression", 1, 1, 10_000, 1_000),
            capital_at_risk=candidate.capital_at_risk,
            state_age_ms=0,
            simulations_agree=True,
            chain_health=ChainHealth.HEALTHY,
            risk_budget_available=True,
        )
        self.assertFalse(assessment.approved)
        self.assertIn(ProfitReason.BELOW_ABSOLUTE_MINIMUM, assessment.reasons)

    def test_boolean_and_zero_action_amounts_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            snapshot(repay_amount=True)
        with self.assertRaises(ValueError):
            snapshot(repay_amount=0)
        with self.assertRaises(ValueError):
            snapshot(repay_value=0)


if __name__ == "__main__":
    unittest.main()
