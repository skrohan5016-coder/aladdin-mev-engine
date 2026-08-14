from __future__ import annotations

import unittest

from aladdin_mev_engine.domain import ChainHealth
from aladdin_mev_engine.profit import CostBreakdown, ProfitPolicy, ProfitReason, assess_profit


def costs(**overrides: int) -> CostBreakdown:
    values = {
        "gross_profit": 10_000,
        "execution_gas_cost": 1_000,
        "l1_data_fee": 200,
        "operator_fee": 0,
        "flash_loan_fee": 300,
        "inclusion_bid": 1_000,
        "slippage_reserve": 400,
        "stale_state_reserve": 200,
        "failure_risk_reserve": 300,
        "infrastructure_cost": 100,
        "inventory_hedge_cost": 0,
    }
    values.update(overrides)
    return CostBreakdown(**values)


class ProfitFirewallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = ProfitPolicy(
            policy_id="f0-test-policy",
            minimum_absolute_profit=1_000,
            minimum_return_bps=100,
            maximum_bid_fraction_bps=2_500,
            maximum_state_age_ms=500,
        )

    def assess(self, value: CostBreakdown, **overrides: object):
        arguments = {
            "capital_at_risk": 100_000,
            "state_age_ms": 100,
            "simulations_agree": True,
            "chain_health": ChainHealth.HEALTHY,
            "risk_budget_available": True,
        }
        arguments.update(overrides)
        return assess_profit(value, self.policy, **arguments)

    def test_conservative_candidate_is_approved(self) -> None:
        result = self.assess(costs())
        self.assertTrue(result.approved)
        self.assertEqual(result.conservative_net_profit, 6_500)
        self.assertEqual(result.reasons, ())

    def test_bid_is_capped_against_pre_bid_surplus(self) -> None:
        result = self.assess(costs(inclusion_bid=2_000))
        self.assertFalse(result.approved)
        self.assertIn(ProfitReason.BID_EXCEEDS_POLICY, result.reasons)

    def test_simulation_disagreement_and_stale_state_fail_closed(self) -> None:
        result = self.assess(costs(), simulations_agree=False, state_age_ms=501)
        self.assertFalse(result.approved)
        self.assertIn(ProfitReason.SIMULATION_DISAGREEMENT, result.reasons)
        self.assertIn(ProfitReason.STATE_TOO_OLD, result.reasons)

    def test_unknown_health_is_not_healthy(self) -> None:
        result = self.assess(costs(), chain_health=ChainHealth.UNKNOWN)
        self.assertIn(ProfitReason.CHAIN_UNHEALTHY, result.reasons)

    def test_required_return_uses_integer_cross_multiplication(self) -> None:
        restrictive = ProfitPolicy(
            policy_id="return-test",
            minimum_absolute_profit=0,
            minimum_return_bps=1_000,
            maximum_bid_fraction_bps=10_000,
            maximum_state_age_ms=500,
        )
        result = assess_profit(
            costs(),
            restrictive,
            capital_at_risk=100_000,
            state_age_ms=0,
            simulations_agree=True,
            chain_health=ChainHealth.HEALTHY,
            risk_budget_available=True,
        )
        self.assertIn(ProfitReason.BELOW_REQUIRED_RETURN, result.reasons)

    def test_return_policy_may_exceed_one_hundred_percent(self) -> None:
        policy = ProfitPolicy("high-return", 0, 20_000, 10_000, 500)
        self.assertEqual(policy.minimum_return_bps, 20_000)

    def test_negative_or_boolean_amounts_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            costs(gross_profit=-1)
        with self.assertRaises(ValueError):
            costs(gross_profit=True)


if __name__ == "__main__":
    unittest.main()
