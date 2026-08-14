from __future__ import annotations

from dataclasses import replace
import random
import unittest

from aladdin_mev_engine.assets import AssetAmount, AssetId, ValuationBook
from aladdin_mev_engine.cost_evidence import (
    ConservativeNetProfitEvidence,
    Eip1559CostEnvelope,
    ExecutionCostEnvelope,
    ReserveCostComponent,
    RouteSimulationResult,
    dual_route_simulations_agree,
)
from aladdin_mev_engine.domain import Chain, ChainHealth
from aladdin_mev_engine.profit import ProfitPolicy

from f4_helpers import (
    POST_STATE,
    TOKEN_DELTAS,
    cost_envelope,
    execution_plan,
    net_evidence,
    reserve_components,
    simulations,
)


class CostAndNetEvidenceF4Tests(unittest.TestCase):
    def test_eip1559_priority_is_not_double_counted(self) -> None:
        native = AssetId.native(Chain.ETHEREUM)
        envelope = Eip1559CostEnvelope(
            Chain.ETHEREUM,
            native,
            100,
            20,
            19,
            0,
            7,
            100,
            200,
            "11" * 32,
        )
        self.assertEqual(envelope.execution_gas_cost_upper_bound, 2_000)
        self.assertEqual(envelope.total_native_upper_bound, 2_007)
        self.assertIn("not-added-again", envelope.to_json_value()["priority_fee_semantics"])
        with self.assertRaisesRegex(ValueError, "priority"):
            replace(envelope, max_priority_fee_per_gas=21)
        with self.assertRaisesRegex(ValueError, "L1 data"):
            replace(envelope, l1_data_fee_upper_bound=1)

    def test_base_requires_explicit_separate_l1_fee_field(self) -> None:
        native = AssetId.native(Chain.BASE)
        envelope = Eip1559CostEnvelope(
            Chain.BASE,
            native,
            100,
            2,
            1,
            50,
            3,
            100,
            200,
            "22" * 32,
        )
        self.assertEqual(envelope.total_native_upper_bound, 253)

    def test_cost_envelope_derives_every_category_and_uses_ceiling_conversion(self) -> None:
        envelope = cost_envelope(
            native_to_base_numerator=3,
            native_to_base_denominator=2,
            gas_units_upper_bound=5,
            max_fee_per_gas=1,
            direct_inclusion_payment_upper_bound=1,
            reserve_amount=2,
        )
        costs = envelope.costs
        self.assertEqual(costs.gross_profit, envelope.plan.opportunity.gross_profit)
        self.assertEqual(costs.execution_gas_cost, 8)
        self.assertEqual(costs.inclusion_bid, 2)
        self.assertEqual(costs.flash_loan_fee, envelope.plan.funding.fee)
        self.assertEqual(costs.slippage_reserve, 2)
        self.assertFalse(envelope.to_json_value()["execution_eligible"])
        self.assertEqual(
            envelope.to_json_value()["cost_completeness"],
            "complete-recorded-upper-bound-no-inclusion-guarantee",
        )

    def test_missing_duplicate_or_expired_component_fails_closed(self) -> None:
        plan = execution_plan()
        components = reserve_components(plan)
        base_envelope = cost_envelope(plan)
        with self.assertRaisesRegex(ValueError, "every category"):
            ExecutionCostEnvelope(
                plan,
                base_envelope.fee_envelope,
                components[:-1],
                base_envelope.valuation_book,
                base_envelope.created_at_unix_ms,
            )
        duplicate = (*components[:-1], components[0])
        with self.assertRaisesRegex(ValueError, "every category"):
            ExecutionCostEnvelope(
                plan,
                base_envelope.fee_envelope,
                duplicate,
                base_envelope.valuation_book,
                base_envelope.created_at_unix_ms,
            )
        expired = replace(
            components[0],
            valid_until_unix_ms=base_envelope.created_at_unix_ms - 1,
        )
        with self.assertRaisesRegex(ValueError, "not valid"):
            ExecutionCostEnvelope(
                plan,
                base_envelope.fee_envelope,
                (expired, *components[1:]),
                base_envelope.valuation_book,
                base_envelope.created_at_unix_ms,
            )

    def test_native_cost_requires_explicit_directional_valuation(self) -> None:
        plan = execution_plan()
        base_envelope = cost_envelope(plan)
        with self.assertRaisesRegex(ValueError, "absent"):
            ExecutionCostEnvelope(
                plan,
                base_envelope.fee_envelope,
                reserve_components(plan),
                ValuationBook(()),
                base_envelope.created_at_unix_ms,
            )

    def test_simulations_must_be_independent_exact_and_plan_bound(self) -> None:
        plan = execution_plan()
        rows = simulations(plan)
        self.assertTrue(dual_route_simulations_agree(rows))
        self.assertFalse(
            dual_route_simulations_agree(
                (rows[0], replace(rows[1], engine_id=rows[0].engine_id))
            )
        )
        self.assertFalse(
            dual_route_simulations_agree(
                (rows[0], replace(rows[1], output_amount=rows[1].output_amount + 1))
            )
        )
        failed = RouteSimulationResult(
            engine_id="failed",
            success=False,
            opportunity_sha256=plan.opportunity.digest,
            execution_plan_sha256=plan.digest,
            gas_units=0,
            output_amount=0,
            token_deltas_sha256=TOKEN_DELTAS,
            post_state_sha256=POST_STATE,
            error_code="revert",
        )
        self.assertFalse(
            dual_route_simulations_agree(
                (failed, replace(failed, engine_id="failed-2"))
            )
        )

    def test_net_evidence_recomputes_profit_and_never_authorizes_execution(self) -> None:
        evidence = net_evidence()
        expected = evidence.cost_envelope.costs.conservative_net_profit
        self.assertEqual(evidence.decision.conservative_net_profit, expected)
        value = evidence.to_json_value()
        self.assertFalse(value["execution_eligible"])
        self.assertFalse(value["inclusion_guarantee"])
        self.assertEqual(value["signing_authority"], "none")
        self.assertEqual(value["decision_authority"], "shadow-economics-only")

    def test_gas_output_staleness_health_and_risk_fail_closed(self) -> None:
        envelope = cost_envelope(gas_units_upper_bound=100)
        with self.assertRaisesRegex(ValueError, "gas exceeds"):
            net_evidence(
                envelope,
                simulation_rows=simulations(envelope.plan, gas_units=101),
            )
        with self.assertRaisesRegex(ValueError, "output"):
            net_evidence(
                envelope,
                simulation_rows=simulations(envelope.plan, output_delta=1),
            )
        unhealthy = net_evidence(envelope, chain_health=ChainHealth.DEGRADED)
        self.assertFalse(unhealthy.decision.approved)
        unavailable = net_evidence(envelope, risk_budget_available=False)
        self.assertFalse(unavailable.decision.approved)
        stale_policy = ProfitPolicy("stale", 0, 0, 10_000, 0)
        stale = ConservativeNetProfitEvidence(
            envelope,
            simulations(envelope.plan),
            stale_policy,
            ChainHealth.HEALTHY,
            True,
            envelope.created_at_unix_ms + 1,
        )
        self.assertFalse(stale.decision.approved)

    def test_randomized_cost_reconciliation_matches_integer_reference(self) -> None:
        rng = random.Random(0xF4C057)
        for _ in range(100):
            numerator = rng.randint(1, 25)
            denominator = rng.randint(1, 25)
            gas = rng.randint(1, 200)
            max_fee = rng.randint(1, 20)
            inclusion = rng.randint(0, 20)
            reserve = rng.randint(0, 20)
            envelope = cost_envelope(
                native_to_base_numerator=numerator,
                native_to_base_denominator=denominator,
                gas_units_upper_bound=gas,
                max_fee_per_gas=max_fee,
                direct_inclusion_payment_upper_bound=inclusion,
                reserve_amount=reserve,
            )
            ceil = lambda value: (value * numerator + denominator - 1) // denominator
            expected_total = (
                ceil(gas * max_fee)
                + ceil(inclusion)
                + envelope.plan.funding.fee
                + 5 * reserve
            )
            self.assertEqual(envelope.costs.total_cost, expected_total)


if __name__ == "__main__":
    unittest.main()
