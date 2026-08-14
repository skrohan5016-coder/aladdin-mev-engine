from __future__ import annotations

from dataclasses import replace
import random
import unittest

from aladdin_mev_engine.assets import (
    AssetAmount,
    AssetId,
    ConservativeValuationRate,
    ValuationBook,
)
from aladdin_mev_engine.canonical import canonical_sha256
from aladdin_mev_engine.context_evidence import ChainHealthEvidence, RiskBudgetEvidence
from aladdin_mev_engine.constant_product import MAX_UINT256
from aladdin_mev_engine.cost_evidence import (
    ConservativeNetProfitEvidence,
    Eip1559CostEnvelope,
    ExecutionCostEnvelope,
    ReserveCostCategory,
    ReserveCostComponent,
    RouteSimulationResult,
    dual_route_simulations_agree,
)
from aladdin_mev_engine.domain import Chain, ChainHealth
from aladdin_mev_engine.profit import ProfitPolicy
from aladdin_mev_engine.risk import RiskLedger, RiskLimits

from f4_helpers import (
    CHAIN_HEALTH_SOURCE,
    ENGINE_A,
    ENVIRONMENT,
    POST_STATE,
    RISK_SOURCE,
    SIMULATION_SOURCE_A,
    SOURCE_B,
    TOKEN_DELTAS,
    chain_health_context,
    cost_envelope,
    execution_plan,
    net_evidence,
    reserve_components,
    risk_budget_context,
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
        self.assertEqual(len(envelope.required_valuation_pair_sha256), 1)
        self.assertEqual(
            envelope.valid_until_unix_ms,
            min(
                envelope.plan.funding.valid_until_unix_ms,
                envelope.fee_envelope.valid_until_unix_ms,
                *(item.valid_until_unix_ms for item in envelope.reserve_components),
                *(item.valid_until_unix_ms for item in envelope.valuation_book.rates),
            ),
        )
        self.assertFalse(envelope.to_json_value()["execution_eligible"])
        self.assertEqual(
            envelope.to_json_value()["cost_completeness"],
            "complete-recorded-upper-bound-no-inclusion-guarantee",
        )

    def test_missing_duplicate_expired_or_wrong_chain_component_fails_closed(self) -> None:
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
        cross_chain = replace(
            components[0],
            amount=AssetAmount(AssetId.native(Chain.BASE), 1),
        )
        with self.assertRaisesRegex(ValueError, "chain"):
            ExecutionCostEnvelope(
                plan,
                base_envelope.fee_envelope,
                (cross_chain, *components[1:]),
                base_envelope.valuation_book,
                base_envelope.created_at_unix_ms,
            )

    def test_valuation_book_must_equal_exact_required_directional_pairs(self) -> None:
        plan = execution_plan()
        base_envelope = cost_envelope(plan)
        with self.assertRaisesRegex(ValueError, "exact required"):
            ExecutionCostEnvelope(
                plan,
                base_envelope.fee_envelope,
                base_envelope.reserve_components,
                ValuationBook(()),
                base_envelope.created_at_unix_ms,
            )
        unrelated_asset = AssetId.erc20(plan.opportunity.universe.chain, bytes.fromhex("ef" * 20))
        unrelated = ConservativeValuationRate(
            "unused",
            unrelated_asset,
            plan.base_asset,
            1,
            1,
            plan.created_at_unix_ms,
            base_envelope.valid_until_unix_ms,
            "de" * 32,
        )
        with self.assertRaisesRegex(ValueError, "exact required"):
            ExecutionCostEnvelope(
                plan,
                base_envelope.fee_envelope,
                base_envelope.reserve_components,
                ValuationBook((*base_envelope.valuation_book.rates, unrelated)),
                base_envelope.created_at_unix_ms,
            )

    def test_simulations_require_distinct_implementation_and_source_authority(self) -> None:
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
                (
                    rows[0],
                    replace(
                        rows[1],
                        engine_implementation_sha256=rows[0].engine_implementation_sha256,
                    ),
                )
            )
        )
        self.assertFalse(
            dual_route_simulations_agree(
                (
                    rows[0],
                    replace(rows[1], result_source_sha256=rows[0].result_source_sha256),
                )
            )
        )
        self.assertFalse(
            dual_route_simulations_agree(
                (rows[0], replace(rows[1], environment_sha256="ab" * 32))
            )
        )
        self.assertFalse(
            dual_route_simulations_agree(
                (rows[0], replace(rows[1], output_amount=rows[1].output_amount + 1))
            )
        )
        failed = RouteSimulationResult(
            engine_id="failed",
            engine_implementation_sha256=ENGINE_A,
            environment_sha256=ENVIRONMENT,
            result_source_sha256=SIMULATION_SOURCE_A,
            state_reference_sha256=canonical_sha256(
                plan.opportunity.universe.state_reference.to_json_value()
            ),
            success=False,
            opportunity_sha256=plan.opportunity.digest,
            execution_plan_sha256=plan.digest,
            gas_units=0,
            output_amount=0,
            token_deltas_sha256=TOKEN_DELTAS,
            post_state_sha256=POST_STATE,
            observed_at_unix_ms=plan.created_at_unix_ms + 1,
            valid_until_unix_ms=plan.created_at_unix_ms + 100,
            error_code="revert",
        )
        self.assertFalse(
            dual_route_simulations_agree(
                (
                    failed,
                    replace(
                        failed,
                        engine_id="failed-2",
                        engine_implementation_sha256="12" * 32,
                        result_source_sha256="13" * 32,
                    ),
                )
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
        self.assertEqual(
            value["chain_health"],
            value["chain_health_evidence"]["health"],
        )
        self.assertEqual(
            value["risk_budget_available"],
            value["risk_budget_evidence"]["allowed"],
        )

    def test_gas_output_health_risk_and_state_age_fail_closed(self) -> None:
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
            chain_health_context(envelope.plan),
            risk_budget_context(envelope),
            envelope.created_at_unix_ms + 3,
        )
        self.assertFalse(stale.decision.approved)

    def test_all_cost_simulation_and_context_inputs_are_fresh_at_final_time(self) -> None:
        envelope = cost_envelope(validity_ms=5)
        too_late = envelope.valid_until_unix_ms + 1
        with self.assertRaisesRegex(ValueError, "cost envelope inputs"):
            net_evidence(envelope, created_at_unix_ms=too_late)

        rows = simulations(envelope.plan, validity_ms=0)
        with self.assertRaisesRegex(ValueError, "simulation is not valid"):
            net_evidence(
                envelope,
                simulation_rows=rows,
                created_at_unix_ms=rows[0].valid_until_unix_ms + 1,
            )
        before_plan = tuple(
            replace(
                item,
                observed_at_unix_ms=envelope.plan.created_at_unix_ms - 1,
                valid_until_unix_ms=envelope.plan.created_at_unix_ms + 100,
            )
            for item in simulations(envelope.plan)
        )
        with self.assertRaisesRegex(ValueError, "cannot precede"):
            net_evidence(envelope, simulation_rows=before_plan)

        final_time = envelope.created_at_unix_ms + 3
        expired_health = chain_health_context(
            envelope.plan,
            observed_at_unix_ms=envelope.created_at_unix_ms,
            valid_until_unix_ms=final_time - 1,
        )
        with self.assertRaisesRegex(ValueError, "chain-health evidence"):
            net_evidence(
                envelope,
                health_evidence=expired_health,
                created_at_unix_ms=final_time,
            )
        expired_risk = risk_budget_context(
            envelope,
            observed_at_unix_ms=envelope.created_at_unix_ms,
            valid_until_unix_ms=final_time - 1,
        )
        with self.assertRaisesRegex(ValueError, "risk-budget evidence"):
            net_evidence(
                envelope,
                risk_evidence=expired_risk,
                created_at_unix_ms=final_time,
            )

    def test_context_evidence_binds_chain_plan_cost_and_notional(self) -> None:
        envelope = cost_envelope()
        wrong_chain = ChainHealthEvidence(
            Chain.BASE,
            ChainHealth.HEALTHY,
            envelope.created_at_unix_ms,
            envelope.valid_until_unix_ms,
            CHAIN_HEALTH_SOURCE,
        )
        with self.assertRaisesRegex(ValueError, "chain-health"):
            net_evidence(envelope, health_evidence=wrong_chain)

        risk = risk_budget_context(envelope)
        with self.assertRaisesRegex(ValueError, "execution plan"):
            net_evidence(
                envelope,
                risk_evidence=replace(risk, execution_plan_sha256="00" * 32),
            )
        with self.assertRaisesRegex(ValueError, "execution cost"):
            net_evidence(
                envelope,
                risk_evidence=replace(
                    risk,
                    requested_execution_cost=risk.requested_execution_cost + 1,
                ),
            )
        with self.assertRaisesRegex(ValueError, "notional"):
            net_evidence(
                envelope,
                risk_evidence=replace(risk, requested_notional=risk.requested_notional + 1),
            )

    def test_risk_budget_is_recomputed_from_snapshot_and_can_be_captured_from_ledger(self) -> None:
        envelope = cost_envelope()
        total = envelope.costs.total_cost
        notional = envelope.plan.opportunity.capital_at_risk
        limits = RiskLimits(total + 1, total - 1, total + 1, 1, notional + 1)
        denied = RiskBudgetEvidence(
            "policy",
            envelope.plan.digest,
            limits,
            0,
            0,
            0,
            total,
            notional,
            envelope.created_at_unix_ms,
            envelope.valid_until_unix_ms,
            RISK_SOURCE,
        )
        self.assertFalse(denied.allowed)
        self.assertIn("single-execution-cost-limit", denied.reasons)

        ledger = RiskLedger(
            RiskLimits(total + 10, total + 10, total + 10, 2, notional + 10)
        )
        captured = RiskBudgetEvidence.capture(
            risk_policy_id="captured",
            execution_plan_sha256=envelope.plan.digest,
            ledger=ledger,
            requested_execution_cost=total,
            requested_notional=notional,
            observed_at_unix_ms=envelope.created_at_unix_ms,
            valid_until_unix_ms=envelope.valid_until_unix_ms,
            source_sha256=RISK_SOURCE,
        )
        self.assertTrue(captured.allowed)


    def test_risk_budget_arithmetic_and_observation_order_fail_closed(self) -> None:
        envelope = cost_envelope()
        notional = envelope.plan.opportunity.capital_at_risk
        wide_limits = RiskLimits(
            MAX_UINT256,
            MAX_UINT256,
            MAX_UINT256,
            MAX_UINT256,
            MAX_UINT256,
        )
        with self.assertRaisesRegex(ValueError, "pending execution cost exceeds uint256"):
            RiskBudgetEvidence(
                "overflow",
                envelope.plan.digest,
                wide_limits,
                0,
                MAX_UINT256,
                0,
                1,
                notional,
                envelope.created_at_unix_ms,
                envelope.valid_until_unix_ms,
                RISK_SOURCE,
            )
        with self.assertRaisesRegex(ValueError, "concurrent candidate count exceeds uint256"):
            RiskBudgetEvidence(
                "overflow",
                envelope.plan.digest,
                wide_limits,
                0,
                0,
                MAX_UINT256,
                0,
                notional,
                envelope.created_at_unix_ms,
                envelope.valid_until_unix_ms,
                RISK_SOURCE,
            )

        early = risk_budget_context(
            envelope,
            observed_at_unix_ms=envelope.plan.created_at_unix_ms,
            valid_until_unix_ms=envelope.valid_until_unix_ms,
        )
        with self.assertRaisesRegex(ValueError, "cannot precede the execution cost envelope"):
            net_evidence(envelope, risk_evidence=early)

    def test_f4_profit_policy_fields_are_uint256_closed(self) -> None:
        envelope = cost_envelope()
        policy = ProfitPolicy("oversized", MAX_UINT256 + 1, 0, 10_000, 1_000_000)
        with self.assertRaisesRegex(ValueError, "profit_policy.minimum_absolute_profit"):
            ConservativeNetProfitEvidence(
                envelope,
                simulations(envelope.plan),
                policy,
                chain_health_context(envelope.plan),
                risk_budget_context(envelope),
                envelope.created_at_unix_ms + 3,
            )

    def test_simulation_order_is_canonical(self) -> None:
        envelope = cost_envelope()
        rows = simulations(envelope.plan)
        forward = net_evidence(envelope, simulation_rows=rows)
        reverse = net_evidence(envelope, simulation_rows=tuple(reversed(rows)))
        self.assertEqual(forward.evidence_id, reverse.evidence_id)
        self.assertEqual(forward.digest, reverse.digest)
        self.assertEqual(
            tuple(item.engine_id for item in forward.simulations),
            tuple(sorted(item.engine_id for item in rows)),
        )

    def test_funding_must_still_be_valid_when_cost_envelope_is_created(self) -> None:
        plan = execution_plan()
        expired_funding = replace(
            plan.funding,
            valid_until_unix_ms=plan.created_at_unix_ms,
        )
        expired_plan = replace(plan, funding=expired_funding)
        with self.assertRaisesRegex(ValueError, "funding plan"):
            cost_envelope(expired_plan)

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
