from __future__ import annotations

import unittest

from aladdin_mev_engine.domain import Chain, ChainHealth, StateReference, Strategy
from aladdin_mev_engine.evidence import EvidenceRecord, SimulationResult, dual_simulations_agree
from aladdin_mev_engine.profit import CostBreakdown, ProfitReason, ProfitPolicy

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


class EvidenceTests(unittest.TestCase):
    def simulation(self, engine_id: str, *, output: int = 100) -> SimulationResult:
        return SimulationResult(
            engine_id=engine_id,
            success=True,
            gas_units=21_000,
            output_amount=output,
            post_state_digest=DIGEST_A,
        )

    def failed_simulation(self, engine_id: str) -> SimulationResult:
        return SimulationResult(
            engine_id=engine_id,
            success=False,
            gas_units=21_000,
            output_amount=0,
            post_state_digest=DIGEST_A,
            error_code="reverted",
        )

    def costs(self) -> CostBreakdown:
        return CostBreakdown(
            gross_profit=1_000,
            execution_gas_cost=100,
            l1_data_fee=0,
            flash_loan_fee=0,
            inclusion_bid=0,
            slippage_reserve=100,
            stale_state_reserve=100,
            failure_risk_reserve=100,
            infrastructure_cost=100,
            inventory_hedge_cost=0,
        )

    def policy(self) -> ProfitPolicy:
        return ProfitPolicy("evidence-test", 1, 0, 10_000, 1_000)

    def record(self, simulations: tuple[SimulationResult, ...]) -> EvidenceRecord:
        return EvidenceRecord(
            opportunity_id="opportunity-1",
            strategy=Strategy.ATOMIC_DEX_ARBITRAGE,
            state_reference=StateReference(
                chain=Chain.ETHEREUM,
                sequence_number=1,
                sequence_hash="0x01",
                observed_at_unix_ms=1_000,
                state_digest=DIGEST_B,
            ),
            capital_at_risk=0,
            costs=self.costs(),
            simulations=simulations,
            profit_policy=self.policy(),
            chain_health=ChainHealth.HEALTHY,
            risk_budget_available=True,
            created_at_unix_ms=1_001,
        )

    def test_independent_simulators_must_match_and_have_unique_ids(self) -> None:
        matching = (self.simulation("local"), self.simulation("remote"))
        mismatching = (self.simulation("local"), self.simulation("remote", output=101))
        duplicate = (self.simulation("local"), self.simulation("local"))
        self.assertTrue(dual_simulations_agree(matching))
        self.assertFalse(dual_simulations_agree(mismatching))
        self.assertFalse(dual_simulations_agree(duplicate))

    def test_record_recomputes_approved_decision_and_digest(self) -> None:
        record = self.record((self.simulation("local"), self.simulation("remote")))
        self.assertTrue(record.decision.approved)
        self.assertEqual(record.decision.conservative_net_profit, 500)
        self.assertEqual(record.digest, record.digest)
        self.assertEqual(len(record.digest), 64)
        self.assertEqual(record.to_json_value()["decision"]["schema"], "aladdin-mev-execution-decision/v1")

    def test_disagreement_is_bound_into_recomputed_rejection(self) -> None:
        record = self.record((self.simulation("local"), self.simulation("remote", output=101)))
        self.assertFalse(record.decision.approved)
        self.assertIn(ProfitReason.SIMULATION_DISAGREEMENT, record.decision.reasons)

    def test_duplicate_simulator_identity_is_rejected_by_decision(self) -> None:
        record = self.record((self.simulation("local"), self.simulation("local")))
        self.assertFalse(record.decision.approved)
        self.assertIn(ProfitReason.SIMULATION_DISAGREEMENT, record.decision.reasons)

    def test_matching_failed_simulations_can_never_approve(self) -> None:
        failures = (self.failed_simulation("local"), self.failed_simulation("remote"))
        self.assertFalse(dual_simulations_agree(failures))
        record = self.record(failures)
        self.assertFalse(record.decision.approved)
        self.assertIn(ProfitReason.SIMULATION_DISAGREEMENT, record.decision.reasons)

    def test_simulation_count_matches_schema_ceiling(self) -> None:
        simulations = tuple(self.simulation(f"engine-{index}") for index in range(9))
        with self.assertRaisesRegex(ValueError, "at most eight"):
            self.record(simulations)

    def test_creation_time_before_observation_fails(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot precede"):
            EvidenceRecord(
                opportunity_id="opportunity-2",
                strategy=Strategy.LIQUIDATION,
                state_reference=StateReference(
                    chain=Chain.BASE,
                    sequence_number=2,
                    sequence_hash="0x02",
                    observed_at_unix_ms=2_000,
                    state_digest=DIGEST_B,
                ),
                capital_at_risk=0,
                costs=self.costs(),
                simulations=(self.simulation("local"), self.simulation("remote")),
                profit_policy=self.policy(),
                chain_health=ChainHealth.HEALTHY,
                risk_budget_available=True,
                created_at_unix_ms=1_999,
            )


if __name__ == "__main__":
    unittest.main()
