from __future__ import annotations

import unittest

from aladdin_mev_engine.opportunity import (
    MAX_UINT64,
    AtomicDexOpportunityEvidence,
    OpportunitySearchReport,
)
from aladdin_mev_engine.opportunity_graph import enumerate_simple_cycles
from aladdin_mev_engine.optimizer import OptimizationLimits

from f3_helpers import (
    TOKEN_A,
    TOKEN_B,
    authenticated_universe,
    pool_fixture,
)


def profitable_universe():
    return authenticated_universe(
        (
            pool_fixture(
                address_byte=1,
                token0=TOKEN_A,
                token1=TOKEN_B,
                reserve0=1000,
                reserve1=2000,
            ),
            pool_fixture(
                address_byte=2,
                token0=TOKEN_A,
                token1=TOKEN_B,
                reserve0=1500,
                reserve1=1000,
            ),
        )
    )


class OpportunityF3Tests(unittest.TestCase):
    def test_opportunity_recomputes_complete_positive_exact_gross_math(self) -> None:
        state = profitable_universe()
        route = next(
            item
            for item in enumerate_simple_cycles(state, TOKEN_A)
            if item.legs[0].pool_address == state.pools[0].pool_address
        )
        limits = OptimizationLimits(10_000)
        evidence = AtomicDexOpportunityEvidence(
            state,
            route,
            limits,
            state.observed_at_unix_ms + 1,
        )
        later = AtomicDexOpportunityEvidence(
            state,
            route,
            limits,
            state.observed_at_unix_ms + 999,
        )
        self.assertEqual(evidence.opportunity_id, later.opportunity_id)
        self.assertNotEqual(evidence.digest, later.digest)
        self.assertEqual(
            evidence.route_quote.gross_profit,
            evidence.optimization.gross_profit,
        )
        value = evidence.to_json_value()
        self.assertFalse(value["execution_eligible"])
        self.assertEqual(
            value["cost_completeness"],
            "gross-only-no-gas-no-inclusion-no-funding",
        )

    def test_nonpositive_or_incomplete_route_cannot_authorize_opportunity(self) -> None:
        state = authenticated_universe(
            (
                pool_fixture(
                    address_byte=1,
                    token0=TOKEN_A,
                    token1=TOKEN_B,
                    reserve0=1000,
                    reserve1=1000,
                ),
                pool_fixture(
                    address_byte=2,
                    token0=TOKEN_A,
                    token1=TOKEN_B,
                    reserve0=1000,
                    reserve1=1000,
                ),
            )
        )
        route = enumerate_simple_cycles(state, TOKEN_A)[0]
        with self.assertRaisesRegex(ValueError, "positive"):
            AtomicDexOpportunityEvidence(
                state,
                route,
                OptimizationLimits(1000),
                state.observed_at_unix_ms,
            )

    def test_search_report_is_deterministic_and_never_execution_eligible(self) -> None:
        state = profitable_universe()
        report = OpportunitySearchReport(
            state,
            TOKEN_A,
            4,
            OptimizationLimits(10_000),
            state.observed_at_unix_ms + 1,
        )
        repeat = OpportunitySearchReport(
            state,
            TOKEN_A,
            4,
            OptimizationLimits(10_000),
            state.observed_at_unix_ms + 1,
        )
        self.assertEqual(report.digest, repeat.digest)
        self.assertTrue(report.complete)
        self.assertEqual(report.positive_route_count, 1)
        self.assertEqual(len(report.opportunities()), 1)
        self.assertFalse(report.to_json_value()["execution_eligible"])

    def test_report_rejects_multiplicative_search_work_exhaustion(self) -> None:
        state = authenticated_universe(
            (
                pool_fixture(
                    address_byte=1,
                    token0=TOKEN_A,
                    token1=TOKEN_B,
                    reserve0=1000,
                    reserve1=1200,
                ),
                pool_fixture(
                    address_byte=2,
                    token0=TOKEN_A,
                    token1=TOKEN_B,
                    reserve0=1100,
                    reserve1=1000,
                ),
                pool_fixture(
                    address_byte=3,
                    token0=TOKEN_A,
                    token1=TOKEN_B,
                    reserve0=900,
                    reserve1=1300,
                ),
            )
        )
        with self.assertRaisesRegex(ValueError, "search work"):
            OpportunitySearchReport(
                state,
                TOKEN_A,
                2,
                OptimizationLimits(1000, 30_000, 32),
                state.observed_at_unix_ms + 1,
            )

    def test_evidence_timestamps_are_uint64_bounded(self) -> None:
        state = profitable_universe()
        route = enumerate_simple_cycles(state, TOKEN_A)[0]
        with self.assertRaisesRegex(ValueError, "64-bit"):
            AtomicDexOpportunityEvidence(
                state,
                route,
                OptimizationLimits(1000),
                MAX_UINT64 + 1,
            )


if __name__ == "__main__":
    unittest.main()
