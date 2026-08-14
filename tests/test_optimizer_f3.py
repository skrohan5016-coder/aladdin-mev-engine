from __future__ import annotations

import random
import unittest

from aladdin_mev_engine.constant_product import MAX_UINT256
from aladdin_mev_engine.opportunity_graph import enumerate_simple_cycles
from aladdin_mev_engine.optimizer import (
    OptimizationLimits,
    OptimizationResult,
    OptimizationStatus,
    _governed_interval_continuous_upper,
    _interval_continuous_upper,
    optimize_route,
)

from f3_helpers import (
    TOKEN_A,
    TOKEN_B,
    TOKEN_C,
    TOKEN_D,
    authenticated_universe,
    pool_fixture,
)


class OptimizerF3Tests(unittest.TestCase):
    def test_limits_reject_uint256_and_combined_work_overflow(self) -> None:
        with self.assertRaisesRegex(ValueError, "uint256"):
            OptimizationLimits(MAX_UINT256 + 1)
        with self.assertRaisesRegex(ValueError, "work budget"):
            OptimizationLimits(1000, 1_000_000, 4096)

    def test_status_objects_cannot_claim_inconsistent_authority(self) -> None:
        limits = OptimizationLimits(100)
        with self.assertRaisesRegex(ValueError, "no-valid-input"):
            OptimizationResult(
                route_sha256="00" * 32,
                status=OptimizationStatus.NO_VALID_INPUT,
                complete=True,
                effective_maximum_input=1,
                amount_in=0,
                amount_out=0,
                gross_profit=0,
                evaluated_inputs=0,
                explored_intervals=0,
                pruned_intervals=0,
                continuous_upper_bound=0,
                limits=limits,
            )
        with self.assertRaisesRegex(ValueError, "budget-exhausted"):
            OptimizationResult(
                route_sha256="00" * 32,
                status=OptimizationStatus.BUDGET_EXHAUSTED,
                complete=False,
                effective_maximum_input=100,
                amount_in=0,
                amount_out=0,
                gross_profit=0,
                evaluated_inputs=0,
                explored_intervals=0,
                pruned_intervals=0,
                continuous_upper_bound=1,
                limits=limits,
            )

    def test_exact_optimizer_matches_exhaustive_two_hop_search(self) -> None:
        rng = random.Random(0xA11ADD1)
        for case in range(40):
            state = authenticated_universe(
                (
                    pool_fixture(
                        address_byte=1,
                        token0=TOKEN_A,
                        token1=TOKEN_B,
                        reserve0=rng.randint(50, 5000),
                        reserve1=rng.randint(50, 5000),
                    ),
                    pool_fixture(
                        address_byte=2,
                        token0=TOKEN_A,
                        token1=TOKEN_B,
                        reserve0=rng.randint(50, 5000),
                        reserve1=rng.randint(50, 5000),
                    ),
                )
            )
            for route in enumerate_simple_cycles(state, TOKEN_A):
                result = optimize_route(
                    state,
                    route,
                    OptimizationLimits(300, 50_000, 16),
                )
                expected = max(
                    [(0, 0, 0)]
                    + [
                        (quote.gross_profit, -amount, quote.amount_out)
                        for amount in range(1, 301)
                        for quote in (route.quote_exact_in(state, amount),)
                    ]
                )
                self.assertTrue(result.complete, msg=f"case={case}")
                self.assertEqual(
                    (result.gross_profit, -result.amount_in, result.amount_out),
                    expected,
                )

    def test_three_and_four_hop_routes_match_exhaustive_search(self) -> None:
        rng = random.Random(0xF334)
        for tokens in (
            (TOKEN_A, TOKEN_B, TOKEN_C),
            (TOKEN_A, TOKEN_B, TOKEN_C, TOKEN_D),
        ):
            fixtures = tuple(
                pool_fixture(
                    address_byte=index + 1,
                    token0=tokens[index],
                    token1=tokens[(index + 1) % len(tokens)],
                    reserve0=rng.randint(200, 5000),
                    reserve1=rng.randint(200, 5000),
                )
                for index in range(len(tokens))
            )
            state = authenticated_universe(fixtures)
            routes = [
                route
                for route in enumerate_simple_cycles(
                    state,
                    TOKEN_A,
                    maximum_hops=len(tokens),
                )
                if len(route.legs) == len(tokens)
            ]
            for route in routes:
                result = optimize_route(
                    state,
                    route,
                    OptimizationLimits(200, 50_000, 8),
                )
                expected = max(
                    [(0, 0, 0)]
                    + [
                        (quote.gross_profit, -amount, quote.amount_out)
                        for amount in range(1, 201)
                        for quote in (route.quote_exact_in(state, amount),)
                    ]
                )
                self.assertEqual(
                    (result.gross_profit, -result.amount_in, result.amount_out),
                    expected,
                )

    def test_continuous_interval_bound_never_understates_discrete_profit(self) -> None:
        rng = random.Random(0xF3B0A7D)
        for _ in range(5000):
            a = rng.randint(1, 100_000)
            b = rng.randint(1, 100_000)
            c = rng.randint(1, 10_000)
            lower = rng.randint(1, 100)
            upper = rng.randint(lower, lower + 100)
            exact = max(
                (a * amount) // (b + c * amount) - amount
                for amount in range(lower, upper + 1)
            )
            self.assertGreaterEqual(
                _interval_continuous_upper(a, b, c, lower, upper),
                exact,
            )

    def test_continuous_bound_is_safely_clamped_to_uint256(self) -> None:
        self.assertEqual(
            _governed_interval_continuous_upper(
                MAX_UINT256 * 4,
                1,
                1,
                1,
                1,
            ),
            MAX_UINT256,
        )

    def test_budget_exhaustion_and_no_trade_states_fail_closed(self) -> None:
        state = authenticated_universe(
            (
                pool_fixture(
                    address_byte=1,
                    token0=TOKEN_A,
                    token1=TOKEN_B,
                    reserve0=1_000_000,
                    reserve1=2_000_000,
                ),
                pool_fixture(
                    address_byte=2,
                    token0=TOKEN_A,
                    token1=TOKEN_B,
                    reserve0=1_500_000,
                    reserve1=1_000_000,
                ),
            )
        )
        route = next(
            item
            for item in enumerate_simple_cycles(state, TOKEN_A)
            if item.legs[0].pool_address == state.pools[0].pool_address
        )
        exhausted = optimize_route(
            state,
            route,
            OptimizationLimits(10**30, 1, 1),
        )
        self.assertEqual(exhausted.status, OptimizationStatus.BUDGET_EXHAUSTED)
        self.assertFalse(exhausted.complete)

        balanced = authenticated_universe(
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
        no_edge = optimize_route(
            balanced,
            enumerate_simple_cycles(balanced, TOKEN_A)[0],
            OptimizationLimits(10**12),
        )
        self.assertEqual(
            no_edge.status,
            OptimizationStatus.NO_POSITIVE_CONTINUOUS_EDGE,
        )
        self.assertTrue(no_edge.complete)

    def test_route_and_result_uint256_authority_is_closed(self) -> None:
        state = authenticated_universe(
            (
                pool_fixture(address_byte=1, token0=TOKEN_A, token1=TOKEN_B, reserve0=1000, reserve1=2000),
                pool_fixture(address_byte=2, token0=TOKEN_A, token1=TOKEN_B, reserve0=1500, reserve1=1000),
            )
        )
        route = enumerate_simple_cycles(state, TOKEN_A)[0]
        with self.assertRaisesRegex(ValueError, "uint256"):
            route.maximum_safe_input(state, MAX_UINT256 + 1)
        limits = OptimizationLimits(100, maximum_intervals=1, exhaustive_threshold=1)
        with self.assertRaisesRegex(ValueError, "budget-exhausted"):
            OptimizationResult(
                route_sha256=route.digest,
                status=OptimizationStatus.BUDGET_EXHAUSTED,
                complete=False,
                effective_maximum_input=100,
                amount_in=1,
                amount_out=2,
                gross_profit=1,
                evaluated_inputs=0,
                explored_intervals=1,
                pruned_intervals=0,
                continuous_upper_bound=1,
                limits=limits,
            )
        with self.assertRaisesRegex(ValueError, "continuous_upper_bound"):
            OptimizationResult(
                route_sha256=route.digest,
                status=OptimizationStatus.BUDGET_EXHAUSTED,
                complete=False,
                effective_maximum_input=100,
                amount_in=0,
                amount_out=0,
                gross_profit=0,
                evaluated_inputs=0,
                explored_intervals=1,
                pruned_intervals=0,
                continuous_upper_bound=MAX_UINT256 + 1,
                limits=limits,
            )

    def test_optimization_result_cross_field_bounds_fail_closed(self) -> None:
        state = authenticated_universe(
            (
                pool_fixture(address_byte=1, token0=TOKEN_A, token1=TOKEN_B, reserve0=1000, reserve1=2000),
                pool_fixture(address_byte=2, token0=TOKEN_A, token1=TOKEN_B, reserve0=1500, reserve1=1000),
            )
        )
        route = enumerate_simple_cycles(state, TOKEN_A)[0]
        limits = OptimizationLimits(100, maximum_intervals=2, exhaustive_threshold=1)
        with self.assertRaisesRegex(ValueError, "understates"):
            OptimizationResult(
                route_sha256=route.digest,
                status=OptimizationStatus.COMPLETE,
                complete=True,
                effective_maximum_input=100,
                amount_in=1,
                amount_out=2,
                gross_profit=1,
                evaluated_inputs=1,
                explored_intervals=1,
                pruned_intervals=0,
                continuous_upper_bound=0,
                limits=limits,
            )
        with self.assertRaisesRegex(ValueError, "explored exhaustive work"):
            OptimizationResult(
                route_sha256=route.digest,
                status=OptimizationStatus.NO_POSITIVE_EXACT_PROFIT,
                complete=True,
                effective_maximum_input=100,
                amount_in=0,
                amount_out=0,
                gross_profit=0,
                evaluated_inputs=2,
                explored_intervals=1,
                pruned_intervals=0,
                continuous_upper_bound=1,
                limits=limits,
            )
        with self.assertRaisesRegex(ValueError, "no-positive-continuous-edge"):
            OptimizationResult(
                route_sha256=route.digest,
                status=OptimizationStatus.NO_POSITIVE_CONTINUOUS_EDGE,
                complete=True,
                effective_maximum_input=100,
                amount_in=0,
                amount_out=0,
                gross_profit=0,
                evaluated_inputs=0,
                explored_intervals=0,
                pruned_intervals=0,
                continuous_upper_bound=1,
                limits=limits,
            )

if __name__ == "__main__":
    unittest.main()
