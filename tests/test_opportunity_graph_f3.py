from __future__ import annotations

from fractions import Fraction
import unittest

from aladdin_mev_engine.opportunity_graph import (
    ConstantProductRoute,
    RouteLeg,
    enumerate_simple_cycles,
)

from f3_helpers import (
    TOKEN_A,
    TOKEN_B,
    TOKEN_C,
    authenticated_universe,
    pool_fixture,
)


class OpportunityGraphF3Tests(unittest.TestCase):
    def test_cycle_enumeration_is_deterministic_simple_and_directional(self) -> None:
        state = authenticated_universe(
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
                pool_fixture(
                    address_byte=3,
                    token0=TOKEN_B,
                    token1=TOKEN_C,
                    reserve0=1000,
                    reserve1=1000,
                ),
                pool_fixture(
                    address_byte=4,
                    token0=TOKEN_C,
                    token1=TOKEN_A,
                    reserve0=1000,
                    reserve1=1000,
                ),
            )
        )
        first = enumerate_simple_cycles(state, TOKEN_A)
        self.assertEqual(first, enumerate_simple_cycles(state, TOKEN_A))
        self.assertEqual(
            [route.digest for route in first],
            sorted(route.digest for route in first),
        )
        for route in first:
            self.assertEqual(
                len({leg.pool_address for leg in route.legs}),
                len(route.legs),
            )

    def test_universe_and_route_identity_ignore_input_fixture_order(self) -> None:
        fixtures = (
            pool_fixture(
                address_byte=1,
                token0=TOKEN_A,
                token1=TOKEN_B,
                reserve0=1000,
                reserve1=2000,
            ),
            pool_fixture(
                address_byte=2,
                token0=TOKEN_B,
                token1=TOKEN_C,
                reserve0=1500,
                reserve1=1200,
            ),
            pool_fixture(
                address_byte=3,
                token0=TOKEN_C,
                token1=TOKEN_A,
                reserve0=900,
                reserve1=1100,
            ),
        )
        forward = authenticated_universe(fixtures)
        reverse = authenticated_universe(tuple(reversed(fixtures)))
        self.assertEqual(forward.digest, reverse.digest)
        self.assertEqual(
            tuple(route.digest for route in enumerate_simple_cycles(forward, TOKEN_A)),
            tuple(route.digest for route in enumerate_simple_cycles(reverse, TOKEN_A)),
        )

    def test_continuous_composition_is_exact_before_integer_flooring(self) -> None:
        state = authenticated_universe(
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
        route = next(
            item
            for item in enumerate_simple_cycles(state, TOKEN_A)
            if item.legs[0].pool_address == state.pools[0].pool_address
        )
        a, b, c = route.continuous_coefficients(state)
        for amount in (1, 17, 100, 999):
            first = Fraction(997 * 2000 * amount, 1000 * 1000 + 997 * amount)
            expected = Fraction(997 * 1500 * first, 1000 * 1000 + 997 * first)
            self.assertEqual(Fraction(a * amount, b + c * amount), expected)

    def test_zero_intermediate_output_is_a_valid_noop_not_a_domain_gap(self) -> None:
        state = authenticated_universe(
            (
                pool_fixture(
                    address_byte=1,
                    token0=TOKEN_A,
                    token1=TOKEN_B,
                    reserve0=1_000_000,
                    reserve1=2,
                ),
                pool_fixture(
                    address_byte=2,
                    token0=TOKEN_A,
                    token1=TOKEN_B,
                    reserve0=10_000_000,
                    reserve1=1,
                ),
            )
        )
        route = next(
            item
            for item in enumerate_simple_cycles(state, TOKEN_A)
            if item.legs[0].pool_address == state.pools[0].pool_address
        )
        self.assertEqual(route.quote_exact_in(state, 1).amount_out, 0)
        self.assertGreater(route.quote_exact_in(state, 2_000_000).amount_out, 0)
        self.assertGreaterEqual(route.maximum_safe_input(state, 2_000_000), 2_000_000)

    def test_route_reuse_and_early_return_fail_closed(self) -> None:
        state = authenticated_universe(
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
        pool = state.pools[0]
        with self.assertRaisesRegex(ValueError, "reuse"):
            ConstantProductRoute(
                state.digest,
                (
                    RouteLeg(pool.pool_address, TOKEN_A, TOKEN_B),
                    RouteLeg(pool.pool_address, TOKEN_B, TOKEN_A),
                ),
            )


if __name__ == "__main__":
    unittest.main()
