from __future__ import annotations

from dataclasses import replace
import random
import unittest

from aladdin_mev_engine.constant_product import (
    AuthenticatedConstantProductPool,
    ConstantProductImplementationSpec,
    ConstantProductModelRegistry,
    ConstantProductPoolSpec,
    PackedStorageField,
    PoolUniverse,
)
from aladdin_mev_engine.domain import Chain

from f3_helpers import (
    RESERVES_SLOT,
    SYNTHETIC_CODE_HASH,
    TOKEN0_SLOT,
    TOKEN1_SLOT,
    TOKEN_A,
    TOKEN_B,
    authenticated_universe,
    implementation_spec,
    pool_fixture,
)


class ConstantProductF3Tests(unittest.TestCase):
    def test_authenticated_pool_binds_code_tokens_reserves_and_exact_slots(self) -> None:
        state = authenticated_universe(
            (
                pool_fixture(
                    address_byte=1,
                    token0=TOKEN_A,
                    token1=TOKEN_B,
                    reserve0=1000,
                    reserve1=2000,
                ),
            )
        )
        pool = state.pools[0]
        self.assertEqual((pool.reserve0, pool.reserve1), (1000, 2000))
        quote = pool.quote_exact_in(TOKEN_A, 100)
        self.assertEqual(
            quote.amount_out,
            100 * 997 * 2000 // (1000 * 1000 + 100 * 997),
        )

        wrong_code = replace(
            pool.spec.implementation,
            implementation_id="wrong-code",
            code_hash=bytes.fromhex("ff" * 32),
        )
        with self.assertRaisesRegex(ValueError, "code hash"):
            AuthenticatedConstantProductPool(
                ConstantProductPoolSpec(
                    "wrong-code",
                    Chain.ETHEREUM,
                    pool.pool_address,
                    TOKEN_A,
                    TOKEN_B,
                    wrong_code,
                ),
                pool.evidence,
            )

        missing_slot_model = replace(
            pool.spec.implementation,
            implementation_id="wrong-slot",
            token0_field=PackedStorageField((9).to_bytes(32, "big"), 0, 160),
        )
        with self.assertRaisesRegex(ValueError, "exact model slot set"):
            AuthenticatedConstantProductPool(
                ConstantProductPoolSpec(
                    "wrong-slot",
                    Chain.ETHEREUM,
                    pool.pool_address,
                    TOKEN_A,
                    TOKEN_B,
                    missing_slot_model,
                ),
                pool.evidence,
            )

    def test_randomized_quotes_match_reference_integer_formula(self) -> None:
        state = authenticated_universe(
            (
                pool_fixture(
                    address_byte=1,
                    token0=TOKEN_A,
                    token1=TOKEN_B,
                    reserve0=1_234_567,
                    reserve1=7_654_321,
                ),
            )
        )
        pool = state.pools[0]
        rng = random.Random(0xF3C0FFEE)
        for _ in range(1_000):
            amount_in = rng.randint(0, 1_000_000)
            quote = pool.quote_exact_in(TOKEN_A, amount_in)
            expected = (
                amount_in
                * 997
                * pool.reserve1
                // (pool.reserve0 * 1000 + amount_in * 997)
            )
            self.assertEqual(quote.amount_out, expected)

    def test_token_identity_and_model_fee_cannot_be_caller_injected(self) -> None:
        state = authenticated_universe(
            (
                pool_fixture(
                    address_byte=1,
                    token0=TOKEN_A,
                    token1=TOKEN_B,
                    reserve0=1000,
                    reserve1=2000,
                ),
            )
        )
        pool = state.pools[0]
        wrong_tokens = ConstantProductPoolSpec(
            "wrong-token",
            Chain.ETHEREUM,
            pool.pool_address,
            TOKEN_B,
            TOKEN_A,
            pool.spec.implementation,
        )
        with self.assertRaisesRegex(ValueError, "token identity"):
            AuthenticatedConstantProductPool(wrong_tokens, pool.evidence)

        conflicting = ConstantProductImplementationSpec(
            "conflicting",
            SYNTHETIC_CODE_HASH,
            PackedStorageField(TOKEN0_SLOT, 0, 160),
            PackedStorageField(TOKEN1_SLOT, 0, 160),
            PackedStorageField(RESERVES_SLOT, 0, 112),
            PackedStorageField(RESERVES_SLOT, 112, 112),
            998,
            1000,
        )
        with self.assertRaisesRegex(ValueError, "code hash"):
            ConstantProductModelRegistry(
                "ambiguous",
                (pool.spec.implementation, conflicting),
            )

    def test_overlapping_storage_fields_fail_before_model_authority(self) -> None:
        with self.assertRaisesRegex(ValueError, "overlap"):
            ConstantProductImplementationSpec(
                "overlap",
                SYNTHETIC_CODE_HASH,
                PackedStorageField(TOKEN0_SLOT, 0, 160),
                PackedStorageField(TOKEN0_SLOT, 96, 160),
                PackedStorageField(RESERVES_SLOT, 0, 112),
                PackedStorageField(RESERVES_SLOT, 112, 112),
                997,
                1000,
            )

    def test_pool_universe_is_exact_snapshot_and_model_registry_bound(self) -> None:
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
        with self.assertRaisesRegex(ValueError, "exact snapshot account set"):
            PoolUniverse(
                state.snapshot,
                state.model_registry,
                (state.pools[0],),
            )
        wrong_registry = ConstantProductModelRegistry(
            "wrong",
            (implementation_spec(fee_numerator=996),),
        )
        with self.assertRaisesRegex(ValueError, "model registry"):
            PoolUniverse(state.snapshot, wrong_registry, state.pools)

    def test_checked_uint256_capacity_and_state_freshness_are_enforced(self) -> None:
        state = authenticated_universe(
            (
                pool_fixture(
                    address_byte=1,
                    token0=TOKEN_A,
                    token1=TOKEN_B,
                    reserve0=(1 << 112) - 2,
                    reserve1=1_000_000,
                ),
            )
        )
        pool = state.pools[0]
        self.assertEqual(pool.maximum_safe_input(TOKEN_A), 1)
        pool.quote_exact_in(TOKEN_A, 1)
        with self.assertRaisesRegex(ValueError, "capacity"):
            pool.quote_exact_in(TOKEN_A, 2)
        self.assertEqual(
            state.observed_at_unix_ms,
            state.snapshot.anchor.state_observed_at_unix_ms,
        )
        self.assertLess(
            state.observed_at_unix_ms,
            pool.evidence.proof_observed_at_unix_ms,
        )


    def test_empty_runtime_code_hash_cannot_authorize_a_pool_model(self) -> None:
        from aladdin_mev_engine.state_proof import EMPTY_CODE_HASH

        with self.assertRaisesRegex(ValueError, "empty code"):
            ConstantProductImplementationSpec(
                "empty-code",
                EMPTY_CODE_HASH,
                PackedStorageField(TOKEN0_SLOT, 0, 160),
                PackedStorageField(TOKEN1_SLOT, 0, 160),
                PackedStorageField(RESERVES_SLOT, 0, 112),
                PackedStorageField(RESERVES_SLOT, 112, 112),
                997,
                1000,
            )

if __name__ == "__main__":
    unittest.main()
