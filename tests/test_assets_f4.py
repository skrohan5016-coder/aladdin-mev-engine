from __future__ import annotations

import random
import unittest

from aladdin_mev_engine.assets import (
    AssetAmount,
    AssetId,
    AssetKind,
    ConservativeValuationRate,
    ValuationBook,
)
from aladdin_mev_engine.constant_product import MAX_UINT256
from aladdin_mev_engine.domain import Chain


class AssetAndValuationF4Tests(unittest.TestCase):
    def test_native_and_erc20_identity_are_closed(self) -> None:
        native = AssetId.native(Chain.ETHEREUM)
        token = AssetId.erc20(Chain.ETHEREUM, bytes.fromhex("11" * 20))
        self.assertIs(native.kind, AssetKind.NATIVE)
        self.assertIsNone(native.address)
        self.assertIs(token.kind, AssetKind.ERC20)
        with self.assertRaisesRegex(ValueError, "native asset"):
            AssetId(Chain.ETHEREUM, AssetKind.NATIVE, bytes.fromhex("11" * 20))
        with self.assertRaisesRegex(ValueError, "cannot be zero"):
            AssetId.erc20(Chain.ETHEREUM, bytes(20))

    def test_conservative_conversion_uses_ceiling(self) -> None:
        source = AssetId.native(Chain.BASE)
        target = AssetId.erc20(Chain.BASE, bytes.fromhex("22" * 20))
        rate = ConservativeValuationRate(
            "ceil",
            source,
            target,
            7,
            3,
            100,
            200,
            "11" * 32,
        )
        self.assertEqual(
            rate.convert_upper_bound(AssetAmount(source, 1), at_unix_ms=150).amount,
            3,
        )
        rng = random.Random(0xF4A55E7)
        for _ in range(2_000):
            amount = rng.randint(0, 10**18)
            numerator = rng.randint(1, 10**9)
            denominator = rng.randint(1, 10**9)
            candidate = ConservativeValuationRate(
                "random",
                source,
                target,
                numerator,
                denominator,
                100,
                200,
                "22" * 32,
            )
            converted = candidate.convert_upper_bound(
                AssetAmount(source, amount), at_unix_ms=150
            ).amount
            self.assertGreaterEqual(converted * denominator, amount * numerator)
            if converted:
                self.assertLess((converted - 1) * denominator, amount * numerator)

    def test_valuation_book_rejects_ambiguity_expiry_and_implicit_inverse(self) -> None:
        native = AssetId.native(Chain.ETHEREUM)
        token = AssetId.erc20(Chain.ETHEREUM, bytes.fromhex("33" * 20))
        rate = ConservativeValuationRate(
            "a",
            native,
            token,
            1,
            1,
            100,
            200,
            "33" * 32,
        )
        duplicate = ConservativeValuationRate(
            "b",
            native,
            token,
            2,
            1,
            100,
            200,
            "44" * 32,
        )
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            ValuationBook((rate, duplicate))
        book = ValuationBook((rate,))
        with self.assertRaisesRegex(ValueError, "not valid"):
            book.convert_upper_bound(AssetAmount(native, 1), token, at_unix_ms=201)
        with self.assertRaisesRegex(ValueError, "absent"):
            book.convert_upper_bound(AssetAmount(token, 1), native, at_unix_ms=150)

        self.assertEqual(len(book.pair_sha256), 1)
        self.assertEqual(
            book.require_exact_pairs(((native, token),), at_unix_ms=150),
            book.rates,
        )
        with self.assertRaisesRegex(ValueError, "exact required"):
            book.require_exact_pairs((), at_unix_ms=150)

    def test_converted_upper_bound_is_uint256_closed(self) -> None:
        native = AssetId.native(Chain.ETHEREUM)
        token = AssetId.erc20(Chain.ETHEREUM, bytes.fromhex("44" * 20))
        rate = ConservativeValuationRate(
            "overflow",
            native,
            token,
            MAX_UINT256,
            1,
            0,
            1,
            "55" * 32,
        )
        with self.assertRaisesRegex(ValueError, "multiplication exceeds uint256"):
            rate.convert_upper_bound(
                AssetAmount(native, MAX_UINT256), at_unix_ms=0
            )
        quotient_would_fit = ConservativeValuationRate(
            "intermediate-overflow",
            native,
            token,
            MAX_UINT256,
            MAX_UINT256,
            0,
            1,
            "66" * 32,
        )
        with self.assertRaisesRegex(ValueError, "multiplication exceeds uint256"):
            quotient_would_fit.convert_upper_bound(
                AssetAmount(native, 2), at_unix_ms=0
            )


if __name__ == "__main__":
    unittest.main()
