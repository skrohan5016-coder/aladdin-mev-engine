from __future__ import annotations

import unittest

from aladdin_mev_engine.liquidation_contracts import (
    LIQUIDATION_MECHANISMS,
    WAD,
    LiquidationProtocol,
    get_liquidation_mechanism,
    liquidation_mechanism_set_digest,
)


class LiquidationMechanismF2Tests(unittest.TestCase):
    def test_registry_is_exact_sorted_and_digest_stable(self) -> None:
        self.assertEqual(
            [protocol.value for protocol in LIQUIDATION_MECHANISMS],
            ["aave-v3", "morpho-blue"],
        )
        self.assertEqual(len(liquidation_mechanism_set_digest()), 64)

    def test_aave_uses_strict_health_factor_boundary(self) -> None:
        mechanism = get_liquidation_mechanism(LiquidationProtocol.AAVE_V3)
        self.assertTrue(mechanism.is_liquidatable(WAD - 1, WAD))
        self.assertFalse(mechanism.is_liquidatable(WAD, WAD))
        self.assertFalse(mechanism.is_liquidatable(WAD + 1, WAD))

    def test_aave_denominator_is_governed(self) -> None:
        mechanism = get_liquidation_mechanism(LiquidationProtocol.AAVE_V3)
        with self.assertRaises(ValueError):
            mechanism.is_liquidatable(WAD - 1, WAD - 1)

    def test_morpho_equality_is_healthy_and_one_unit_above_is_liquidatable(self) -> None:
        mechanism = get_liquidation_mechanism(LiquidationProtocol.MORPHO_BLUE)
        self.assertFalse(mechanism.is_liquidatable(100, 100))
        self.assertTrue(mechanism.is_liquidatable(101, 100))
        self.assertFalse(mechanism.is_liquidatable(99, 100))

    def test_invalid_integer_shapes_fail_closed(self) -> None:
        mechanism = get_liquidation_mechanism(LiquidationProtocol.MORPHO_BLUE)
        for numerator, denominator in ((True, 1), (-1, 1), (1, 0), (1, True)):
            with self.subTest(numerator=numerator, denominator=denominator):
                with self.assertRaises(ValueError):
                    mechanism.is_liquidatable(numerator, denominator)

    def test_source_commits_are_exactly_pinned(self) -> None:
        self.assertEqual(
            get_liquidation_mechanism(LiquidationProtocol.AAVE_V3).source_commit,
            "cff15de6d1271b0c800fc001f4aea4c263e8a597",
        )
        self.assertEqual(
            get_liquidation_mechanism(LiquidationProtocol.MORPHO_BLUE).source_commit,
            "d09dd1c4b9c7d9d05f976faa7ebfdc424dae5e8c",
        )


if __name__ == "__main__":
    unittest.main()
