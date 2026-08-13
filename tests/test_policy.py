from __future__ import annotations

import unittest

from aladdin_mev_engine.domain import OperatingMode, Strategy
from aladdin_mev_engine.policy import PolicyReason, StrategyPolicy


class StrategyPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = StrategyPolicy()

    def test_allowlisted_strategy_is_shadow_only(self) -> None:
        shadow = self.policy.evaluate(Strategy.ATOMIC_DEX_ARBITRAGE.value, OperatingMode.SHADOW)
        live = self.policy.evaluate(Strategy.ATOMIC_DEX_ARBITRAGE.value, OperatingMode.LIVE)
        self.assertTrue(shadow.allowed)
        self.assertEqual(shadow.reason, PolicyReason.ALLOWED_SHADOW_STRATEGY)
        self.assertFalse(live.allowed)
        self.assertEqual(live.reason, PolicyReason.F0_EXECUTION_DISABLED)

    def test_prohibited_strategy_is_explicitly_rejected(self) -> None:
        decision = self.policy.evaluate("sandwich", OperatingMode.SHADOW)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, PolicyReason.PROHIBITED_STRATEGY)

    def test_unknown_strategy_fails_closed(self) -> None:
        decision = self.policy.evaluate("future-magic-strategy", OperatingMode.SHADOW)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, PolicyReason.UNKNOWN_STRATEGY)

    def test_non_canonical_strategy_text_is_not_normalized(self) -> None:
        decision = self.policy.evaluate(" atomic-dex-arbitrage ", OperatingMode.SHADOW)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, PolicyReason.UNKNOWN_STRATEGY)


if __name__ == "__main__":
    unittest.main()
