from __future__ import annotations

import unittest

from aladdin_mev_engine.domain import OperatingMode
from aladdin_mev_engine.risk import (
    GovernorEvent,
    RiskGovernor,
    RiskLedger,
    RiskLimits,
    TransitionContext,
    TransitionRejected,
)


class RiskGovernorTests(unittest.TestCase):
    def test_transition_context_rejects_truthy_non_booleans(self) -> None:
        with self.assertRaises(ValueError):
            TransitionContext(human_approved=1)

    def test_promotions_require_human_and_evidence(self) -> None:
        governor = RiskGovernor()
        with self.assertRaises(TransitionRejected):
            governor.apply(GovernorEvent.BOOTSTRAP_TO_SHADOW, TransitionContext())
        self.assertEqual(governor.mode, OperatingMode.STOPPED)
        governor.apply(
            GovernorEvent.BOOTSTRAP_TO_SHADOW,
            TransitionContext(human_approved=True, acceptance_evidence_valid=True),
        )
        self.assertEqual(governor.mode, OperatingMode.SHADOW)
        with self.assertRaises(TransitionRejected):
            governor.apply(
                GovernorEvent.PROMOTE_TO_CANARY,
                TransitionContext(human_approved=True, acceptance_evidence_valid=False),
            )

    def test_critical_event_halts_immediately(self) -> None:
        governor = RiskGovernor(OperatingMode.LIVE)
        governor.apply(GovernorEvent.INVARIANT_BREACH, TransitionContext())
        self.assertEqual(governor.mode, OperatingMode.HALTED)

    def test_recovery_requires_closed_incident(self) -> None:
        governor = RiskGovernor(OperatingMode.HALTED)
        context = TransitionContext(human_approved=True, acceptance_evidence_valid=True)
        with self.assertRaises(TransitionRejected):
            governor.apply(GovernorEvent.RECOVER_TO_SHADOW, context)
        recovered = governor.apply(
            GovernorEvent.RECOVER_TO_SHADOW,
            TransitionContext(
                human_approved=True,
                acceptance_evidence_valid=True,
                incident_closed=True,
            ),
        )
        self.assertEqual(recovered, OperatingMode.SHADOW)


class RiskLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = RiskLedger(
            RiskLimits(
                maximum_daily_loss=1_000,
                maximum_single_execution_cost=300,
                maximum_pending_execution_cost=500,
                maximum_concurrent_candidates=2,
                maximum_notional=10_000,
            )
        )

    def test_reservation_and_settlement_are_reconciled(self) -> None:
        self.ledger.reserve(execution_cost=200, notional=5_000)
        self.assertEqual(self.ledger.reserved_execution_cost, 200)
        self.ledger.settle(reserved_execution_cost=200, realized_net_profit=50)
        self.assertEqual(self.ledger.reserved_execution_cost, 0)
        self.assertEqual(self.ledger.realized_net_profit, 50)

    def test_limits_fail_closed(self) -> None:
        decision = self.ledger.authorize(execution_cost=301, notional=10_001)
        self.assertFalse(decision.allowed)
        self.assertIn("single-execution-cost-limit", decision.reasons)
        self.assertIn("notional-limit", decision.reasons)

    def test_realized_loss_consumes_daily_budget(self) -> None:
        self.ledger.realized_net_profit = -900
        decision = self.ledger.authorize(execution_cost=101, notional=1)
        self.assertIn("daily-loss-limit", decision.reasons)


if __name__ == "__main__":
    unittest.main()
