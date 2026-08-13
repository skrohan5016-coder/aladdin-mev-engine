from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .domain import OperatingMode, require_non_negative_int


class GovernorEvent(StrEnum):
    BOOTSTRAP_TO_SHADOW = "bootstrap-to-shadow"
    PROMOTE_TO_CANARY = "promote-to-canary"
    PROMOTE_TO_LIVE = "promote-to-live"
    DATA_MISMATCH = "data-mismatch"
    SERVICE_DEGRADED = "service-degraded"
    INVARIANT_BREACH = "invariant-breach"
    SIGNER_ANOMALY = "signer-anomaly"
    DAILY_LOSS_LIMIT = "daily-loss-limit"
    RECOVER_TO_SHADOW = "recover-to-shadow"
    STOP = "stop"


class TransitionRejected(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TransitionContext:
    human_approved: bool = False
    acceptance_evidence_valid: bool = False
    incident_closed: bool = False

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be boolean")


class RiskGovernor:
    def __init__(self, mode: OperatingMode = OperatingMode.STOPPED) -> None:
        self._mode = mode

    @property
    def mode(self) -> OperatingMode:
        return self._mode

    def apply(self, event: GovernorEvent, context: TransitionContext) -> OperatingMode:
        critical = {
            GovernorEvent.INVARIANT_BREACH,
            GovernorEvent.SIGNER_ANOMALY,
            GovernorEvent.DAILY_LOSS_LIMIT,
        }
        degraded = {GovernorEvent.DATA_MISMATCH, GovernorEvent.SERVICE_DEGRADED}

        if event in critical:
            self._mode = OperatingMode.HALTED
            return self._mode
        if event in degraded:
            if self._mode not in {OperatingMode.STOPPED, OperatingMode.HALTED}:
                self._mode = OperatingMode.DEGRADED
            return self._mode
        if event is GovernorEvent.STOP:
            if not context.human_approved:
                raise TransitionRejected("stopping a governed mode requires human approval")
            self._mode = OperatingMode.STOPPED
            return self._mode
        if event is GovernorEvent.BOOTSTRAP_TO_SHADOW:
            self._require(self._mode is OperatingMode.STOPPED, "bootstrap requires stopped mode")
            self._require_human_evidence(context)
            self._mode = OperatingMode.SHADOW
            return self._mode
        if event is GovernorEvent.PROMOTE_TO_CANARY:
            self._require(self._mode is OperatingMode.SHADOW, "canary promotion requires shadow mode")
            self._require_human_evidence(context)
            self._mode = OperatingMode.CANARY
            return self._mode
        if event is GovernorEvent.PROMOTE_TO_LIVE:
            self._require(self._mode is OperatingMode.CANARY, "live promotion requires canary mode")
            self._require_human_evidence(context)
            self._mode = OperatingMode.LIVE
            return self._mode
        if event is GovernorEvent.RECOVER_TO_SHADOW:
            self._require(
                self._mode in {OperatingMode.DEGRADED, OperatingMode.HALTED},
                "recovery requires degraded or halted mode",
            )
            self._require_human_evidence(context)
            self._require(context.incident_closed, "recovery requires closed incident evidence")
            self._mode = OperatingMode.SHADOW
            return self._mode
        raise TransitionRejected(f"unsupported transition event: {event}")

    @staticmethod
    def _require(condition: bool, message: str) -> None:
        if not condition:
            raise TransitionRejected(message)

    @classmethod
    def _require_human_evidence(cls, context: TransitionContext) -> None:
        cls._require(context.human_approved, "transition requires explicit human approval")
        cls._require(
            context.acceptance_evidence_valid,
            "transition requires valid acceptance evidence",
        )


@dataclass(frozen=True, slots=True)
class RiskLimits:
    maximum_daily_loss: int
    maximum_single_execution_cost: int
    maximum_pending_execution_cost: int
    maximum_concurrent_candidates: int
    maximum_notional: int

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            require_non_negative_int(name, getattr(self, name))


@dataclass(frozen=True, slots=True)
class RiskAuthorization:
    allowed: bool
    reasons: tuple[str, ...]


class RiskLedger:
    def __init__(self, limits: RiskLimits) -> None:
        self.limits = limits
        self.realized_net_profit = 0
        self.reserved_execution_cost = 0
        self.concurrent_candidates = 0

    @property
    def realized_loss(self) -> int:
        return max(-self.realized_net_profit, 0)

    def authorize(self, *, execution_cost: int, notional: int) -> RiskAuthorization:
        require_non_negative_int("execution_cost", execution_cost)
        require_non_negative_int("notional", notional)
        reasons: list[str] = []
        if execution_cost > self.limits.maximum_single_execution_cost:
            reasons.append("single-execution-cost-limit")
        if self.reserved_execution_cost + execution_cost > self.limits.maximum_pending_execution_cost:
            reasons.append("pending-execution-cost-limit")
        if self.realized_loss + self.reserved_execution_cost + execution_cost > self.limits.maximum_daily_loss:
            reasons.append("daily-loss-limit")
        if self.concurrent_candidates + 1 > self.limits.maximum_concurrent_candidates:
            reasons.append("concurrent-candidate-limit")
        if notional > self.limits.maximum_notional:
            reasons.append("notional-limit")
        return RiskAuthorization(not reasons, tuple(reasons))

    def reserve(self, *, execution_cost: int, notional: int) -> None:
        decision = self.authorize(execution_cost=execution_cost, notional=notional)
        if not decision.allowed:
            raise RuntimeError("risk reservation rejected: " + ", ".join(decision.reasons))
        self.reserved_execution_cost += execution_cost
        self.concurrent_candidates += 1

    def settle(self, *, reserved_execution_cost: int, realized_net_profit: int) -> None:
        require_non_negative_int("reserved_execution_cost", reserved_execution_cost)
        if isinstance(realized_net_profit, bool) or not isinstance(realized_net_profit, int):
            raise ValueError("realized_net_profit must be an integer")
        if reserved_execution_cost > self.reserved_execution_cost:
            raise ValueError("cannot settle more cost than is reserved")
        if self.concurrent_candidates <= 0:
            raise ValueError("no concurrent candidate is available to settle")
        self.reserved_execution_cost -= reserved_execution_cost
        self.concurrent_candidates -= 1
        self.realized_net_profit += realized_net_profit
