from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .domain import OperatingMode, require_bounded_text, require_non_negative_int


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
    __slots__ = ("_mode",)

    def __init__(self) -> None:
        self._mode = OperatingMode.STOPPED

    @property
    def mode(self) -> OperatingMode:
        return self._mode

    def apply(self, event: GovernorEvent, context: TransitionContext) -> OperatingMode:
        if type(event) is not GovernorEvent:
            raise TransitionRejected("event must be a governed GovernorEvent")
        if type(context) is not TransitionContext:
            raise TransitionRejected("context must be an exact TransitionContext")
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
            if self._mode in {OperatingMode.DEGRADED, OperatingMode.HALTED}:
                self._require_human_evidence(context)
                self._require(
                    context.incident_closed,
                    "stopping after an incident requires closed incident evidence",
                )
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
    __slots__ = ("_limits", "_realized_net_profit", "_reservations")

    def __init__(self, limits: RiskLimits) -> None:
        if type(limits) is not RiskLimits:
            raise ValueError("limits must be an exact RiskLimits value")
        self._limits = limits
        self._realized_net_profit = 0
        self._reservations: dict[str, int] = {}

    @property
    def limits(self) -> RiskLimits:
        return self._limits

    @property
    def realized_net_profit(self) -> int:
        return self._realized_net_profit

    @property
    def reserved_execution_cost(self) -> int:
        return sum(self._reservations.values())

    @property
    def concurrent_candidates(self) -> int:
        return len(self._reservations)

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

    def reserve(self, *, reservation_id: str, execution_cost: int, notional: int) -> None:
        require_bounded_text("reservation_id", reservation_id, maximum=128)
        if reservation_id in self._reservations:
            raise ValueError("reservation_id already exists")
        decision = self.authorize(execution_cost=execution_cost, notional=notional)
        if not decision.allowed:
            raise RuntimeError("risk reservation rejected: " + ", ".join(decision.reasons))
        self._reservations[reservation_id] = execution_cost

    def settle(self, *, reservation_id: str, realized_net_profit: int) -> None:
        require_bounded_text("reservation_id", reservation_id, maximum=128)
        if isinstance(realized_net_profit, bool) or not isinstance(realized_net_profit, int):
            raise ValueError("realized_net_profit must be an integer")
        if reservation_id not in self._reservations:
            raise ValueError("unknown reservation_id")
        del self._reservations[reservation_id]
        self._realized_net_profit += realized_net_profit
