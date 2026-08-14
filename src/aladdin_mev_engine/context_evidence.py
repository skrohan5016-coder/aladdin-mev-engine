from __future__ import annotations

from dataclasses import dataclass, field

from .canonical import canonical_json_bytes, canonical_sha256
from .constant_product import MAX_UINT256
from .domain import Chain, ChainHealth, require_bounded_text, require_sha256
from .risk import RiskLedger, RiskLimits

CHAIN_HEALTH_EVIDENCE_SCHEMA = "aladdin-mev-chain-health-evidence/v1"
RISK_BUDGET_EVIDENCE_SCHEMA = "aladdin-mev-risk-budget-evidence/v1"
MAX_UINT64 = (1 << 64) - 1


def _uint(name: str, value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT256:
        raise ValueError(f"{name} must be an unsigned 256-bit exact integer")
    return value


def _signed_uint(name: str, value: object) -> int:
    if type(value) is not int or not -MAX_UINT256 <= value <= MAX_UINT256:
        raise ValueError(f"{name} must be a signed 256-bit exact integer")
    return value


def _time(name: str, value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT64:
        raise ValueError(f"{name} must be an unsigned 64-bit exact integer")
    return value


def _checked_sum(values: tuple[int, ...], name: str) -> int:
    total = 0
    for value in values:
        _uint(f"{name} component", value)
        if value > MAX_UINT256 - total:
            raise ValueError(f"{name} exceeds uint256")
        total += value
    return total


def _limits_to_json(limits: RiskLimits) -> dict[str, str]:
    return {
        "maximum_daily_loss": str(limits.maximum_daily_loss),
        "maximum_single_execution_cost": str(limits.maximum_single_execution_cost),
        "maximum_pending_execution_cost": str(limits.maximum_pending_execution_cost),
        "maximum_concurrent_candidates": str(limits.maximum_concurrent_candidates),
        "maximum_notional": str(limits.maximum_notional),
    }


@dataclass(frozen=True, slots=True)
class ChainHealthEvidence:
    chain: Chain
    health: ChainHealth
    observed_at_unix_ms: int
    valid_until_unix_ms: int
    source_sha256: str
    schema: str = CHAIN_HEALTH_EVIDENCE_SCHEMA
    _evidence_id: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != CHAIN_HEALTH_EVIDENCE_SCHEMA:
            raise ValueError("unsupported chain-health-evidence schema")
        if type(self.chain) is not Chain:
            raise TypeError("chain must be an exact Chain")
        if type(self.health) is not ChainHealth:
            raise TypeError("health must be an exact ChainHealth")
        _time("observed_at_unix_ms", self.observed_at_unix_ms)
        _time("valid_until_unix_ms", self.valid_until_unix_ms)
        if self.valid_until_unix_ms < self.observed_at_unix_ms:
            raise ValueError("chain-health validity cannot precede observation")
        require_sha256("source_sha256", self.source_sha256)
        identity = {
            "schema": self.schema,
            "chain": self.chain.value,
            "health": self.health.value,
            "observed_at_unix_ms": str(self.observed_at_unix_ms),
            "valid_until_unix_ms": str(self.valid_until_unix_ms),
            "source_sha256": self.source_sha256,
            "authority": "recorded-chain-health-shadow-context-only",
        }
        object.__setattr__(
            self,
            "_evidence_id",
            "chain-health-" + canonical_sha256(identity),
        )
        canonical_json_bytes(self.to_json_value())

    @property
    def evidence_id(self) -> str:
        return self._evidence_id

    def is_valid_at(self, at_unix_ms: int) -> bool:
        _time("at_unix_ms", at_unix_ms)
        return self.observed_at_unix_ms <= at_unix_ms <= self.valid_until_unix_ms

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "evidence_id": self.evidence_id,
            "chain": self.chain.value,
            "health": self.health.value,
            "observed_at_unix_ms": str(self.observed_at_unix_ms),
            "valid_until_unix_ms": str(self.valid_until_unix_ms),
            "source_sha256": self.source_sha256,
            "authority": "recorded-chain-health-shadow-context-only",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class RiskBudgetEvidence:
    risk_policy_id: str
    execution_plan_sha256: str
    limits: RiskLimits
    realized_net_profit: int
    reserved_execution_cost: int
    concurrent_candidates: int
    requested_execution_cost: int
    requested_notional: int
    observed_at_unix_ms: int
    valid_until_unix_ms: int
    source_sha256: str
    schema: str = RISK_BUDGET_EVIDENCE_SCHEMA
    _allowed: bool = field(init=False, repr=False)
    _reasons: tuple[str, ...] = field(init=False, repr=False)
    _evidence_id: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != RISK_BUDGET_EVIDENCE_SCHEMA:
            raise ValueError("unsupported risk-budget-evidence schema")
        require_bounded_text("risk_policy_id", self.risk_policy_id, maximum=128)
        require_sha256("execution_plan_sha256", self.execution_plan_sha256)
        if type(self.limits) is not RiskLimits:
            raise TypeError("limits must be an exact RiskLimits")
        for name in self.limits.__dataclass_fields__:
            _uint(name, getattr(self.limits, name))
        _signed_uint("realized_net_profit", self.realized_net_profit)
        _uint("reserved_execution_cost", self.reserved_execution_cost)
        _uint("concurrent_candidates", self.concurrent_candidates)
        _uint("requested_execution_cost", self.requested_execution_cost)
        _uint("requested_notional", self.requested_notional)
        _time("observed_at_unix_ms", self.observed_at_unix_ms)
        _time("valid_until_unix_ms", self.valid_until_unix_ms)
        if self.valid_until_unix_ms < self.observed_at_unix_ms:
            raise ValueError("risk-budget validity cannot precede observation")
        require_sha256("source_sha256", self.source_sha256)

        pending_execution_cost = _checked_sum(
            (self.reserved_execution_cost, self.requested_execution_cost),
            "pending execution cost",
        )
        daily_loss_exposure = _checked_sum(
            (
                self.realized_loss,
                self.reserved_execution_cost,
                self.requested_execution_cost,
            ),
            "daily loss exposure",
        )
        concurrent_after_request = _checked_sum(
            (self.concurrent_candidates, 1),
            "concurrent candidate count",
        )

        reasons: list[str] = []
        if self.requested_execution_cost > self.limits.maximum_single_execution_cost:
            reasons.append("single-execution-cost-limit")
        if pending_execution_cost > self.limits.maximum_pending_execution_cost:
            reasons.append("pending-execution-cost-limit")
        if daily_loss_exposure > self.limits.maximum_daily_loss:
            reasons.append("daily-loss-limit")
        if concurrent_after_request > self.limits.maximum_concurrent_candidates:
            reasons.append("concurrent-candidate-limit")
        if self.requested_notional > self.limits.maximum_notional:
            reasons.append("notional-limit")

        object.__setattr__(self, "_allowed", not reasons)
        object.__setattr__(self, "_reasons", tuple(reasons))
        identity = {
            "schema": self.schema,
            "risk_policy_id": self.risk_policy_id,
            "execution_plan_sha256": self.execution_plan_sha256,
            "limits": _limits_to_json(self.limits),
            "realized_net_profit": str(self.realized_net_profit),
            "reserved_execution_cost": str(self.reserved_execution_cost),
            "concurrent_candidates": str(self.concurrent_candidates),
            "requested_execution_cost": str(self.requested_execution_cost),
            "requested_notional": str(self.requested_notional),
            "allowed": self.allowed,
            "reasons": list(self.reasons),
            "observed_at_unix_ms": str(self.observed_at_unix_ms),
            "valid_until_unix_ms": str(self.valid_until_unix_ms),
            "source_sha256": self.source_sha256,
            "authority": "recorded-risk-budget-snapshot-shadow-only",
        }
        object.__setattr__(
            self,
            "_evidence_id",
            "risk-budget-" + canonical_sha256(identity),
        )
        canonical_json_bytes(self.to_json_value())

    @classmethod
    def capture(
        cls,
        *,
        risk_policy_id: str,
        execution_plan_sha256: str,
        ledger: RiskLedger,
        requested_execution_cost: int,
        requested_notional: int,
        observed_at_unix_ms: int,
        valid_until_unix_ms: int,
        source_sha256: str,
    ) -> RiskBudgetEvidence:
        if type(ledger) is not RiskLedger:
            raise TypeError("ledger must be an exact RiskLedger")
        return cls(
            risk_policy_id=risk_policy_id,
            execution_plan_sha256=execution_plan_sha256,
            limits=ledger.limits,
            realized_net_profit=ledger.realized_net_profit,
            reserved_execution_cost=ledger.reserved_execution_cost,
            concurrent_candidates=ledger.concurrent_candidates,
            requested_execution_cost=requested_execution_cost,
            requested_notional=requested_notional,
            observed_at_unix_ms=observed_at_unix_ms,
            valid_until_unix_ms=valid_until_unix_ms,
            source_sha256=source_sha256,
        )

    @property
    def realized_loss(self) -> int:
        return max(-self.realized_net_profit, 0)

    @property
    def allowed(self) -> bool:
        return self._allowed

    @property
    def reasons(self) -> tuple[str, ...]:
        return self._reasons

    @property
    def evidence_id(self) -> str:
        return self._evidence_id

    def is_valid_at(self, at_unix_ms: int) -> bool:
        _time("at_unix_ms", at_unix_ms)
        return self.observed_at_unix_ms <= at_unix_ms <= self.valid_until_unix_ms

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "evidence_id": self.evidence_id,
            "risk_policy_id": self.risk_policy_id,
            "execution_plan_sha256": self.execution_plan_sha256,
            "limits": _limits_to_json(self.limits),
            "realized_net_profit": str(self.realized_net_profit),
            "realized_loss": str(self.realized_loss),
            "reserved_execution_cost": str(self.reserved_execution_cost),
            "concurrent_candidates": str(self.concurrent_candidates),
            "requested_execution_cost": str(self.requested_execution_cost),
            "requested_notional": str(self.requested_notional),
            "allowed": self.allowed,
            "reasons": list(self.reasons),
            "observed_at_unix_ms": str(self.observed_at_unix_ms),
            "valid_until_unix_ms": str(self.valid_until_unix_ms),
            "source_sha256": self.source_sha256,
            "authority": "recorded-risk-budget-snapshot-shadow-only",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())
