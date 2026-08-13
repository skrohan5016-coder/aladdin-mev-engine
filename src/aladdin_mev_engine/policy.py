from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .domain import OperatingMode, Strategy


class PolicyReason(StrEnum):
    ALLOWED_SHADOW_STRATEGY = "allowed-shadow-strategy"
    UNKNOWN_STRATEGY = "unknown-strategy"
    PROHIBITED_STRATEGY = "prohibited-strategy"
    OPERATING_MODE_NOT_ACTIVE = "operating-mode-not-active"
    F0_EXECUTION_DISABLED = "f0-execution-disabled"


PROHIBITED_STRATEGIES = frozenset(
    {
        "sandwich",
        "harmful-frontrun",
        "oracle-manipulation",
        "protocol-exploit",
        "mempool-spam",
        "malicious-token",
        "stolen-key-use",
    }
)


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    reason: PolicyReason
    normalized_strategy: str


class StrategyPolicy:
    """F0 policy: approved strategies may be evaluated in shadow mode only."""

    def evaluate(self, strategy_id: str, mode: OperatingMode) -> PolicyDecision:
        normalized = strategy_id if isinstance(strategy_id, str) else ""
        if normalized in PROHIBITED_STRATEGIES:
            return PolicyDecision(False, PolicyReason.PROHIBITED_STRATEGY, normalized)
        try:
            Strategy(normalized)
        except ValueError:
            return PolicyDecision(False, PolicyReason.UNKNOWN_STRATEGY, normalized)

        if mode is OperatingMode.SHADOW:
            return PolicyDecision(True, PolicyReason.ALLOWED_SHADOW_STRATEGY, normalized)
        if mode in {OperatingMode.CANARY, OperatingMode.LIVE}:
            return PolicyDecision(False, PolicyReason.F0_EXECUTION_DISABLED, normalized)
        return PolicyDecision(False, PolicyReason.OPERATING_MODE_NOT_ACTIVE, normalized)
