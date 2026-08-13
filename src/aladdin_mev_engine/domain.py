from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import re

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class Chain(StrEnum):
    ETHEREUM = "ethereum"
    BASE = "base"
    ARBITRUM = "arbitrum"
    BNB_SMART_CHAIN = "bnb-smart-chain"
    SOLANA = "solana"


class Strategy(StrEnum):
    ATOMIC_DEX_ARBITRAGE = "atomic-dex-arbitrage"
    CONSENSUAL_BACKRUN = "consensual-backrun"
    LIQUIDATION = "liquidation"
    INVENTORY_ASSISTED_ARBITRAGE = "inventory-assisted-arbitrage"
    CROSS_CHAIN_INVENTORY_REBALANCING = "cross-chain-inventory-rebalancing"


class OperatingMode(StrEnum):
    STOPPED = "stopped"
    SHADOW = "shadow"
    CANARY = "canary"
    LIVE = "live"
    DEGRADED = "degraded"
    HALTED = "halted"


class ChainHealth(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


def require_non_negative_int(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def require_bounded_text(name: str, value: str, *, maximum: int) -> None:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{name} must be non-empty text of at most {maximum} characters")
    if any(ord(char) < 0x20 for char in value):
        raise ValueError(f"{name} contains a control character")


def require_sha256(name: str, value: str) -> None:
    if not isinstance(value, str) or _HEX_64.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")


@dataclass(frozen=True, slots=True)
class StateReference:
    chain: Chain
    sequence_number: int
    sequence_hash: str
    observed_at_unix_ms: int
    state_digest: str

    def __post_init__(self) -> None:
        require_non_negative_int("sequence_number", self.sequence_number)
        require_non_negative_int("observed_at_unix_ms", self.observed_at_unix_ms)
        require_bounded_text("sequence_hash", self.sequence_hash, maximum=130)
        require_sha256("state_digest", self.state_digest)

    def to_json_value(self) -> dict[str, str]:
        return {
            "chain": self.chain.value,
            "sequence_number": str(self.sequence_number),
            "sequence_hash": self.sequence_hash,
            "observed_at_unix_ms": str(self.observed_at_unix_ms),
            "state_digest": self.state_digest,
        }
