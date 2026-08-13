from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import re
from typing import Any

from .canonical import canonical_sha256
from .domain import (
    Chain,
    StateReference,
    Strategy,
    require_bounded_text,
    require_sha256,
)
from .liquidation_contracts import (
    MAX_UINT256,
    EligibilityMetric,
    LiquidationProtocol,
    get_liquidation_mechanism,
)

_EVM_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
_CANONICAL_ID = re.compile(r"^[a-z0-9](?:[a-z0-9._:-]{0,126}[a-z0-9])?$")
MAX_OBSERVATION_DIGESTS = 64


class DiscoveryReason(StrEnum):
    CANDIDATE = "candidate"
    NOT_LIQUIDATABLE = "not-liquidatable"
    NON_POSITIVE_GROSS_EDGE = "non-positive-gross-edge"


def _require_uint256(name: str, value: object, *, positive: bool = False) -> None:
    if type(value) is not int or not 0 <= value <= MAX_UINT256:
        raise ValueError(f"{name} must be an unsigned 256-bit integer")
    if positive and value == 0:
        raise ValueError(f"{name} must be positive")


def _require_evm_address(name: str, value: object) -> None:
    if type(value) is not str or _EVM_ADDRESS.fullmatch(value) is None:
        raise ValueError(f"{name} must be a canonical lowercase EVM address")
    if value == "0x" + "0" * 40:
        raise ValueError(f"{name} cannot be the zero address")


def _require_canonical_id(name: str, value: object) -> None:
    if type(value) is not str or _CANONICAL_ID.fullmatch(value) is None:
        raise ValueError(f"{name} must be a canonical lowercase identifier")


@dataclass(frozen=True, slots=True)
class LiquidationSnapshot:
    protocol: LiquidationProtocol
    chain: Chain
    deployment_address: str
    deployment_evidence_sha256: str
    market_id: str
    borrower: str
    debt_asset: str
    collateral_asset: str
    state_reference: StateReference
    observation_digests: tuple[str, ...]
    metric_numerator: int
    metric_denominator: int
    repay_amount: int
    seize_amount: int
    valuation_unit: str
    repay_value: int
    seize_value: int
    valuation_evidence_sha256: str

    SCHEMA = "aladdin-mev-liquidation-snapshot/v1"

    def __post_init__(self) -> None:
        if type(self.protocol) is not LiquidationProtocol:
            raise TypeError("protocol must be an exact LiquidationProtocol")
        if type(self.chain) is not Chain:
            raise TypeError("chain must be an exact Chain")
        if self.chain is Chain.SOLANA:
            raise ValueError("F2 liquidation discovery supports recorded EVM state only")
        for name in (
            "deployment_address",
            "borrower",
            "debt_asset",
            "collateral_asset",
        ):
            _require_evm_address(name, getattr(self, name))
        require_sha256("deployment_evidence_sha256", self.deployment_evidence_sha256)
        require_bounded_text("market_id", self.market_id, maximum=256)
        if type(self.state_reference) is not StateReference:
            raise TypeError("state_reference must be an exact StateReference")
        if self.state_reference.chain is not self.chain:
            raise ValueError("state reference chain does not match liquidation snapshot")
        if type(self.observation_digests) is not tuple:
            raise TypeError("observation_digests must be an exact tuple")
        if not 1 <= len(self.observation_digests) <= MAX_OBSERVATION_DIGESTS:
            raise ValueError("observation_digests count is outside the governed range")
        for digest in self.observation_digests:
            require_sha256("observation_digest", digest)
        if len(set(self.observation_digests)) != len(self.observation_digests):
            raise ValueError("observation_digests must be unique")
        if tuple(sorted(self.observation_digests)) != self.observation_digests:
            raise ValueError("observation_digests must be sorted canonically")

        mechanism = get_liquidation_mechanism(self.protocol)
        mechanism.validate_metric(self.metric_numerator, self.metric_denominator)
        for name in ("repay_amount", "seize_amount", "repay_value", "seize_value"):
            _require_uint256(name, getattr(self, name), positive=True)
        _require_canonical_id("valuation_unit", self.valuation_unit)
        require_sha256("valuation_evidence_sha256", self.valuation_evidence_sha256)

    @property
    def mechanism_contract_sha256(self) -> str:
        return get_liquidation_mechanism(self.protocol).digest

    @property
    def eligibility_metric(self) -> EligibilityMetric:
        return get_liquidation_mechanism(self.protocol).metric

    @property
    def liquidatable(self) -> bool:
        return get_liquidation_mechanism(self.protocol).is_liquidatable(
            self.metric_numerator,
            self.metric_denominator,
        )

    @property
    def positive_gross_edge(self) -> bool:
        return self.seize_value > self.repay_value

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.SCHEMA,
            "protocol": self.protocol.value,
            "chain": self.chain.value,
            "deployment_address": self.deployment_address,
            "deployment_evidence_sha256": self.deployment_evidence_sha256,
            "market_id": self.market_id,
            "borrower": self.borrower,
            "debt_asset": self.debt_asset,
            "collateral_asset": self.collateral_asset,
            "state_reference": self.state_reference.to_json_value(),
            "observation_digests": list(self.observation_digests),
            "eligibility_metric": self.eligibility_metric.value,
            "metric_numerator": str(self.metric_numerator),
            "metric_denominator": str(self.metric_denominator),
            "repay_amount": str(self.repay_amount),
            "seize_amount": str(self.seize_amount),
            "valuation_unit": self.valuation_unit,
            "repay_value": str(self.repay_value),
            "seize_value": str(self.seize_value),
            "valuation_evidence_sha256": self.valuation_evidence_sha256,
            "mechanism_contract_sha256": self.mechanism_contract_sha256,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class LiquidationCandidate:
    snapshot: LiquidationSnapshot

    SCHEMA = "aladdin-mev-liquidation-candidate/v1"

    def __post_init__(self) -> None:
        if type(self.snapshot) is not LiquidationSnapshot:
            raise TypeError("snapshot must be an exact LiquidationSnapshot")
        if not self.snapshot.liquidatable:
            raise ValueError("a non-liquidatable snapshot cannot become a candidate")
        if not self.snapshot.positive_gross_edge:
            raise ValueError("candidate requires a positive same-unit gross edge")

    @property
    def gross_profit(self) -> int:
        return self.snapshot.seize_value - self.snapshot.repay_value

    @property
    def capital_at_risk(self) -> int:
        return self.snapshot.repay_value

    @property
    def opportunity_id(self) -> str:
        identity = {
            "schema": "aladdin-mev-liquidation-opportunity-identity/v1",
            "strategy": Strategy.LIQUIDATION.value,
            "snapshot_sha256": self.snapshot.digest,
            "mechanism_contract_sha256": self.snapshot.mechanism_contract_sha256,
        }
        return "liq-" + canonical_sha256(identity)

    def to_json_value(self) -> dict[str, object]:
        snapshot = self.snapshot
        return {
            "schema": self.SCHEMA,
            "opportunity_id": self.opportunity_id,
            "chain": snapshot.chain.value,
            "strategy": Strategy.LIQUIDATION.value,
            "protocol": snapshot.protocol.value,
            "mechanism_contract_sha256": snapshot.mechanism_contract_sha256,
            "deployment_address": snapshot.deployment_address,
            "deployment_evidence_sha256": snapshot.deployment_evidence_sha256,
            "market_id": snapshot.market_id,
            "borrower": snapshot.borrower,
            "debt_asset": snapshot.debt_asset,
            "collateral_asset": snapshot.collateral_asset,
            "state_reference": snapshot.state_reference.to_json_value(),
            "observation_digests": list(snapshot.observation_digests),
            "eligibility_metric": snapshot.eligibility_metric.value,
            "metric_numerator": str(snapshot.metric_numerator),
            "metric_denominator": str(snapshot.metric_denominator),
            "repay_amount": str(snapshot.repay_amount),
            "seize_amount": str(snapshot.seize_amount),
            "valuation_unit": snapshot.valuation_unit,
            "repay_value": str(snapshot.repay_value),
            "seize_value": str(snapshot.seize_value),
            "gross_profit": str(self.gross_profit),
            "capital_at_risk": str(self.capital_at_risk),
            "valuation_evidence_sha256": snapshot.valuation_evidence_sha256,
            "snapshot_sha256": snapshot.digest,
            "execution_authority": "none",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class LiquidationDiscoveryDecision:
    snapshot: LiquidationSnapshot

    SCHEMA = "aladdin-mev-liquidation-discovery-decision/v1"

    def __post_init__(self) -> None:
        if type(self.snapshot) is not LiquidationSnapshot:
            raise TypeError("snapshot must be an exact LiquidationSnapshot")

    @property
    def reason(self) -> DiscoveryReason:
        if not self.snapshot.liquidatable:
            return DiscoveryReason.NOT_LIQUIDATABLE
        if not self.snapshot.positive_gross_edge:
            return DiscoveryReason.NON_POSITIVE_GROSS_EDGE
        return DiscoveryReason.CANDIDATE

    @property
    def candidate(self) -> LiquidationCandidate | None:
        if self.reason is DiscoveryReason.CANDIDATE:
            return LiquidationCandidate(self.snapshot)
        return None

    def to_json_value(self) -> dict[str, Any]:
        candidate = self.candidate
        return {
            "schema": self.SCHEMA,
            "snapshot_sha256": self.snapshot.digest,
            "mechanism_contract_sha256": self.snapshot.mechanism_contract_sha256,
            "liquidatable": self.snapshot.liquidatable,
            "positive_gross_edge": self.snapshot.positive_gross_edge,
            "reason": self.reason.value,
            "candidate": None if candidate is None else candidate.to_json_value(),
            "execution_authority": "none",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


def discover_liquidation(snapshot: LiquidationSnapshot) -> LiquidationDiscoveryDecision:
    if type(snapshot) is not LiquidationSnapshot:
        raise TypeError("snapshot must be an exact LiquidationSnapshot")
    return LiquidationDiscoveryDecision(snapshot)
