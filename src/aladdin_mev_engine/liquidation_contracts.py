from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import re
from types import MappingProxyType
from typing import Mapping

from .canonical import canonical_sha256
from .domain import require_bounded_text

WAD = 10**18
MAX_UINT256 = (1 << 256) - 1
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_PROTOCOL_ID = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$")


class LiquidationProtocol(StrEnum):
    AAVE_V3 = "aave-v3"
    MORPHO_BLUE = "morpho-blue"


class EligibilityMetric(StrEnum):
    HEALTH_FACTOR_WAD = "health-factor-wad"
    BORROWED_ASSETS_VS_MAX_BORROW_ASSETS = "borrowed-assets-vs-max-borrow-assets"


class LiquidationComparator(StrEnum):
    STRICTLY_BELOW = "strictly-below"
    STRICTLY_ABOVE = "strictly-above"


def _require_uint256(name: str, value: object, *, positive: bool = False) -> None:
    if type(value) is not int or not 0 <= value <= MAX_UINT256:
        raise ValueError(f"{name} must be an unsigned 256-bit integer")
    if positive and value == 0:
        raise ValueError(f"{name} must be positive")


@dataclass(frozen=True, slots=True)
class LiquidationMechanism:
    protocol: LiquidationProtocol
    mechanism_version: str
    metric: EligibilityMetric
    comparator: LiquidationComparator
    fixed_denominator: int | None
    source_repository: str
    source_commit: str
    source_path: str
    source_reference: str
    docs_reference: str

    SCHEMA = "aladdin-mev-liquidation-mechanism/v1"

    def __post_init__(self) -> None:
        if type(self.protocol) is not LiquidationProtocol:
            raise TypeError("protocol must be an exact LiquidationProtocol")
        if _PROTOCOL_ID.fullmatch(self.protocol.value) is None:
            raise ValueError("protocol identifier is not canonical")
        require_bounded_text("mechanism_version", self.mechanism_version, maximum=128)
        if type(self.metric) is not EligibilityMetric:
            raise TypeError("metric must be an exact EligibilityMetric")
        if type(self.comparator) is not LiquidationComparator:
            raise TypeError("comparator must be an exact LiquidationComparator")
        if self.fixed_denominator is not None:
            _require_uint256("fixed_denominator", self.fixed_denominator, positive=True)
        require_bounded_text("source_repository", self.source_repository, maximum=128)
        if self.source_repository.count("/") != 1:
            raise ValueError("source_repository must be an owner/repository identifier")
        if type(self.source_commit) is not str or _COMMIT.fullmatch(self.source_commit) is None:
            raise ValueError("source_commit must be a lowercase 40-character commit SHA")
        require_bounded_text("source_path", self.source_path, maximum=256)
        for name in ("source_reference", "docs_reference"):
            value = getattr(self, name)
            require_bounded_text(name, value, maximum=1024)
            if not value.startswith("https://"):
                raise ValueError(f"{name} must use HTTPS")

        if self.protocol is LiquidationProtocol.AAVE_V3:
            if self.metric is not EligibilityMetric.HEALTH_FACTOR_WAD:
                raise ValueError("Aave V3 must use the health-factor metric")
            if self.comparator is not LiquidationComparator.STRICTLY_BELOW:
                raise ValueError("Aave V3 liquidation threshold is strict-below")
            if self.fixed_denominator != WAD:
                raise ValueError("Aave V3 health factor denominator must be WAD")
        elif self.protocol is LiquidationProtocol.MORPHO_BLUE:
            if self.metric is not EligibilityMetric.BORROWED_ASSETS_VS_MAX_BORROW_ASSETS:
                raise ValueError("Morpho Blue must compare borrowed assets to max borrow")
            if self.comparator is not LiquidationComparator.STRICTLY_ABOVE:
                raise ValueError("Morpho Blue liquidation threshold is strict-above")
            if self.fixed_denominator is not None:
                raise ValueError("Morpho Blue max borrow is position-specific")

    def validate_metric(self, numerator: object, denominator: object) -> None:
        _require_uint256("metric_numerator", numerator)
        _require_uint256("metric_denominator", denominator, positive=True)
        if self.fixed_denominator is not None and denominator != self.fixed_denominator:
            raise ValueError("metric denominator does not match the mechanism contract")

    def is_liquidatable(self, numerator: int, denominator: int) -> bool:
        self.validate_metric(numerator, denominator)
        if self.comparator is LiquidationComparator.STRICTLY_BELOW:
            return numerator < denominator
        if self.comparator is LiquidationComparator.STRICTLY_ABOVE:
            return numerator > denominator
        raise AssertionError("unreachable liquidation comparator")

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.SCHEMA,
            "protocol": self.protocol.value,
            "mechanism_version": self.mechanism_version,
            "metric": self.metric.value,
            "comparator": self.comparator.value,
            "fixed_denominator": (
                None if self.fixed_denominator is None else str(self.fixed_denominator)
            ),
            "source_repository": self.source_repository,
            "source_commit": self.source_commit,
            "source_path": self.source_path,
            "source_reference": self.source_reference,
            "docs_reference": self.docs_reference,
            "deployment_authority": "none-recorded-input-only",
            "network_authority": "none",
            "execution_authority": "none",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


_MECHANISMS = (
    LiquidationMechanism(
        protocol=LiquidationProtocol.AAVE_V3,
        mechanism_version="aave-v3.7-origin",
        metric=EligibilityMetric.HEALTH_FACTOR_WAD,
        comparator=LiquidationComparator.STRICTLY_BELOW,
        fixed_denominator=WAD,
        source_repository="aave-dao/aave-v3-origin",
        source_commit="cff15de6d1271b0c800fc001f4aea4c263e8a597",
        source_path="src/contracts/protocol/libraries/logic/ValidationLogic.sol",
        source_reference=(
            "https://github.com/aave-dao/aave-v3-origin/blob/"
            "cff15de6d1271b0c800fc001f4aea4c263e8a597/"
            "src/contracts/protocol/libraries/logic/ValidationLogic.sol"
        ),
        docs_reference="https://aave.com/help/borrowing/liquidations",
    ),
    LiquidationMechanism(
        protocol=LiquidationProtocol.MORPHO_BLUE,
        mechanism_version="morpho-blue-core",
        metric=EligibilityMetric.BORROWED_ASSETS_VS_MAX_BORROW_ASSETS,
        comparator=LiquidationComparator.STRICTLY_ABOVE,
        fixed_denominator=None,
        source_repository="morpho-org/morpho-blue",
        source_commit="d09dd1c4b9c7d9d05f976faa7ebfdc424dae5e8c",
        source_path="src/Morpho.sol",
        source_reference=(
            "https://github.com/morpho-org/morpho-blue/blob/"
            "d09dd1c4b9c7d9d05f976faa7ebfdc424dae5e8c/src/Morpho.sol"
        ),
        docs_reference="https://docs.morpho.org/developers/borrow/concepts/liquidation/",
    ),
)

if tuple(sorted(_MECHANISMS, key=lambda item: item.protocol.value)) != _MECHANISMS:
    raise RuntimeError("liquidation mechanisms must be sorted canonically")
if len({item.protocol for item in _MECHANISMS}) != len(_MECHANISMS):
    raise RuntimeError("liquidation mechanism protocol identifiers must be unique")

LIQUIDATION_MECHANISMS: Mapping[LiquidationProtocol, LiquidationMechanism] = MappingProxyType(
    {item.protocol: item for item in _MECHANISMS}
)


def get_liquidation_mechanism(protocol: LiquidationProtocol) -> LiquidationMechanism:
    if type(protocol) is not LiquidationProtocol:
        raise TypeError("protocol must be an exact LiquidationProtocol")
    return LIQUIDATION_MECHANISMS[protocol]


def liquidation_mechanism_set_digest() -> str:
    return canonical_sha256(
        [
            LIQUIDATION_MECHANISMS[protocol].to_json_value()
            for protocol in sorted(LIQUIDATION_MECHANISMS, key=lambda item: item.value)
        ]
    )
