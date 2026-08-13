"""Governed offline safety, observation, replay, and discovery core for F2."""

from .domain import Chain, ChainHealth, OperatingMode, StateReference, Strategy
from .evidence import EvidenceRecord, SimulationResult, dual_simulations_agree
from .head_tracker import EvmHead, HeadTracker, HeadTransition, HeadTransitionKind
from .ledger import (
    LedgerRecord,
    ObservationLedgerBuilder,
    ObservationSegment,
    SegmentManifest,
    SourceCheckpoint,
    parse_segment,
    serialize_segment,
    validate_segment_chain,
)
from .ledger_io import read_segment_stable, write_segment_once
from .liquidation import (
    DiscoveryReason,
    LiquidationCandidate,
    LiquidationDiscoveryDecision,
    LiquidationSnapshot,
    discover_liquidation,
)
from .liquidation_contracts import (
    LIQUIDATION_MECHANISMS,
    EligibilityMetric,
    LiquidationComparator,
    LiquidationMechanism,
    LiquidationProtocol,
    get_liquidation_mechanism,
    liquidation_mechanism_set_digest,
)
from .observation import ObservationEnvelope
from .policy import StrategyPolicy
from .profit import CostBreakdown, ProfitAssessment, ProfitPolicy, assess_profit
from .risk import RiskGovernor, RiskLedger, RiskLimits
from .source_contracts import (
    EventShape,
    Finality,
    ObservationKind,
    SourceContract,
    SourceKind,
    Transport,
    Visibility,
    get_source_contract,
    source_contract_set_digest,
)

__all__ = [
    "Chain",
    "ChainHealth",
    "CostBreakdown",
    "DiscoveryReason",
    "EligibilityMetric",
    "EventShape",
    "EvidenceRecord",
    "EvmHead",
    "Finality",
    "HeadTracker",
    "HeadTransition",
    "HeadTransitionKind",
    "LIQUIDATION_MECHANISMS",
    "LedgerRecord",
    "LiquidationCandidate",
    "LiquidationComparator",
    "LiquidationDiscoveryDecision",
    "LiquidationMechanism",
    "LiquidationProtocol",
    "LiquidationSnapshot",
    "ObservationEnvelope",
    "ObservationKind",
    "ObservationLedgerBuilder",
    "ObservationSegment",
    "OperatingMode",
    "ProfitAssessment",
    "ProfitPolicy",
    "RiskGovernor",
    "RiskLedger",
    "RiskLimits",
    "SegmentManifest",
    "SimulationResult",
    "SourceCheckpoint",
    "SourceContract",
    "SourceKind",
    "StateReference",
    "Strategy",
    "StrategyPolicy",
    "Transport",
    "Visibility",
    "assess_profit",
    "discover_liquidation",
    "dual_simulations_agree",
    "get_liquidation_mechanism",
    "get_source_contract",
    "liquidation_mechanism_set_digest",
    "parse_segment",
    "read_segment_stable",
    "serialize_segment",
    "source_contract_set_digest",
    "validate_segment_chain",
    "write_segment_once",
]

__version__ = "0.3.0"
