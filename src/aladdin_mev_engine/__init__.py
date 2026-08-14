"""Governed offline authenticated-state and gross-opportunity core for F3."""

from .constant_product import (
    AuthenticatedConstantProductPool,
    ConstantProductArithmeticError,
    ConstantProductImplementationSpec,
    ConstantProductModelRegistry,
    ConstantProductPoolSpec,
    PackedStorageField,
    PoolSwapQuote,
    PoolUniverse,
)
from .domain import Chain, ChainHealth, OperatingMode, StateReference, Strategy
from .evidence import EvidenceRecord, SimulationResult, dual_simulations_agree
from .head_tracker import EvmHead, HeadTracker, HeadTransition, HeadTransitionKind
from .keccak import keccak256, keccak256_hex
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
from .mpt import EMPTY_TRIE_ROOT, MptProofResult, MptTerminal, verify_mpt_proof
from .observation import ObservationEnvelope
from .opportunity import AtomicDexOpportunityEvidence, OpportunitySearchReport
from .opportunity_graph import (
    ConstantProductRoute,
    RouteLeg,
    RouteQuote,
    enumerate_simple_cycles,
)
from .optimizer import (
    OptimizationLimits,
    OptimizationResult,
    OptimizationStatus,
    optimize_route,
)
from .policy import StrategyPolicy
from .profit import CostBreakdown, ProfitAssessment, ProfitPolicy, assess_profit
from .risk import RiskGovernor, RiskLedger, RiskLimits
from .rlp import RlpError, rlp_decode, rlp_encode
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
from .state_proof import (
    EMPTY_CODE_HASH,
    EvmBlockStateAnchor,
    EvmStateProofEvidence,
    EvmStateSnapshot,
    VerifiedStorageValue,
)

__all__ = [
    "AtomicDexOpportunityEvidence",
    "AuthenticatedConstantProductPool",
    "Chain",
    "ChainHealth",
    "ConstantProductArithmeticError",
    "ConstantProductImplementationSpec",
    "ConstantProductModelRegistry",
    "ConstantProductPoolSpec",
    "ConstantProductRoute",
    "CostBreakdown",
    "EMPTY_CODE_HASH",
    "EMPTY_TRIE_ROOT",
    "EventShape",
    "EvidenceRecord",
    "EvmBlockStateAnchor",
    "EvmHead",
    "EvmStateProofEvidence",
    "EvmStateSnapshot",
    "Finality",
    "HeadTracker",
    "HeadTransition",
    "HeadTransitionKind",
    "LedgerRecord",
    "MptProofResult",
    "MptTerminal",
    "ObservationEnvelope",
    "ObservationKind",
    "ObservationLedgerBuilder",
    "ObservationSegment",
    "OperatingMode",
    "OpportunitySearchReport",
    "OptimizationLimits",
    "OptimizationResult",
    "OptimizationStatus",
    "PackedStorageField",
    "PoolSwapQuote",
    "PoolUniverse",
    "ProfitAssessment",
    "ProfitPolicy",
    "RiskGovernor",
    "RiskLedger",
    "RiskLimits",
    "RlpError",
    "RouteLeg",
    "RouteQuote",
    "SegmentManifest",
    "SimulationResult",
    "SourceCheckpoint",
    "SourceContract",
    "SourceKind",
    "StateReference",
    "Strategy",
    "StrategyPolicy",
    "Transport",
    "VerifiedStorageValue",
    "Visibility",
    "assess_profit",
    "dual_simulations_agree",
    "enumerate_simple_cycles",
    "get_source_contract",
    "keccak256",
    "keccak256_hex",
    "optimize_route",
    "parse_segment",
    "read_segment_stable",
    "rlp_decode",
    "rlp_encode",
    "serialize_segment",
    "source_contract_set_digest",
    "validate_segment_chain",
    "verify_mpt_proof",
    "write_segment_once",
]

__version__ = "0.4.0"
