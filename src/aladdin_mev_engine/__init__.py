"""Governed offline conformance core for Aladdin MEV Engine F0."""

from .domain import Chain, ChainHealth, OperatingMode, StateReference, Strategy
from .evidence import EvidenceRecord, SimulationResult, dual_simulations_agree
from .policy import StrategyPolicy
from .profit import CostBreakdown, ProfitAssessment, ProfitPolicy, assess_profit
from .risk import RiskGovernor, RiskLedger, RiskLimits

__all__ = [
    "Chain",
    "ChainHealth",
    "CostBreakdown",
    "EvidenceRecord",
    "OperatingMode",
    "ProfitAssessment",
    "ProfitPolicy",
    "RiskGovernor",
    "RiskLedger",
    "RiskLimits",
    "SimulationResult",
    "StateReference",
    "Strategy",
    "StrategyPolicy",
    "assess_profit",
    "dual_simulations_agree",
]

__version__ = "0.1.0"
