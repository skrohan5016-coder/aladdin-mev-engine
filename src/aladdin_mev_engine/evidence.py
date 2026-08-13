from __future__ import annotations

from dataclasses import dataclass

from .canonical import canonical_sha256
from .domain import (
    ChainHealth,
    StateReference,
    Strategy,
    require_bounded_text,
    require_non_negative_int,
    require_sha256,
)
from .profit import CostBreakdown, ProfitAssessment, ProfitPolicy, assess_profit

EVIDENCE_SCHEMA_ID = "aladdin-mev-simulation-evidence/v1"


@dataclass(frozen=True, slots=True)
class SimulationResult:
    engine_id: str
    success: bool
    gas_units: int
    output_amount: int
    post_state_digest: str
    error_code: str | None = None

    def __post_init__(self) -> None:
        require_bounded_text("engine_id", self.engine_id, maximum=128)
        if not isinstance(self.success, bool):
            raise ValueError("success must be boolean")
        require_non_negative_int("gas_units", self.gas_units)
        require_non_negative_int("output_amount", self.output_amount)
        require_sha256("post_state_digest", self.post_state_digest)
        if self.error_code is not None:
            require_bounded_text("error_code", self.error_code, maximum=128)
        if self.success and self.error_code is not None:
            raise ValueError("successful simulation cannot carry an error code")

    def to_json_value(self) -> dict[str, object]:
        return {
            "engine_id": self.engine_id,
            "success": self.success,
            "gas_units": str(self.gas_units),
            "output_amount": str(self.output_amount),
            "post_state_digest": self.post_state_digest,
            "error_code": self.error_code,
        }


def dual_simulations_agree(simulations: tuple[SimulationResult, ...]) -> bool:
    if len(simulations) < 2:
        return False
    engine_ids = {result.engine_id for result in simulations}
    if len(engine_ids) != len(simulations):
        return False
    reference = simulations[0]
    if not reference.success:
        return False
    return all(
        result.success
        and result.gas_units == reference.gas_units
        and result.output_amount == reference.output_amount
        and result.post_state_digest == reference.post_state_digest
        and result.error_code == reference.error_code
        for result in simulations[1:]
    )


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    opportunity_id: str
    strategy: Strategy
    state_reference: StateReference
    capital_at_risk: int
    costs: CostBreakdown
    simulations: tuple[SimulationResult, ...]
    profit_policy: ProfitPolicy
    chain_health: ChainHealth
    risk_budget_available: bool
    created_at_unix_ms: int
    schema: str = EVIDENCE_SCHEMA_ID

    def __post_init__(self) -> None:
        require_bounded_text("opportunity_id", self.opportunity_id, maximum=128)
        require_non_negative_int("capital_at_risk", self.capital_at_risk)
        require_non_negative_int("created_at_unix_ms", self.created_at_unix_ms)
        if self.schema != EVIDENCE_SCHEMA_ID:
            raise ValueError("unsupported evidence schema")
        if not isinstance(self.risk_budget_available, bool):
            raise ValueError("risk_budget_available must be boolean")
        if self.created_at_unix_ms < self.state_reference.observed_at_unix_ms:
            raise ValueError("evidence creation time cannot precede state observation")
        if len(self.simulations) < 2:
            raise ValueError("at least two independent simulations are required")
        if len(self.simulations) > 8:
            raise ValueError("at most eight independent simulations are supported")

    @property
    def state_age_ms(self) -> int:
        return self.created_at_unix_ms - self.state_reference.observed_at_unix_ms

    @property
    def decision(self) -> ProfitAssessment:
        return assess_profit(
            self.costs,
            self.profit_policy,
            capital_at_risk=self.capital_at_risk,
            state_age_ms=self.state_age_ms,
            simulations_agree=dual_simulations_agree(self.simulations),
            chain_health=self.chain_health,
            risk_budget_available=self.risk_budget_available,
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "opportunity_id": self.opportunity_id,
            "strategy": self.strategy.value,
            "state_reference": self.state_reference.to_json_value(),
            "capital_at_risk": str(self.capital_at_risk),
            "costs": self.costs.to_json_value(),
            "simulations": [result.to_json_value() for result in self.simulations],
            "profit_policy": self.profit_policy.to_json_value(),
            "chain_health": self.chain_health.value,
            "risk_budget_available": self.risk_budget_available,
            "decision": self.decision.to_json_value(),
            "created_at_unix_ms": str(self.created_at_unix_ms),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())
