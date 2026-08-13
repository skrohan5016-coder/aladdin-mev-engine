from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .domain import ChainHealth, require_non_negative_int

BASIS_POINTS = 10_000


class ProfitReason(StrEnum):
    NON_POSITIVE_GROSS_PROFIT = "non-positive-gross-profit"
    SIMULATION_DISAGREEMENT = "simulation-disagreement"
    CHAIN_UNHEALTHY = "chain-unhealthy"
    STATE_TOO_OLD = "state-too-old"
    RISK_BUDGET_UNAVAILABLE = "risk-budget-unavailable"
    BID_EXCEEDS_POLICY = "bid-exceeds-policy"
    BELOW_ABSOLUTE_MINIMUM = "below-absolute-minimum"
    BELOW_REQUIRED_RETURN = "below-required-return"


@dataclass(frozen=True, slots=True)
class CostBreakdown:
    gross_profit: int
    execution_gas_cost: int
    l1_data_fee: int
    flash_loan_fee: int
    inclusion_bid: int
    slippage_reserve: int
    stale_state_reserve: int
    failure_risk_reserve: int
    infrastructure_cost: int
    inventory_hedge_cost: int

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            require_non_negative_int(name, getattr(self, name))

    @property
    def cost_excluding_bid(self) -> int:
        return (
            self.execution_gas_cost
            + self.l1_data_fee
            + self.flash_loan_fee
            + self.slippage_reserve
            + self.stale_state_reserve
            + self.failure_risk_reserve
            + self.infrastructure_cost
            + self.inventory_hedge_cost
        )

    @property
    def surplus_before_bid(self) -> int:
        return self.gross_profit - self.cost_excluding_bid

    @property
    def total_cost(self) -> int:
        return self.cost_excluding_bid + self.inclusion_bid

    @property
    def conservative_net_profit(self) -> int:
        return self.gross_profit - self.total_cost

    def to_json_value(self) -> dict[str, str]:
        return {name: str(getattr(self, name)) for name in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class ProfitPolicy:
    policy_id: str
    minimum_absolute_profit: int
    minimum_return_bps: int
    maximum_bid_fraction_bps: int
    maximum_state_age_ms: int

    def __post_init__(self) -> None:
        if not self.policy_id or len(self.policy_id) > 128:
            raise ValueError("policy_id must be non-empty and at most 128 characters")
        for name in (
            "minimum_absolute_profit",
            "minimum_return_bps",
            "maximum_bid_fraction_bps",
            "maximum_state_age_ms",
        ):
            require_non_negative_int(name, getattr(self, name))
        if self.maximum_bid_fraction_bps > BASIS_POINTS:
            raise ValueError("maximum_bid_fraction_bps cannot exceed 10000")


    def to_json_value(self) -> dict[str, str]:
        return {
            "policy_id": self.policy_id,
            "minimum_absolute_profit": str(self.minimum_absolute_profit),
            "minimum_return_bps": str(self.minimum_return_bps),
            "maximum_bid_fraction_bps": str(self.maximum_bid_fraction_bps),
            "maximum_state_age_ms": str(self.maximum_state_age_ms),
        }


@dataclass(frozen=True, slots=True)
class ProfitAssessment:
    approved: bool
    policy_id: str
    conservative_net_profit: int
    surplus_before_bid: int
    reasons: tuple[ProfitReason, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.approved, bool):
            raise ValueError("approved must be boolean")
        if not self.policy_id or len(self.policy_id) > 128:
            raise ValueError("policy_id must be non-empty and at most 128 characters")
        for name in ("conservative_net_profit", "surplus_before_bid"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
        if self.approved and self.reasons:
            raise ValueError("approved assessment cannot contain rejection reasons")
        if not self.approved and not self.reasons:
            raise ValueError("rejected assessment must contain at least one reason")
        if len(set(self.reasons)) != len(self.reasons):
            raise ValueError("assessment reasons must be unique")

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": "aladdin-mev-execution-decision/v1",
            "approved": self.approved,
            "policy_id": self.policy_id,
            "conservative_net_profit": str(self.conservative_net_profit),
            "surplus_before_bid": str(self.surplus_before_bid),
            "reasons": [reason.value for reason in self.reasons],
        }


def assess_profit(
    costs: CostBreakdown,
    policy: ProfitPolicy,
    *,
    capital_at_risk: int,
    state_age_ms: int,
    simulations_agree: bool,
    chain_health: ChainHealth,
    risk_budget_available: bool,
) -> ProfitAssessment:
    require_non_negative_int("capital_at_risk", capital_at_risk)
    require_non_negative_int("state_age_ms", state_age_ms)
    if not isinstance(simulations_agree, bool):
        raise ValueError("simulations_agree must be boolean")
    if not isinstance(risk_budget_available, bool):
        raise ValueError("risk_budget_available must be boolean")

    reasons: list[ProfitReason] = []
    if costs.gross_profit <= 0:
        reasons.append(ProfitReason.NON_POSITIVE_GROSS_PROFIT)
    if not simulations_agree:
        reasons.append(ProfitReason.SIMULATION_DISAGREEMENT)
    if chain_health is not ChainHealth.HEALTHY:
        reasons.append(ProfitReason.CHAIN_UNHEALTHY)
    if state_age_ms > policy.maximum_state_age_ms:
        reasons.append(ProfitReason.STATE_TOO_OLD)
    if not risk_budget_available:
        reasons.append(ProfitReason.RISK_BUDGET_UNAVAILABLE)

    bid_capacity = max(costs.surplus_before_bid, 0)
    if costs.inclusion_bid * BASIS_POINTS > bid_capacity * policy.maximum_bid_fraction_bps:
        reasons.append(ProfitReason.BID_EXCEEDS_POLICY)

    if costs.conservative_net_profit < policy.minimum_absolute_profit:
        reasons.append(ProfitReason.BELOW_ABSOLUTE_MINIMUM)

    if capital_at_risk > 0 and (
        costs.conservative_net_profit * BASIS_POINTS
        < capital_at_risk * policy.minimum_return_bps
    ):
        reasons.append(ProfitReason.BELOW_REQUIRED_RETURN)

    return ProfitAssessment(
        approved=not reasons,
        policy_id=policy.policy_id,
        conservative_net_profit=costs.conservative_net_profit,
        surplus_before_bid=costs.surplus_before_bid,
        reasons=tuple(reasons),
    )
