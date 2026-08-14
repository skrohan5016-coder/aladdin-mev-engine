from __future__ import annotations

from functools import lru_cache

from aladdin_mev_engine.assets import (
    AssetAmount,
    AssetId,
    ConservativeValuationRate,
    ValuationBook,
)
from aladdin_mev_engine.canonical import canonical_sha256
from aladdin_mev_engine.context_evidence import ChainHealthEvidence, RiskBudgetEvidence
from aladdin_mev_engine.cost_evidence import (
    ConservativeNetProfitEvidence,
    Eip1559CostEnvelope,
    ExecutionCostEnvelope,
    ReserveCostCategory,
    ReserveCostComponent,
    RouteSimulationResult,
)
from aladdin_mev_engine.domain import ChainHealth
from aladdin_mev_engine.execution_plan import AtomicExecutionPlan, FundingKind, FundingPlan
from aladdin_mev_engine.opportunity import OpportunitySearchReport
from aladdin_mev_engine.optimizer import OptimizationLimits
from aladdin_mev_engine.profit import ProfitPolicy
from aladdin_mev_engine.risk import RiskLimits

from f3_helpers import TOKEN_A, TOKEN_B, authenticated_universe, pool_fixture

SOURCE_A = "11" * 32
SOURCE_B = "22" * 32
SOURCE_C = "33" * 32
TOKEN_DELTAS = "44" * 32
POST_STATE = "55" * 32
ENGINE_A = "66" * 32
ENGINE_B = "77" * 32
ENVIRONMENT = "88" * 32
SIMULATION_SOURCE_A = "99" * 32
SIMULATION_SOURCE_B = "aa" * 32
CHAIN_HEALTH_SOURCE = "bb" * 32
RISK_SOURCE = "cc" * 32


@lru_cache(maxsize=1)
def profitable_opportunity():
    state = authenticated_universe(
        (
            pool_fixture(
                address_byte=1,
                token0=TOKEN_A,
                token1=TOKEN_B,
                reserve0=1_000_000,
                reserve1=2_000_000,
            ),
            pool_fixture(
                address_byte=2,
                token0=TOKEN_A,
                token1=TOKEN_B,
                reserve0=1_500_000,
                reserve1=1_000_000,
            ),
        )
    )
    report = OpportunitySearchReport(
        state,
        TOKEN_A,
        4,
        OptimizationLimits(50_000),
        state.observed_at_unix_ms + 1,
    )
    return report.opportunities()[0]


@lru_cache(maxsize=8)
def execution_plan(*, flash_fee: int = 25, kind: FundingKind = FundingKind.FLASH_LOAN):
    opportunity = profitable_opportunity()
    base = AssetId.erc20(opportunity.universe.chain, opportunity.route.base_token)
    created = opportunity.created_at_unix_ms + 1
    funding = FundingPlan(
        kind=kind,
        asset=base,
        principal=opportunity.capital_at_risk,
        fee=0 if kind is FundingKind.OWN_INVENTORY else flash_fee,
        provider_id="self" if kind is FundingKind.OWN_INVENTORY else "recorded-lender-a",
        observed_at_unix_ms=opportunity.created_at_unix_ms,
        valid_until_unix_ms=created + 10_000,
        source_sha256=SOURCE_A,
    )
    return AtomicExecutionPlan(opportunity, funding, created)


def reserve_components(plan: AtomicExecutionPlan, *, amount: int = 1):
    at = plan.created_at_unix_ms
    return tuple(
        ReserveCostComponent(
            category=category,
            amount=AssetAmount(plan.base_asset, amount),
            observed_at_unix_ms=at,
            valid_until_unix_ms=at + 10_000,
            source_sha256=SOURCE_B,
        )
        for category in ReserveCostCategory
    )


def cost_envelope(
    plan: AtomicExecutionPlan | None = None,
    *,
    native_to_base_numerator: int = 1,
    native_to_base_denominator: int = 1,
    gas_units_upper_bound: int = 100,
    max_fee_per_gas: int = 2,
    l1_data_fee_upper_bound: int = 0,
    direct_inclusion_payment_upper_bound: int = 3,
    reserve_amount: int = 1,
    validity_ms: int = 10_000,
):
    plan = execution_plan() if plan is None else plan
    native = AssetId.native(plan.opportunity.universe.chain)
    at = plan.created_at_unix_ms + 1
    valid_until = at + validity_ms
    fee = Eip1559CostEnvelope(
        chain=plan.opportunity.universe.chain,
        native_asset=native,
        gas_units_upper_bound=gas_units_upper_bound,
        max_fee_per_gas=max_fee_per_gas,
        max_priority_fee_per_gas=1,
        l1_data_fee_upper_bound=l1_data_fee_upper_bound,
        direct_inclusion_payment_upper_bound=direct_inclusion_payment_upper_bound,
        observed_at_unix_ms=plan.created_at_unix_ms,
        valid_until_unix_ms=valid_until,
        source_sha256=SOURCE_C,
    )
    components = tuple(
        ReserveCostComponent(
            category=item.category,
            amount=item.amount,
            observed_at_unix_ms=item.observed_at_unix_ms,
            valid_until_unix_ms=valid_until,
            source_sha256=item.source_sha256,
        )
        for item in reserve_components(plan, amount=reserve_amount)
    )
    book = ValuationBook(
        (
            ConservativeValuationRate(
                rate_id="native-to-base-upper-bound",
                asset_in=native,
                asset_out=plan.base_asset,
                numerator=native_to_base_numerator,
                denominator=native_to_base_denominator,
                observed_at_unix_ms=plan.created_at_unix_ms,
                valid_until_unix_ms=valid_until,
                source_sha256=SOURCE_C,
            ),
        )
    )
    return ExecutionCostEnvelope(
        plan=plan,
        fee_envelope=fee,
        reserve_components=components,
        valuation_book=book,
        created_at_unix_ms=at,
    )


def simulations(
    plan: AtomicExecutionPlan,
    *,
    gas_units: int = 90,
    output_delta: int = 0,
    validity_ms: int = 10_000,
):
    output = plan.opportunity.route_quote.amount_out + output_delta
    observed = plan.created_at_unix_ms + 2
    common = dict(
        success=True,
        opportunity_sha256=plan.opportunity.digest,
        execution_plan_sha256=plan.digest,
        state_reference_sha256=canonical_sha256(
            plan.opportunity.universe.state_reference.to_json_value()
        ),
        gas_units=gas_units,
        output_amount=output,
        token_deltas_sha256=TOKEN_DELTAS,
        post_state_sha256=POST_STATE,
        observed_at_unix_ms=observed,
        valid_until_unix_ms=observed + validity_ms,
    )
    return (
        RouteSimulationResult(
            engine_id="deterministic-engine-a",
            engine_implementation_sha256=ENGINE_A,
            environment_sha256=ENVIRONMENT,
            result_source_sha256=SIMULATION_SOURCE_A,
            **common,
        ),
        RouteSimulationResult(
            engine_id="independent-engine-b",
            engine_implementation_sha256=ENGINE_B,
            environment_sha256=ENVIRONMENT,
            result_source_sha256=SIMULATION_SOURCE_B,
            **common,
        ),
    )


def chain_health_context(
    plan: AtomicExecutionPlan,
    *,
    health: ChainHealth = ChainHealth.HEALTHY,
    observed_at_unix_ms: int | None = None,
    valid_until_unix_ms: int | None = None,
) -> ChainHealthEvidence:
    observed = plan.created_at_unix_ms + 2 if observed_at_unix_ms is None else observed_at_unix_ms
    valid_until = observed + 10_000 if valid_until_unix_ms is None else valid_until_unix_ms
    return ChainHealthEvidence(
        chain=plan.opportunity.universe.chain,
        health=health,
        observed_at_unix_ms=observed,
        valid_until_unix_ms=valid_until,
        source_sha256=CHAIN_HEALTH_SOURCE,
    )


def risk_budget_context(
    envelope: ExecutionCostEnvelope,
    *,
    available: bool = True,
    observed_at_unix_ms: int | None = None,
    valid_until_unix_ms: int | None = None,
) -> RiskBudgetEvidence:
    observed = envelope.created_at_unix_ms if observed_at_unix_ms is None else observed_at_unix_ms
    valid_until = observed + 10_000 if valid_until_unix_ms is None else valid_until_unix_ms
    total = envelope.costs.total_cost
    notional = envelope.plan.opportunity.capital_at_risk
    limits = RiskLimits(
        maximum_daily_loss=total + 1_000,
        maximum_single_execution_cost=total + 1_000 if available else max(total - 1, 0),
        maximum_pending_execution_cost=total + 1_000,
        maximum_concurrent_candidates=10,
        maximum_notional=notional + 1_000,
    )
    return RiskBudgetEvidence(
        risk_policy_id="f4-shadow-risk-policy",
        execution_plan_sha256=envelope.plan.digest,
        limits=limits,
        realized_net_profit=0,
        reserved_execution_cost=0,
        concurrent_candidates=0,
        requested_execution_cost=total,
        requested_notional=notional,
        observed_at_unix_ms=observed,
        valid_until_unix_ms=valid_until,
        source_sha256=RISK_SOURCE,
    )


def net_evidence(
    envelope: ExecutionCostEnvelope | None = None,
    *,
    simulation_rows=None,
    minimum_absolute_profit: int = 1,
    minimum_return_bps: int = 0,
    chain_health: ChainHealth = ChainHealth.HEALTHY,
    risk_budget_available: bool = True,
    health_evidence: ChainHealthEvidence | None = None,
    risk_evidence: RiskBudgetEvidence | None = None,
    created_at_unix_ms: int | None = None,
):
    envelope = cost_envelope() if envelope is None else envelope
    rows = simulations(envelope.plan) if simulation_rows is None else simulation_rows
    policy = ProfitPolicy(
        policy_id="f4-shadow-profit-policy",
        minimum_absolute_profit=minimum_absolute_profit,
        minimum_return_bps=minimum_return_bps,
        maximum_bid_fraction_bps=10_000,
        maximum_state_age_ms=1_000_000,
    )
    health = (
        chain_health_context(envelope.plan, health=chain_health)
        if health_evidence is None
        else health_evidence
    )
    risk = (
        risk_budget_context(envelope, available=risk_budget_available)
        if risk_evidence is None
        else risk_evidence
    )
    created = envelope.created_at_unix_ms + 3 if created_at_unix_ms is None else created_at_unix_ms
    return ConservativeNetProfitEvidence(
        cost_envelope=envelope,
        simulations=rows,
        profit_policy=policy,
        chain_health_evidence=health,
        risk_budget_evidence=risk,
        created_at_unix_ms=created,
    )
