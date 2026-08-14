from __future__ import annotations

from aladdin_mev_engine.assets import (
    AssetAmount,
    AssetId,
    ConservativeValuationRate,
    ValuationBook,
)
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

from f3_helpers import TOKEN_A, TOKEN_B, authenticated_universe, pool_fixture

SOURCE_A = "11" * 32
SOURCE_B = "22" * 32
SOURCE_C = "33" * 32
TOKEN_DELTAS = "44" * 32
POST_STATE = "55" * 32


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
):
    plan = execution_plan() if plan is None else plan
    native = AssetId.native(plan.opportunity.universe.chain)
    at = plan.created_at_unix_ms + 1
    fee = Eip1559CostEnvelope(
        chain=plan.opportunity.universe.chain,
        native_asset=native,
        gas_units_upper_bound=gas_units_upper_bound,
        max_fee_per_gas=max_fee_per_gas,
        max_priority_fee_per_gas=1,
        l1_data_fee_upper_bound=l1_data_fee_upper_bound,
        direct_inclusion_payment_upper_bound=direct_inclusion_payment_upper_bound,
        observed_at_unix_ms=plan.created_at_unix_ms,
        valid_until_unix_ms=at + 10_000,
        source_sha256=SOURCE_C,
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
                valid_until_unix_ms=at + 10_000,
                source_sha256=SOURCE_C,
            ),
        )
    )
    return ExecutionCostEnvelope(
        plan=plan,
        fee_envelope=fee,
        reserve_components=reserve_components(plan, amount=reserve_amount),
        valuation_book=book,
        created_at_unix_ms=at,
    )


def simulations(plan: AtomicExecutionPlan, *, gas_units: int = 90, output_delta: int = 0):
    output = plan.opportunity.route_quote.amount_out + output_delta
    common = dict(
        success=True,
        opportunity_sha256=plan.opportunity.digest,
        execution_plan_sha256=plan.digest,
        gas_units=gas_units,
        output_amount=output,
        token_deltas_sha256=TOKEN_DELTAS,
        post_state_sha256=POST_STATE,
    )
    return (
        RouteSimulationResult(engine_id="deterministic-engine-a", **common),
        RouteSimulationResult(engine_id="independent-engine-b", **common),
    )


def net_evidence(
    envelope: ExecutionCostEnvelope | None = None,
    *,
    simulation_rows=None,
    minimum_absolute_profit: int = 1,
    minimum_return_bps: int = 0,
    chain_health: ChainHealth = ChainHealth.HEALTHY,
    risk_budget_available: bool = True,
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
    return ConservativeNetProfitEvidence(
        cost_envelope=envelope,
        simulations=rows,
        profit_policy=policy,
        chain_health=chain_health,
        risk_budget_available=risk_budget_available,
        created_at_unix_ms=envelope.created_at_unix_ms + 1,
    )
