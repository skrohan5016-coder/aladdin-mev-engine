from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from .assets import (
    AssetAmount,
    AssetId,
    AssetKind,
    ValuationBook,
    valuation_pair_sha256,
)
from .canonical import canonical_json_bytes, canonical_sha256
from .constant_product import MAX_UINT256
from .context_evidence import ChainHealthEvidence, RiskBudgetEvidence
from .domain import Chain, require_bounded_text, require_sha256
from .execution_plan import AtomicExecutionPlan
from .opportunity import MAX_UINT64
from .profit import CostBreakdown, ProfitAssessment, ProfitPolicy, assess_profit

FEE_ENVELOPE_SCHEMA = "aladdin-mev-eip1559-cost-envelope/v1"
RESERVE_COMPONENT_SCHEMA = "aladdin-mev-reserve-cost-component/v1"
ROUTE_SIMULATION_SCHEMA = "aladdin-mev-route-simulation-result/v1"
COST_ENVELOPE_SCHEMA = "aladdin-mev-execution-cost-envelope/v1"
NET_EVIDENCE_SCHEMA = "aladdin-mev-conservative-net-profit-evidence/v1"
COST_COMPLETENESS = "complete-recorded-upper-bound-no-inclusion-guarantee"
NET_AUTHORITY = "offline-recorded-cost-complete-shadow-net-evidence"
MAX_SIMULATIONS = 8


class ReserveCostCategory(StrEnum):
    SLIPPAGE_RESERVE = "slippage_reserve"
    STALE_STATE_RESERVE = "stale_state_reserve"
    FAILURE_RISK_RESERVE = "failure_risk_reserve"
    INFRASTRUCTURE_COST = "infrastructure_cost"
    INVENTORY_HEDGE_COST = "inventory_hedge_cost"


def _uint(name: str, value: object, *, positive: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT256:
        raise ValueError(f"{name} must be an unsigned 256-bit exact integer")
    if positive and value == 0:
        raise ValueError(f"{name} must be positive")
    return value


def _time(name: str, value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT64:
        raise ValueError(f"{name} must be an unsigned 64-bit exact integer")
    return value


def _checked_mul(left: int, right: int, name: str) -> int:
    _uint(f"{name} left", left)
    _uint(f"{name} right", right)
    value = left * right
    if value > MAX_UINT256:
        raise ValueError(f"{name} exceeds uint256")
    return value


def _checked_sum(values: tuple[int, ...], name: str) -> int:
    total = 0
    for value in values:
        _uint(f"{name} component", value)
        total += value
        if total > MAX_UINT256:
            raise ValueError(f"{name} exceeds uint256")
    return total


@dataclass(frozen=True, slots=True)
class Eip1559CostEnvelope:
    chain: Chain
    native_asset: AssetId
    gas_units_upper_bound: int
    max_fee_per_gas: int
    max_priority_fee_per_gas: int
    l1_data_fee_upper_bound: int
    operator_fee_upper_bound: int
    direct_inclusion_payment_upper_bound: int
    observed_at_unix_ms: int
    valid_until_unix_ms: int
    source_sha256: str
    schema: str = FEE_ENVELOPE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != FEE_ENVELOPE_SCHEMA:
            raise ValueError("unsupported EIP-1559 cost-envelope schema")
        if type(self.chain) is not Chain or self.chain not in {Chain.ETHEREUM, Chain.BASE}:
            raise ValueError("F4 EIP-1559 cost envelope supports Ethereum and Base only")
        if type(self.native_asset) is not AssetId:
            raise TypeError("native_asset must be an exact AssetId")
        if (
            self.native_asset.chain is not self.chain
            or self.native_asset.kind is not AssetKind.NATIVE
        ):
            raise ValueError("native_asset does not match the exact fee-envelope chain")
        _uint("gas_units_upper_bound", self.gas_units_upper_bound, positive=True)
        _uint("max_fee_per_gas", self.max_fee_per_gas, positive=True)
        _uint("max_priority_fee_per_gas", self.max_priority_fee_per_gas)
        _uint("l1_data_fee_upper_bound", self.l1_data_fee_upper_bound)
        _uint("operator_fee_upper_bound", self.operator_fee_upper_bound)
        _uint(
            "direct_inclusion_payment_upper_bound",
            self.direct_inclusion_payment_upper_bound,
        )
        if self.max_priority_fee_per_gas > self.max_fee_per_gas:
            raise ValueError("max priority fee cannot exceed max fee per gas")
        if self.chain is Chain.ETHEREUM and self.l1_data_fee_upper_bound != 0:
            raise ValueError("Ethereum envelope cannot double-count an L1 data fee")
        if self.chain is Chain.ETHEREUM and self.operator_fee_upper_bound != 0:
            raise ValueError("Ethereum envelope cannot record an OP Stack operator fee")
        _time("observed_at_unix_ms", self.observed_at_unix_ms)
        _time("valid_until_unix_ms", self.valid_until_unix_ms)
        if self.valid_until_unix_ms < self.observed_at_unix_ms:
            raise ValueError("fee-envelope validity cannot precede observation")
        require_sha256("source_sha256", self.source_sha256)
        _ = self.total_native_upper_bound
        canonical_json_bytes(self.to_json_value())

    def is_valid_at(self, at_unix_ms: int) -> bool:
        _time("at_unix_ms", at_unix_ms)
        return self.observed_at_unix_ms <= at_unix_ms <= self.valid_until_unix_ms

    @property
    def execution_gas_cost_upper_bound(self) -> int:
        return _checked_mul(
            self.gas_units_upper_bound,
            self.max_fee_per_gas,
            "execution gas cost",
        )

    @property
    def total_native_upper_bound(self) -> int:
        return _checked_sum(
            (
                self.execution_gas_cost_upper_bound,
                self.l1_data_fee_upper_bound,
                self.operator_fee_upper_bound,
                self.direct_inclusion_payment_upper_bound,
            ),
            "total native fee upper bound",
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "chain": self.chain.value,
            "native_asset": self.native_asset.to_json_value(),
            "gas_units_upper_bound": str(self.gas_units_upper_bound),
            "max_fee_per_gas": str(self.max_fee_per_gas),
            "max_priority_fee_per_gas": str(self.max_priority_fee_per_gas),
            "execution_gas_cost_upper_bound": str(
                self.execution_gas_cost_upper_bound
            ),
            "l1_data_fee_upper_bound": str(self.l1_data_fee_upper_bound),
            "operator_fee_upper_bound": str(self.operator_fee_upper_bound),
            "direct_inclusion_payment_upper_bound": str(
                self.direct_inclusion_payment_upper_bound
            ),
            "total_native_upper_bound": str(self.total_native_upper_bound),
            "priority_fee_semantics": "included-inside-max-fee-per-gas-not-added-again",
            "operator_fee_semantics": "separate-recorded-protocol-fee-upper-bound-not-in-eip1559-gas",
            "direct_payment_semantics": "separate-conditional-payment-not-priority-fee",
            "observed_at_unix_ms": str(self.observed_at_unix_ms),
            "valid_until_unix_ms": str(self.valid_until_unix_ms),
            "source_sha256": self.source_sha256,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class ReserveCostComponent:
    category: ReserveCostCategory
    amount: AssetAmount
    observed_at_unix_ms: int
    valid_until_unix_ms: int
    source_sha256: str
    schema: str = RESERVE_COMPONENT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != RESERVE_COMPONENT_SCHEMA:
            raise ValueError("unsupported reserve-cost-component schema")
        if type(self.category) is not ReserveCostCategory:
            raise TypeError("category must be an exact ReserveCostCategory")
        if type(self.amount) is not AssetAmount:
            raise TypeError("amount must be an exact AssetAmount")
        _time("observed_at_unix_ms", self.observed_at_unix_ms)
        _time("valid_until_unix_ms", self.valid_until_unix_ms)
        if self.valid_until_unix_ms < self.observed_at_unix_ms:
            raise ValueError("reserve-component validity cannot precede observation")
        require_sha256("source_sha256", self.source_sha256)
        canonical_json_bytes(self.to_json_value())

    def is_valid_at(self, at_unix_ms: int) -> bool:
        _time("at_unix_ms", at_unix_ms)
        return self.observed_at_unix_ms <= at_unix_ms <= self.valid_until_unix_ms

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "category": self.category.value,
            "amount": self.amount.to_json_value(),
            "bound_semantics": "conservative-upper-bound",
            "observed_at_unix_ms": str(self.observed_at_unix_ms),
            "valid_until_unix_ms": str(self.valid_until_unix_ms),
            "source_sha256": self.source_sha256,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class RouteSimulationResult:
    engine_id: str
    engine_implementation_sha256: str
    environment_sha256: str
    result_source_sha256: str
    state_reference_sha256: str
    success: bool
    opportunity_sha256: str
    execution_plan_sha256: str
    gas_units: int
    output_amount: int
    token_deltas_sha256: str
    post_state_sha256: str
    observed_at_unix_ms: int
    valid_until_unix_ms: int
    error_code: str | None = None
    schema: str = ROUTE_SIMULATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != ROUTE_SIMULATION_SCHEMA:
            raise ValueError("unsupported route-simulation-result schema")
        require_bounded_text("engine_id", self.engine_id, maximum=128)
        require_sha256(
            "engine_implementation_sha256",
            self.engine_implementation_sha256,
        )
        require_sha256("environment_sha256", self.environment_sha256)
        require_sha256("result_source_sha256", self.result_source_sha256)
        require_sha256("state_reference_sha256", self.state_reference_sha256)
        if type(self.success) is not bool:
            raise TypeError("success must be an exact bool")
        require_sha256("opportunity_sha256", self.opportunity_sha256)
        require_sha256("execution_plan_sha256", self.execution_plan_sha256)
        _uint("gas_units", self.gas_units)
        _uint("output_amount", self.output_amount)
        require_sha256("token_deltas_sha256", self.token_deltas_sha256)
        require_sha256("post_state_sha256", self.post_state_sha256)
        _time("observed_at_unix_ms", self.observed_at_unix_ms)
        _time("valid_until_unix_ms", self.valid_until_unix_ms)
        if self.valid_until_unix_ms < self.observed_at_unix_ms:
            raise ValueError("simulation validity cannot precede observation")
        if self.error_code is not None:
            require_bounded_text("error_code", self.error_code, maximum=128)
        if self.success:
            if self.error_code is not None:
                raise ValueError("successful route simulation cannot carry an error code")
            if self.gas_units == 0:
                raise ValueError("successful route simulation requires positive gas units")
        elif self.error_code is None:
            raise ValueError("failed route simulation requires an error code")
        canonical_json_bytes(self.to_json_value())

    def is_valid_at(self, at_unix_ms: int) -> bool:
        _time("at_unix_ms", at_unix_ms)
        return self.observed_at_unix_ms <= at_unix_ms <= self.valid_until_unix_ms

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "engine_id": self.engine_id,
            "engine_implementation_sha256": self.engine_implementation_sha256,
            "environment_sha256": self.environment_sha256,
            "result_source_sha256": self.result_source_sha256,
            "state_reference_sha256": self.state_reference_sha256,
            "success": self.success,
            "opportunity_sha256": self.opportunity_sha256,
            "execution_plan_sha256": self.execution_plan_sha256,
            "gas_units": str(self.gas_units),
            "output_amount": str(self.output_amount),
            "token_deltas_sha256": self.token_deltas_sha256,
            "post_state_sha256": self.post_state_sha256,
            "observed_at_unix_ms": str(self.observed_at_unix_ms),
            "valid_until_unix_ms": str(self.valid_until_unix_ms),
            "error_code": self.error_code,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


def dual_route_simulations_agree(
    simulations: tuple[RouteSimulationResult, ...],
) -> bool:
    if type(simulations) is not tuple or not 2 <= len(simulations) <= MAX_SIMULATIONS:
        return False
    if any(type(item) is not RouteSimulationResult for item in simulations):
        return False
    if len({item.engine_id for item in simulations}) != len(simulations):
        return False
    if len({item.engine_implementation_sha256 for item in simulations}) != len(simulations):
        return False
    if len({item.result_source_sha256 for item in simulations}) != len(simulations):
        return False
    if len({item.environment_sha256 for item in simulations}) != 1:
        return False
    reference = simulations[0]
    if not reference.success:
        return False
    return all(
        item.success
        and item.state_reference_sha256 == reference.state_reference_sha256
        and item.opportunity_sha256 == reference.opportunity_sha256
        and item.execution_plan_sha256 == reference.execution_plan_sha256
        and item.gas_units == reference.gas_units
        and item.output_amount == reference.output_amount
        and item.token_deltas_sha256 == reference.token_deltas_sha256
        and item.post_state_sha256 == reference.post_state_sha256
        and item.error_code == reference.error_code
        for item in simulations[1:]
    )


@dataclass(frozen=True, slots=True)
class ExecutionCostEnvelope:
    plan: AtomicExecutionPlan
    fee_envelope: Eip1559CostEnvelope
    reserve_components: tuple[ReserveCostComponent, ...]
    valuation_book: ValuationBook
    created_at_unix_ms: int
    schema: str = COST_ENVELOPE_SCHEMA
    _costs: CostBreakdown = field(init=False, repr=False)
    _converted_components: tuple[tuple[str, int], ...] = field(init=False, repr=False)
    _required_valuation_pairs: tuple[tuple[AssetId, AssetId], ...] = field(
        init=False,
        repr=False,
    )
    _valid_until_unix_ms: int = field(init=False, repr=False)
    _envelope_id: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != COST_ENVELOPE_SCHEMA:
            raise ValueError("unsupported execution-cost-envelope schema")
        if type(self.plan) is not AtomicExecutionPlan:
            raise TypeError("plan must be an exact AtomicExecutionPlan")
        if type(self.fee_envelope) is not Eip1559CostEnvelope:
            raise TypeError("fee_envelope must be an exact Eip1559CostEnvelope")
        if type(self.reserve_components) is not tuple:
            raise TypeError("reserve_components must be an exact tuple")
        if any(type(item) is not ReserveCostComponent for item in self.reserve_components):
            raise TypeError("reserve_components contain an ungoverned component")
        if type(self.valuation_book) is not ValuationBook:
            raise TypeError("valuation_book must be an exact ValuationBook")
        _time("created_at_unix_ms", self.created_at_unix_ms)
        if self.created_at_unix_ms < self.plan.created_at_unix_ms:
            raise ValueError("cost envelope cannot precede its execution plan")
        if self.fee_envelope.chain is not self.plan.opportunity.universe.chain:
            raise ValueError("fee envelope chain does not match the execution plan")
        if not self.plan.funding.is_valid_at(self.created_at_unix_ms):
            raise ValueError("funding plan is not valid at cost-envelope creation time")
        if not self.fee_envelope.is_valid_at(self.created_at_unix_ms):
            raise ValueError("fee envelope is not valid at cost-envelope creation time")

        ordered = tuple(sorted(self.reserve_components, key=lambda item: item.category.value))
        object.__setattr__(self, "reserve_components", ordered)
        categories = [item.category for item in ordered]
        required_categories = set(ReserveCostCategory)
        if len(categories) != len(required_categories) or set(categories) != required_categories:
            raise ValueError("reserve cost components must contain every category exactly once")
        if any(not item.is_valid_at(self.created_at_unix_ms) for item in ordered):
            raise ValueError("reserve component is not valid at cost-envelope creation time")

        base = self.plan.base_asset
        native = self.fee_envelope.native_asset
        cost_assets = (native, self.plan.funding.asset, *(item.amount.asset for item in ordered))
        if any(asset.chain is not base.chain for asset in cost_assets):
            raise ValueError("cost component asset does not match the execution-plan chain")
        required_pairs_set = {
            (asset, base)
            for asset in cost_assets
            if asset != base
        }
        required_pairs = tuple(
            sorted(
                required_pairs_set,
                key=lambda pair: valuation_pair_sha256(pair[0], pair[1]),
            )
        )
        rates = self.valuation_book.require_exact_pairs(
            required_pairs,
            at_unix_ms=self.created_at_unix_ms,
        )
        object.__setattr__(self, "_required_valuation_pairs", required_pairs)

        def convert(asset: AssetId, amount: int) -> int:
            return self.valuation_book.convert_upper_bound(
                AssetAmount(asset, amount),
                base,
                at_unix_ms=self.created_at_unix_ms,
            ).amount

        values: dict[str, int] = {
            "execution_gas_cost": convert(
                native,
                self.fee_envelope.execution_gas_cost_upper_bound,
            ),
            "l1_data_fee": convert(native, self.fee_envelope.l1_data_fee_upper_bound),
            "operator_fee": convert(native, self.fee_envelope.operator_fee_upper_bound),
            "flash_loan_fee": convert(self.plan.funding.asset, self.plan.funding.fee),
            "inclusion_bid": convert(
                native,
                self.fee_envelope.direct_inclusion_payment_upper_bound,
            ),
        }
        for component in ordered:
            values[component.category.value] = convert(
                component.amount.asset,
                component.amount.amount,
            )
        _checked_sum(tuple(values.values()), "converted execution cost")
        costs = CostBreakdown(
            gross_profit=self.plan.gross_profit,
            execution_gas_cost=values["execution_gas_cost"],
            l1_data_fee=values["l1_data_fee"],
            operator_fee=values["operator_fee"],
            flash_loan_fee=values["flash_loan_fee"],
            inclusion_bid=values["inclusion_bid"],
            slippage_reserve=values["slippage_reserve"],
            stale_state_reserve=values["stale_state_reserve"],
            failure_risk_reserve=values["failure_risk_reserve"],
            infrastructure_cost=values["infrastructure_cost"],
            inventory_hedge_cost=values["inventory_hedge_cost"],
        )
        converted = tuple(sorted(values.items()))
        valid_until = min(
            self.plan.funding.valid_until_unix_ms,
            self.fee_envelope.valid_until_unix_ms,
            *(item.valid_until_unix_ms for item in ordered),
            *(item.valid_until_unix_ms for item in rates),
        )
        identity = {
            "schema": self.schema,
            "execution_plan_sha256": self.plan.digest,
            "fee_envelope_sha256": self.fee_envelope.digest,
            "reserve_component_sha256": [item.digest for item in ordered],
            "valuation_book_sha256": self.valuation_book.digest,
            "required_valuation_pair_sha256": list(self.required_valuation_pair_sha256),
            "converted_costs": {key: str(value) for key, value in converted},
            "valid_until_unix_ms": str(valid_until),
            "cost_completeness": COST_COMPLETENESS,
        }
        object.__setattr__(self, "_costs", costs)
        object.__setattr__(self, "_converted_components", converted)
        object.__setattr__(self, "_valid_until_unix_ms", valid_until)
        object.__setattr__(
            self,
            "_envelope_id",
            "execution-cost-" + canonical_sha256(identity),
        )
        canonical_json_bytes(self.to_json_value())

    @property
    def costs(self) -> CostBreakdown:
        return self._costs

    @property
    def converted_components(self) -> tuple[tuple[str, int], ...]:
        return self._converted_components

    @property
    def required_valuation_pairs(self) -> tuple[tuple[AssetId, AssetId], ...]:
        return self._required_valuation_pairs

    @property
    def required_valuation_pair_sha256(self) -> tuple[str, ...]:
        return tuple(
            valuation_pair_sha256(asset_in, asset_out)
            for asset_in, asset_out in self.required_valuation_pairs
        )

    @property
    def valid_until_unix_ms(self) -> int:
        return self._valid_until_unix_ms

    @property
    def envelope_id(self) -> str:
        return self._envelope_id

    def is_valid_at(self, at_unix_ms: int) -> bool:
        _time("at_unix_ms", at_unix_ms)
        if not self.created_at_unix_ms <= at_unix_ms <= self.valid_until_unix_ms:
            return False
        if not self.plan.funding.is_valid_at(at_unix_ms):
            return False
        if not self.fee_envelope.is_valid_at(at_unix_ms):
            return False
        if any(not item.is_valid_at(at_unix_ms) for item in self.reserve_components):
            return False
        try:
            self.valuation_book.require_exact_pairs(
                self.required_valuation_pairs,
                at_unix_ms=at_unix_ms,
            )
        except (TypeError, ValueError):
            return False
        return True

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "envelope_id": self.envelope_id,
            "execution_plan_sha256": self.plan.digest,
            "base_asset": self.plan.base_asset.to_json_value(),
            "fee_envelope": self.fee_envelope.to_json_value(),
            "fee_envelope_sha256": self.fee_envelope.digest,
            "reserve_components": [item.to_json_value() for item in self.reserve_components],
            "reserve_component_sha256": [item.digest for item in self.reserve_components],
            "valuation_book": self.valuation_book.to_json_value(),
            "valuation_book_sha256": self.valuation_book.digest,
            "required_valuation_pair_sha256": list(
                self.required_valuation_pair_sha256
            ),
            "converted_costs": {
                key: str(value) for key, value in self.converted_components
            },
            "cost_breakdown": self.costs.to_json_value(),
            "cost_completeness": COST_COMPLETENESS,
            "execution_eligible": False,
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "valid_until_unix_ms": str(self.valid_until_unix_ms),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class ConservativeNetProfitEvidence:
    cost_envelope: ExecutionCostEnvelope
    simulations: tuple[RouteSimulationResult, ...]
    profit_policy: ProfitPolicy
    chain_health_evidence: ChainHealthEvidence
    risk_budget_evidence: RiskBudgetEvidence
    created_at_unix_ms: int
    schema: str = NET_EVIDENCE_SCHEMA
    _decision: ProfitAssessment = field(init=False, repr=False)
    _evidence_id: str = field(init=False, repr=False)
    _inputs_valid_until_unix_ms: int = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != NET_EVIDENCE_SCHEMA:
            raise ValueError("unsupported conservative-net-profit-evidence schema")
        if type(self.cost_envelope) is not ExecutionCostEnvelope:
            raise TypeError("cost_envelope must be an exact ExecutionCostEnvelope")
        if type(self.simulations) is not tuple or not 2 <= len(self.simulations) <= MAX_SIMULATIONS:
            raise ValueError("two to eight exact route simulations are required")
        if any(type(item) is not RouteSimulationResult for item in self.simulations):
            raise TypeError("simulations contain an ungoverned result")
        ordered = tuple(
            sorted(
                self.simulations,
                key=lambda item: (
                    item.engine_id,
                    item.engine_implementation_sha256,
                    item.digest,
                ),
            )
        )
        object.__setattr__(self, "simulations", ordered)
        if type(self.profit_policy) is not ProfitPolicy:
            raise TypeError("profit_policy must be an exact ProfitPolicy")
        for name in (
            "minimum_absolute_profit",
            "minimum_return_bps",
            "maximum_bid_fraction_bps",
            "maximum_state_age_ms",
        ):
            _uint(f"profit_policy.{name}", getattr(self.profit_policy, name))
        if type(self.chain_health_evidence) is not ChainHealthEvidence:
            raise TypeError("chain_health_evidence must be exact ChainHealthEvidence")
        if type(self.risk_budget_evidence) is not RiskBudgetEvidence:
            raise TypeError("risk_budget_evidence must be exact RiskBudgetEvidence")
        _time("created_at_unix_ms", self.created_at_unix_ms)
        if self.created_at_unix_ms < self.cost_envelope.created_at_unix_ms:
            raise ValueError("net-profit evidence cannot precede its cost envelope")
        if not self.cost_envelope.is_valid_at(self.created_at_unix_ms):
            raise ValueError("cost envelope inputs are not valid at net-evidence time")
        if not dual_route_simulations_agree(self.simulations):
            raise ValueError("route simulations do not provide independent exact agreement")

        plan = self.cost_envelope.plan
        state_reference_sha256 = canonical_sha256(
            plan.opportunity.universe.state_reference.to_json_value()
        )
        for simulation in self.simulations:
            if simulation.observed_at_unix_ms < plan.created_at_unix_ms:
                raise ValueError("route simulation cannot precede the execution plan")
            if not simulation.is_valid_at(self.created_at_unix_ms):
                raise ValueError("route simulation is not valid at net-evidence time")
            if simulation.state_reference_sha256 != state_reference_sha256:
                raise ValueError("route simulation does not bind the exact state reference")
        reference = self.simulations[0]
        if reference.opportunity_sha256 != plan.opportunity.digest:
            raise ValueError("route simulation does not bind the exact F3 opportunity")
        if reference.execution_plan_sha256 != plan.digest:
            raise ValueError("route simulation does not bind the exact execution plan")
        if reference.output_amount != plan.opportunity.route_quote.amount_out:
            raise ValueError("route simulation output disagrees with exact F3 output")
        if reference.gas_units > self.cost_envelope.fee_envelope.gas_units_upper_bound:
            raise ValueError("simulated gas exceeds the recorded gas upper bound")

        if self.chain_health_evidence.chain is not plan.opportunity.universe.chain:
            raise ValueError("chain-health evidence does not match the execution-plan chain")
        if not self.chain_health_evidence.is_valid_at(self.created_at_unix_ms):
            raise ValueError("chain-health evidence is not valid at net-evidence time")
        if not self.risk_budget_evidence.is_valid_at(self.created_at_unix_ms):
            raise ValueError("risk-budget evidence is not valid at net-evidence time")
        if self.risk_budget_evidence.observed_at_unix_ms < self.cost_envelope.created_at_unix_ms:
            raise ValueError("risk-budget evidence cannot precede the execution cost envelope")
        if self.risk_budget_evidence.execution_plan_sha256 != plan.digest:
            raise ValueError("risk-budget evidence does not bind the exact execution plan")
        if (
            self.risk_budget_evidence.requested_execution_cost
            != self.cost_envelope.costs.total_cost
        ):
            raise ValueError("risk-budget evidence does not bind the exact execution cost")
        if (
            self.risk_budget_evidence.requested_notional
            != plan.opportunity.capital_at_risk
        ):
            raise ValueError("risk-budget evidence does not bind the exact notional")

        state_age_ms = (
            self.created_at_unix_ms
            - plan.opportunity.universe.state_reference.observed_at_unix_ms
        )
        decision = assess_profit(
            self.cost_envelope.costs,
            self.profit_policy,
            capital_at_risk=plan.opportunity.capital_at_risk,
            state_age_ms=state_age_ms,
            simulations_agree=True,
            chain_health=self.chain_health_evidence.health,
            risk_budget_available=self.risk_budget_evidence.allowed,
        )
        inputs_valid_until = min(
            self.cost_envelope.valid_until_unix_ms,
            self.chain_health_evidence.valid_until_unix_ms,
            self.risk_budget_evidence.valid_until_unix_ms,
            *(item.valid_until_unix_ms for item in self.simulations),
        )
        identity = {
            "schema": self.schema,
            "cost_envelope_sha256": self.cost_envelope.digest,
            "simulation_sha256": [item.digest for item in self.simulations],
            "profit_policy": self.profit_policy.to_json_value(),
            "chain_health_evidence_sha256": self.chain_health_evidence.digest,
            "risk_budget_evidence_sha256": self.risk_budget_evidence.digest,
            "decision": decision.to_json_value(),
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "inputs_valid_until_unix_ms": str(inputs_valid_until),
            "authority": NET_AUTHORITY,
        }
        object.__setattr__(self, "_decision", decision)
        object.__setattr__(self, "_inputs_valid_until_unix_ms", inputs_valid_until)
        object.__setattr__(self, "_evidence_id", "net-evidence-" + canonical_sha256(identity))
        canonical_json_bytes(self.to_json_value())

    @property
    def decision(self) -> ProfitAssessment:
        return self._decision

    @property
    def evidence_id(self) -> str:
        return self._evidence_id

    @property
    def plan(self) -> AtomicExecutionPlan:
        return self.cost_envelope.plan

    @property
    def state_age_ms(self) -> int:
        return (
            self.created_at_unix_ms
            - self.plan.opportunity.universe.state_reference.observed_at_unix_ms
        )

    @property
    def inputs_valid_until_unix_ms(self) -> int:
        return self._inputs_valid_until_unix_ms

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "evidence_id": self.evidence_id,
            "opportunity_id": self.plan.opportunity.opportunity_id,
            "opportunity_sha256": self.plan.opportunity.digest,
            "execution_plan_sha256": self.plan.digest,
            "cost_envelope": self.cost_envelope.to_json_value(),
            "cost_envelope_sha256": self.cost_envelope.digest,
            "simulations": [item.to_json_value() for item in self.simulations],
            "simulation_sha256": [item.digest for item in self.simulations],
            "profit_policy": self.profit_policy.to_json_value(),
            "chain_health_evidence": self.chain_health_evidence.to_json_value(),
            "chain_health_evidence_sha256": self.chain_health_evidence.digest,
            "risk_budget_evidence": self.risk_budget_evidence.to_json_value(),
            "risk_budget_evidence_sha256": self.risk_budget_evidence.digest,
            "chain_health": self.chain_health_evidence.health.value,
            "risk_budget_available": self.risk_budget_evidence.allowed,
            "state_age_ms": str(self.state_age_ms),
            "decision": self.decision.to_json_value(),
            "decision_authority": "shadow-economics-only",
            "cost_completeness": COST_COMPLETENESS,
            "authority": NET_AUTHORITY,
            "inclusion_guarantee": False,
            "signing_authority": "none",
            "execution_eligible": False,
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "inputs_valid_until_unix_ms": str(self.inputs_valid_until_unix_ms),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())
