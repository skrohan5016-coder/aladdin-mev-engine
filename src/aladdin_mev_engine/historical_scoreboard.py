from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from .assets import AssetAmount, AssetId, ValuationBook
from .canonical import canonical_json_bytes, canonical_sha256
from .domain import Chain, Strategy, require_bounded_text, require_sha256
from .execution_outcome import (
    AuthenticatedTransactionReceiptInclusionEvidence,
    ExecutorSettlementEventRegistry,
    ExecutorSettlementEventSpec,
    RealizedExecutionOutcomeEvidence,
    RecordedRollupFeeEvidence,
)
from .execution_plan import FundingKind
from .evm_hex import to_hex_data
from .relay_evidence import ExternallySignedExecutionPackageEvidence
from .source_contracts import Finality

BASIS_POINTS = 10_000
MAX_UINT64 = (1 << 64) - 1
MAX_UINT256 = (1 << 256) - 1
MAX_AGGREGATE = (1 << 512) - 1
MAX_CORPUS_RECORDS = 128
MAX_CALIBRATION_BUCKETS = 16

COHORT_SCHEMA = "aladdin-mev-historical-cohort-key/v1"
VALUATION_POLICY_SCHEMA = "aladdin-mev-historical-valuation-policy/v1"
RECORD_SCHEMA = "aladdin-mev-historical-execution-record/v1"
ATTEMPT_REFERENCE_SCHEMA = "aladdin-mev-historical-attempt-reference/v1"
SOURCE_MANIFEST_SCHEMA = "aladdin-mev-historical-corpus-source-manifest/v1"
CORPUS_SCHEMA = "aladdin-mev-historical-outcome-corpus/v1"
SCOREBOARD_SCHEMA = "aladdin-mev-historical-economic-scoreboard/v1"
CALIBRATION_POLICY_SCHEMA = "aladdin-mev-calibration-policy/v1"
CALIBRATION_BUCKET_SCHEMA = "aladdin-mev-calibration-bucket/v1"
CALIBRATION_REPORT_SCHEMA = "aladdin-mev-historical-calibration-report/v1"
EXPECTED_VALUE_SCHEMA = "aladdin-mev-historical-expected-value/v1"
PROMOTION_POLICY_SCHEMA = "aladdin-mev-research-promotion-policy/v1"
PROMOTION_DECISION_SCHEMA = "aladdin-mev-research-promotion-decision/v1"


class HistoricalDisposition(StrEnum):
    SETTLED = "settled"
    REVERTED = "reverted"
    SETTLEMENT_MISSING = "settlement-missing"
    SETTLEMENT_EVIDENCE_INCOMPLETE = "settlement-evidence-incomplete"


class ResearchPromotionReason(StrEnum):
    EXPECTED_VALUE_UNAVAILABLE = "expected-value-unavailable"
    INSUFFICIENT_ATTEMPTS = "insufficient-attempts"
    INSUFFICIENT_SCOREABLE_RECORDS = "insufficient-scoreable-records"
    INSUFFICIENT_SCOREABLE_RATE = "insufficient-scoreable-rate"
    INSUFFICIENT_EXECUTION_SUCCESS_RATE = "insufficient-execution-success-rate"
    INSUFFICIENT_FLOOR_PRESERVATION_RATE = "insufficient-floor-preservation-rate"
    INSUFFICIENT_COST_BOUND_RATE = "insufficient-cost-bound-rate"
    INSUFFICIENT_POSITIVE_SURPLUS_RATE = "insufficient-positive-surplus-rate"
    INSUFFICIENT_UNIQUE_SCOREABLE_BLOCKS = "insufficient-unique-scoreable-blocks"
    EXCESSIVE_NATIVE_COST_OVERRUN_RATE = "excessive-native-cost-overrun-rate"
    EXCESSIVE_MEAN_ABSOLUTE_ERROR = "excessive-mean-absolute-error"
    GUARDED_EXPECTED_VALUE_BELOW_FLOOR = "guarded-expected-value-below-floor"
    CALIBRATION_BUCKET_UNDERSAMPLED = "calibration-bucket-undersampled"


def _uint64(name: str, value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT64:
        raise ValueError(f"{name} must be an unsigned 64-bit exact integer")
    return value


def _uint256(name: str, value: object, *, positive: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT256:
        raise ValueError(f"{name} must be an unsigned 256-bit exact integer")
    if positive and value == 0:
        raise ValueError(f"{name} must be positive")
    return value


def _address(name: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 20 or value == bytes(20):
        raise ValueError(f"{name} must be a non-zero exact 20-byte address")
    return value


def _signed_aggregate(name: str, value: object) -> int:
    if type(value) is not int or not -MAX_AGGREGATE <= value <= MAX_AGGREGATE:
        raise ValueError(f"{name} exceeds the governed signed aggregate domain")
    return value


def _checked_add(left: int, right: int, name: str) -> int:
    _signed_aggregate(f"{name} left", left)
    _signed_aggregate(f"{name} right", right)
    return _signed_aggregate(name, left + right)


def _checked_sum(values: tuple[int, ...], name: str) -> int:
    total = 0
    for value in values:
        total = _checked_add(total, value, name)
    return total


def _ceil_div(numerator: int, denominator: int) -> int:
    if type(numerator) is not int or type(denominator) is not int or denominator <= 0:
        raise ValueError("ceiling division requires exact integer numerator and positive denominator")
    return -((-numerator) // denominator)


def _ratio_bps(numerator: int, denominator: int) -> int:
    if type(numerator) is not int or type(denominator) is not int:
        raise TypeError("ratio inputs must be exact integers")
    if numerator < 0 or denominator < 0 or numerator > denominator:
        raise ValueError("ratio inputs must satisfy 0 <= numerator <= denominator")
    if denominator == 0:
        return 0
    return numerator * BASIS_POINTS // denominator


def _signed_ratio_bps_floor(numerator: int, denominator: int) -> int:
    if type(numerator) is not int or type(denominator) is not int or denominator <= 0:
        raise ValueError("signed ratio requires an exact numerator and positive denominator")
    _signed_aggregate("signed ratio numerator", numerator)
    if abs(numerator) > MAX_AGGREGATE // BASIS_POINTS:
        raise ValueError("signed ratio multiplication exceeds the governed aggregate domain")
    return numerator * BASIS_POINTS // denominator


def _unsigned_ratio_bps_ceiling_saturated(numerator: int, denominator: int) -> int:
    if type(numerator) is not int or type(denominator) is not int:
        raise TypeError("unsigned ratio inputs must be exact integers")
    if numerator < 0 or denominator <= 0:
        raise ValueError("unsigned ratio requires a non-negative numerator and positive denominator")
    value = _ceil_div(numerator * BASIS_POINTS, denominator)
    return min(value, MAX_UINT256)


@dataclass(frozen=True, slots=True)
class HistoricalValuationPolicy:
    policy_id: str
    native_asset: AssetId
    base_asset: AssetId
    rate_source_sha256: str | None
    schema: str = VALUATION_POLICY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != VALUATION_POLICY_SCHEMA:
            raise ValueError("unsupported historical-valuation-policy schema")
        require_bounded_text("policy_id", self.policy_id, maximum=128)
        if type(self.native_asset) is not AssetId or type(self.base_asset) is not AssetId:
            raise TypeError("historical valuation assets must be exact AssetId values")
        if self.native_asset.chain is not self.base_asset.chain:
            raise ValueError("historical valuation policy cannot cross chains")
        if self.native_asset == self.base_asset:
            if self.rate_source_sha256 is not None:
                raise ValueError("identity valuation policy cannot carry a rate source")
        else:
            if self.rate_source_sha256 is None:
                raise ValueError("directional valuation policy requires a rate source")
            require_sha256("rate_source_sha256", self.rate_source_sha256)
        canonical_json_bytes(self.to_json_value())

    @property
    def mode(self) -> str:
        return "identity" if self.native_asset == self.base_asset else "directional-ceiling"

    def validate_assets(self, native_asset: AssetId, base_asset: AssetId) -> None:
        if type(native_asset) is not AssetId or type(base_asset) is not AssetId:
            raise TypeError("historical valuation policy comparison requires exact AssetId values")
        if native_asset != self.native_asset or base_asset != self.base_asset:
            raise ValueError("historical valuation policy asset identity disagrees with the package")

    def validate_book(self, book: ValuationBook, *, at_unix_ms: int) -> None:
        if type(book) is not ValuationBook:
            raise TypeError("historical valuation book must be an exact ValuationBook")
        _uint64("at_unix_ms", at_unix_ms)
        if self.mode == "identity":
            book.require_exact_pairs((), at_unix_ms=at_unix_ms)
            return
        rates = book.require_exact_pairs(
            ((self.native_asset, self.base_asset),),
            at_unix_ms=at_unix_ms,
        )
        if len(rates) != 1 or rates[0].source_sha256 != self.rate_source_sha256:
            raise ValueError("historical valuation rate source disagrees with its policy")

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "policy_id": self.policy_id,
            "native_asset": self.native_asset.to_json_value(),
            "base_asset": self.base_asset.to_json_value(),
            "rate_source_sha256": self.rate_source_sha256,
            "mode": self.mode,
            "rounding": "identity-or-ceiling",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class HistoricalCohortKey:
    chain: Chain
    strategy: Strategy
    base_asset_sha256: str
    sender_address: bytes
    signature_source_sha256: str
    profit_policy_sha256: str
    relay_endpoint_sha256: str
    relay_response_source_set_sha256: str
    funding_kind: FundingKind
    funding_provider_id: str
    funding_source_sha256: str
    executor_interface_sha256: str
    execution_constraint_policy_sha256: str
    pool_model_registry_sha256: str
    simulation_environment_sha256: str
    route_simulation_engine_set_sha256: str
    transaction_simulation_engine_set_sha256: str
    executor_deployment_sha256: str
    settlement_event_registry_sha256: str
    settlement_event_spec_sha256: str
    rollup_fee_source_identity_sha256: str
    historical_valuation_policy_sha256: str
    inclusion_finality: Finality
    schema: str = COHORT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != COHORT_SCHEMA:
            raise ValueError("unsupported historical-cohort schema")
        if type(self.chain) is not Chain or self.chain not in {Chain.ETHEREUM, Chain.BASE}:
            raise ValueError("F8 historical cohorts support Ethereum and Base only")
        if type(self.strategy) is not Strategy:
            raise TypeError("strategy must be an exact Strategy")
        if self.strategy is not Strategy.ATOMIC_DEX_ARBITRAGE:
            raise ValueError("F8 historical cohorts support atomic DEX arbitrage only")
        _address("sender_address", self.sender_address)
        for name in (
            "base_asset_sha256",
            "signature_source_sha256",
            "profit_policy_sha256",
            "relay_endpoint_sha256",
            "relay_response_source_set_sha256",
            "funding_source_sha256",
            "executor_interface_sha256",
            "execution_constraint_policy_sha256",
            "pool_model_registry_sha256",
            "simulation_environment_sha256",
            "route_simulation_engine_set_sha256",
            "transaction_simulation_engine_set_sha256",
            "executor_deployment_sha256",
            "settlement_event_registry_sha256",
            "settlement_event_spec_sha256",
            "rollup_fee_source_identity_sha256",
            "historical_valuation_policy_sha256",
        ):
            require_sha256(name, getattr(self, name))
        if type(self.funding_kind) is not FundingKind:
            raise TypeError("funding_kind must be an exact FundingKind")
        if type(self.inclusion_finality) is not Finality:
            raise TypeError("inclusion_finality must be an exact Finality")
        if self.inclusion_finality not in {Finality.CONFIRMED, Finality.FINALIZED}:
            raise ValueError("F8 historical cohorts require confirmed or finalized inclusion")
        require_bounded_text("funding_provider_id", self.funding_provider_id, maximum=128)
        canonical_json_bytes(self.to_json_value())

    @classmethod
    def from_evidence(
        cls,
        package: ExternallySignedExecutionPackageEvidence,
        inclusion: AuthenticatedTransactionReceiptInclusionEvidence,
        settlement_registry: ExecutorSettlementEventRegistry,
        settlement_spec: ExecutorSettlementEventSpec,
        rollup_fee: RecordedRollupFeeEvidence,
        historical_valuation_policy: HistoricalValuationPolicy,
    ) -> HistoricalCohortKey:
        if type(package) is not ExternallySignedExecutionPackageEvidence:
            raise TypeError("package must be exact ExternallySignedExecutionPackageEvidence")
        if type(inclusion) is not AuthenticatedTransactionReceiptInclusionEvidence:
            raise TypeError("inclusion must be exact AuthenticatedTransactionReceiptInclusionEvidence")
        if type(settlement_registry) is not ExecutorSettlementEventRegistry:
            raise TypeError("settlement_registry must be an exact ExecutorSettlementEventRegistry")
        if type(settlement_spec) is not ExecutorSettlementEventSpec:
            raise TypeError("settlement_spec must be an exact ExecutorSettlementEventSpec")
        if type(rollup_fee) is not RecordedRollupFeeEvidence:
            raise TypeError("rollup_fee must be exact RecordedRollupFeeEvidence")
        if type(historical_valuation_policy) is not HistoricalValuationPolicy:
            raise TypeError("historical_valuation_policy must be an exact HistoricalValuationPolicy")
        if inclusion.package.digest != package.digest:
            raise ValueError("cohort inclusion does not bind the exact package")
        unsigned = package.unsigned_package
        net = unsigned.net_profit_evidence
        plan = net.plan
        runtime_code_hash = unsigned.call.deployment.spec.runtime_code_hash
        resolved = settlement_registry.resolve(runtime_code_hash, inclusion.block.block_number)
        if resolved.digest != settlement_spec.digest:
            raise ValueError("cohort settlement registry does not bind the exact settlement spec")
        if settlement_spec.runtime_code_hash != runtime_code_hash:
            raise ValueError("cohort settlement spec does not bind the executor runtime code")
        return cls(
            chain=unsigned.bundle.chain,
            strategy=Strategy.ATOMIC_DEX_ARBITRAGE,
            base_asset_sha256=plan.base_asset.digest,
            sender_address=package.signed_transaction.recovered_sender,
            signature_source_sha256=package.signed_transaction.signature.source_sha256,
            profit_policy_sha256=canonical_sha256(net.profit_policy.to_json_value()),
            relay_endpoint_sha256=package.relay_request.endpoint.digest,
            relay_response_source_set_sha256=canonical_sha256(
                [
                    {
                        "response_source_id": item.response_source_id,
                        "response_source_sha256": item.response_source_sha256,
                    }
                    for item in package.relay_responses
                ]
            ),
            funding_kind=plan.funding.kind,
            funding_provider_id=plan.funding.provider_id,
            funding_source_sha256=plan.funding.source_sha256,
            executor_interface_sha256=unsigned.call.deployment.spec.interface.digest,
            execution_constraint_policy_sha256=unsigned.call.constraints.digest,
            pool_model_registry_sha256=plan.opportunity.universe.model_registry.digest,
            simulation_environment_sha256=unsigned.simulations[0].environment_sha256,
            route_simulation_engine_set_sha256=canonical_sha256(
                [
                    {
                        "engine_id": item.engine_id,
                        "engine_implementation_sha256": item.engine_implementation_sha256,
                        "result_source_sha256": item.result_source_sha256,
                    }
                    for item in net.simulations
                ]
            ),
            transaction_simulation_engine_set_sha256=canonical_sha256(
                [
                    {
                        "engine_id": item.engine_id,
                        "engine_implementation_sha256": item.engine_implementation_sha256,
                        "result_source_sha256": item.result_source_sha256,
                    }
                    for item in unsigned.simulations
                ]
            ),
            executor_deployment_sha256=unsigned.call.deployment.spec.digest,
            settlement_event_registry_sha256=settlement_registry.digest,
            settlement_event_spec_sha256=settlement_spec.digest,
            rollup_fee_source_identity_sha256=canonical_sha256(
                {
                    "source_id": rollup_fee.source_id,
                    "source_sha256": rollup_fee.source_sha256,
                }
            ),
            historical_valuation_policy_sha256=historical_valuation_policy.digest,
            inclusion_finality=inclusion.block.block.finality,
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "chain": self.chain.value,
            "strategy": self.strategy.value,
            "base_asset_sha256": self.base_asset_sha256,
            "sender_address": to_hex_data(self.sender_address),
            "signature_source_sha256": self.signature_source_sha256,
            "profit_policy_sha256": self.profit_policy_sha256,
            "relay_endpoint_sha256": self.relay_endpoint_sha256,
            "relay_response_source_set_sha256": self.relay_response_source_set_sha256,
            "funding_kind": self.funding_kind.value,
            "funding_provider_id": self.funding_provider_id,
            "funding_source_sha256": self.funding_source_sha256,
            "executor_interface_sha256": self.executor_interface_sha256,
            "execution_constraint_policy_sha256": self.execution_constraint_policy_sha256,
            "pool_model_registry_sha256": self.pool_model_registry_sha256,
            "simulation_environment_sha256": self.simulation_environment_sha256,
            "route_simulation_engine_set_sha256": self.route_simulation_engine_set_sha256,
            "transaction_simulation_engine_set_sha256": self.transaction_simulation_engine_set_sha256,
            "executor_deployment_sha256": self.executor_deployment_sha256,
            "settlement_event_registry_sha256": self.settlement_event_registry_sha256,
            "settlement_event_spec_sha256": self.settlement_event_spec_sha256,
            "rollup_fee_source_identity_sha256": self.rollup_fee_source_identity_sha256,
            "historical_valuation_policy_sha256": self.historical_valuation_policy_sha256,
            "inclusion_finality": self.inclusion_finality.value,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class HistoricalExecutionRecord:
    package: ExternallySignedExecutionPackageEvidence
    inclusion: AuthenticatedTransactionReceiptInclusionEvidence
    settlement_registry: ExecutorSettlementEventRegistry
    settlement_spec: ExecutorSettlementEventSpec
    rollup_fee: RecordedRollupFeeEvidence
    outcome: RealizedExecutionOutcomeEvidence | None
    historical_valuation_policy: HistoricalValuationPolicy
    historical_valuation_book: ValuationBook
    recorded_at_unix_ms: int
    schema: str = RECORD_SCHEMA
    _cohort: HistoricalCohortKey = field(init=False, repr=False)
    _disposition: HistoricalDisposition = field(init=False, repr=False)
    _predicted_conservative_net_profit: int = field(init=False, repr=False)
    _predicted_external_cost_base_upper_bound: int = field(init=False, repr=False)
    _actual_external_cost_base_upper_bound: int | None = field(init=False, repr=False)
    _historical_conservative_surplus: int | None = field(init=False, repr=False)
    _prediction_error: int | None = field(init=False, repr=False)
    _settlement_event_observed: bool = field(init=False, repr=False)
    _cost_upper_bounds_respected: bool = field(init=False, repr=False)
    _conservative_floor_preserved: bool = field(init=False, repr=False)
    _record_id: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != RECORD_SCHEMA:
            raise ValueError("unsupported historical-execution-record schema")
        if type(self.package) is not ExternallySignedExecutionPackageEvidence:
            raise TypeError("package must be exact ExternallySignedExecutionPackageEvidence")
        if type(self.inclusion) is not AuthenticatedTransactionReceiptInclusionEvidence:
            raise TypeError("inclusion must be exact AuthenticatedTransactionReceiptInclusionEvidence")
        if type(self.settlement_registry) is not ExecutorSettlementEventRegistry:
            raise TypeError("settlement_registry must be exact ExecutorSettlementEventRegistry")
        if type(self.settlement_spec) is not ExecutorSettlementEventSpec:
            raise TypeError("settlement_spec must be exact ExecutorSettlementEventSpec")
        if type(self.rollup_fee) is not RecordedRollupFeeEvidence:
            raise TypeError("rollup_fee must be exact RecordedRollupFeeEvidence")
        if self.outcome is not None and type(self.outcome) is not RealizedExecutionOutcomeEvidence:
            raise TypeError("outcome must be exact RealizedExecutionOutcomeEvidence or None")
        if type(self.historical_valuation_policy) is not HistoricalValuationPolicy:
            raise TypeError("historical_valuation_policy must be an exact HistoricalValuationPolicy")
        if type(self.historical_valuation_book) is not ValuationBook:
            raise TypeError("historical_valuation_book must be an exact ValuationBook")
        _uint64("recorded_at_unix_ms", self.recorded_at_unix_ms)
        if self.inclusion.package.digest != self.package.digest:
            raise ValueError("inclusion does not bind the exact F6 package")
        if self.rollup_fee.chain is not self.inclusion.block.chain:
            raise ValueError("rollup fee chain disagrees with inclusion")
        if self.rollup_fee.transaction_hash != self.package.signed_transaction.transaction_hash:
            raise ValueError("rollup fee does not bind the exact transaction")
        if self.rollup_fee.observed_at_unix_ms < self.inclusion.block.block.observed_at_unix_ms:
            raise ValueError("rollup fee evidence predates the authenticated block")

        unsigned = self.package.unsigned_package
        deployment = unsigned.call.deployment
        runtime_code_hash = deployment.spec.runtime_code_hash
        resolved_spec = self.settlement_registry.resolve(
            runtime_code_hash,
            self.inclusion.block.block_number,
        )
        if resolved_spec.digest != self.settlement_spec.digest:
            raise ValueError("settlement registry does not bind the exact settlement spec")
        if self.settlement_spec.runtime_code_hash != runtime_code_hash:
            raise ValueError("settlement spec does not bind the executor runtime code")
        candidates = tuple(
            item
            for item in self.inclusion.receipt.logs
            if item.address == deployment.address
            and item.topics
            and item.topics[0] == self.settlement_spec.topic0
        )
        if len(candidates) > 1:
            raise ValueError("historical record contains multiple governed settlement events")
        settlement_event = (
            self.settlement_spec.decode(candidates[0]) if candidates else None
        )
        settlement_event_observed = settlement_event is not None
        if settlement_event is not None:
            plan = unsigned.net_profit_evidence.plan
            transaction = self.package.signed_transaction.unsigned_transaction
            if settlement_event.plan_sha256 != plan.digest:
                raise ValueError("historical settlement event does not bind the exact plan")
            if settlement_event.beneficiary != transaction.sender:
                raise ValueError("historical settlement beneficiary is not the authenticated sender")
            if plan.base_asset.address is None or settlement_event.base_token != plan.base_asset.address:
                raise ValueError("historical settlement base token is not the exact plan asset")
            if settlement_event.principal_repaid != plan.funding.principal:
                raise ValueError("historical settlement principal disagrees with funding")
            if settlement_event.flash_loan_fee_paid != plan.funding.fee:
                raise ValueError("historical settlement fee disagrees with funding")
            if settlement_event.gross_output < unsigned.call.minimum_final_output:
                raise ValueError("historical settlement output violates the governed minimum")
            if settlement_event.direct_inclusion_payment > transaction.value:
                raise ValueError("historical settlement direct payment exceeds transaction value")
        latest = max(self.inclusion.created_at_unix_ms, self.rollup_fee.observed_at_unix_ms)
        if self.outcome is not None:
            if self.outcome.package.digest != self.package.digest:
                raise ValueError("outcome does not bind the exact package")
            if self.outcome.inclusion.digest != self.inclusion.digest:
                raise ValueError("outcome does not bind the exact inclusion")
            if self.outcome.rollup_fee.digest != self.rollup_fee.digest:
                raise ValueError("outcome does not bind the exact rollup fee evidence")
            if self.outcome.settlement_registry.digest != self.settlement_registry.digest:
                raise ValueError("outcome does not bind the exact settlement registry")
            if self.outcome.settlement_spec.digest != self.settlement_spec.digest:
                raise ValueError("outcome does not bind the exact settlement spec")
            if settlement_event is None:
                raise ValueError("outcome requires one authenticated governed settlement event")
            if self.outcome.settlement_event.digest != settlement_event.digest:
                raise ValueError("outcome settlement event disagrees with the authenticated receipt")
            latest = max(latest, self.outcome.created_at_unix_ms)
        if self.recorded_at_unix_ms < latest:
            raise ValueError("historical record predates its latest bound evidence")

        if self.inclusion.receipt.success:
            if self.outcome is not None:
                disposition = HistoricalDisposition.SETTLED
            elif settlement_event_observed:
                disposition = HistoricalDisposition.SETTLEMENT_EVIDENCE_INCOMPLETE
            else:
                disposition = HistoricalDisposition.SETTLEMENT_MISSING
        else:
            if self.outcome is not None:
                raise ValueError("reverted inclusion cannot carry successful settlement outcome")
            if settlement_event_observed:
                raise ValueError("reverted inclusion cannot retain a governed settlement event")
            disposition = HistoricalDisposition.REVERTED

        cohort = HistoricalCohortKey.from_evidence(
            self.package,
            self.inclusion,
            self.settlement_registry,
            self.settlement_spec,
            self.rollup_fee,
            self.historical_valuation_policy,
        )
        net = unsigned.net_profit_evidence
        costs = net.cost_envelope.costs
        predicted_net = net.decision.conservative_net_profit
        predicted_external = _checked_sum(
            (
                costs.execution_gas_cost,
                costs.l1_data_fee,
                costs.operator_fee,
                costs.inclusion_bid,
            ),
            "predicted external cost upper bound",
        )
        actual_external: int | None = None
        historical_surplus: int | None = None
        prediction_error: int | None = None
        cost_bounds_respected = False
        floor_preserved = False
        base = net.plan.base_asset
        native = net.cost_envelope.fee_envelope.native_asset
        self.historical_valuation_policy.validate_assets(native, base)
        block_time_ms = self.inclusion.block.block.block_timestamp_unix_s * 1000
        if block_time_ms > MAX_UINT64:
            raise ValueError("included block timestamp exceeds the governed millisecond domain")

        if self.outcome is None:
            if self.historical_valuation_book.rates:
                raise ValueError("unscoreable historical record cannot carry unused valuation authority")
        else:
            self.historical_valuation_policy.validate_book(
                self.historical_valuation_book,
                at_unix_ms=block_time_ms,
            )
            actual_external = self.historical_valuation_book.convert_upper_bound(
                AssetAmount(native, self.outcome.actual_native_cost),
                base,
                at_unix_ms=block_time_ms,
            ).amount
            reserve_cost = _checked_sum(
                (
                    costs.slippage_reserve,
                    costs.stale_state_reserve,
                    costs.failure_risk_reserve,
                    costs.infrastructure_cost,
                    costs.inventory_hedge_cost,
                ),
                "retained conservative reserve cost",
            )
            historical_surplus = _checked_add(
                self.outcome.settlement_event.base_token_residual_before_external_costs,
                -actual_external,
                "historical conservative surplus",
            )
            historical_surplus = _checked_add(
                historical_surplus,
                -reserve_cost,
                "historical conservative surplus",
            )
            prediction_error = _checked_add(
                historical_surplus,
                -predicted_net,
                "historical prediction error",
            )
            cost_bounds_respected = (
                self.outcome.cost_upper_bounds_respected
                and actual_external <= predicted_external
            )
            floor_preserved = (
                self.outcome.conservative_shadow_floor_preserved
                and cost_bounds_respected
                and historical_surplus >= predicted_net
            )

        identity = {
            "schema": self.schema,
            "package_sha256": self.package.digest,
            "inclusion_sha256": self.inclusion.digest,
            "settlement_event_registry_sha256": self.settlement_registry.digest,
            "settlement_event_spec_sha256": self.settlement_spec.digest,
            "rollup_fee_sha256": self.rollup_fee.digest,
            "outcome_sha256": self.outcome.digest if self.outcome is not None else None,
            "historical_valuation_policy_sha256": self.historical_valuation_policy.digest,
            "historical_valuation_book_sha256": self.historical_valuation_book.digest,
            "cohort_sha256": cohort.digest,
            "disposition": disposition.value,
            "settlement_event_observed": settlement_event_observed,
            "recorded_at_unix_ms": str(self.recorded_at_unix_ms),
        }
        object.__setattr__(self, "_cohort", cohort)
        object.__setattr__(self, "_disposition", disposition)
        object.__setattr__(self, "_predicted_conservative_net_profit", predicted_net)
        object.__setattr__(self, "_predicted_external_cost_base_upper_bound", predicted_external)
        object.__setattr__(self, "_actual_external_cost_base_upper_bound", actual_external)
        object.__setattr__(self, "_historical_conservative_surplus", historical_surplus)
        object.__setattr__(self, "_prediction_error", prediction_error)
        object.__setattr__(self, "_settlement_event_observed", settlement_event_observed)
        object.__setattr__(self, "_cost_upper_bounds_respected", cost_bounds_respected)
        object.__setattr__(self, "_conservative_floor_preserved", floor_preserved)
        object.__setattr__(self, "_record_id", "historical-record-" + canonical_sha256(identity))
        canonical_json_bytes(self.to_json_value())

    @property
    def cohort(self) -> HistoricalCohortKey:
        return self._cohort

    @property
    def disposition(self) -> HistoricalDisposition:
        return self._disposition

    @property
    def record_id(self) -> str:
        return self._record_id

    @property
    def capital_at_risk(self) -> int:
        return self.package.unsigned_package.net_profit_evidence.plan.opportunity.capital_at_risk

    @property
    def predicted_conservative_net_profit(self) -> int:
        return self._predicted_conservative_net_profit

    @property
    def predicted_external_cost_base_upper_bound(self) -> int:
        return self._predicted_external_cost_base_upper_bound

    @property
    def actual_external_cost_base_upper_bound(self) -> int | None:
        return self._actual_external_cost_base_upper_bound

    @property
    def historical_conservative_surplus(self) -> int | None:
        return self._historical_conservative_surplus

    @property
    def prediction_error(self) -> int | None:
        return self._prediction_error

    @property
    def absolute_prediction_error(self) -> int | None:
        return abs(self.prediction_error) if self.prediction_error is not None else None

    @property
    def economics_scoreable(self) -> bool:
        return self.outcome is not None

    @property
    def execution_success(self) -> bool:
        return self.inclusion.receipt.success

    @property
    def settlement_observed(self) -> bool:
        return self._settlement_event_observed

    @property
    def outcome_evidence_complete(self) -> bool:
        return self.outcome is not None

    @property
    def conservative_floor_preserved(self) -> bool:
        return self._conservative_floor_preserved

    @property
    def positive_historical_surplus(self) -> bool:
        return self.historical_conservative_surplus is not None and self.historical_conservative_surplus > 0

    @property
    def simulation_exact_match(self) -> bool:
        return self.outcome.simulation_exact_match if self.outcome is not None else False

    @property
    def cost_upper_bounds_respected(self) -> bool:
        return self._cost_upper_bounds_respected

    @property
    def native_cost_overrun(self) -> int | None:
        return self.outcome.native_cost_overrun if self.outcome is not None else None

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "record_id": self.record_id,
            "cohort": self.cohort.to_json_value(),
            "cohort_sha256": self.cohort.digest,
            "package_sha256": self.package.digest,
            "inclusion_sha256": self.inclusion.digest,
            "settlement_event_registry_sha256": self.settlement_registry.digest,
            "settlement_event_spec_sha256": self.settlement_spec.digest,
            "rollup_fee_sha256": self.rollup_fee.digest,
            "outcome_sha256": self.outcome.digest if self.outcome is not None else None,
            "historical_valuation_policy": self.historical_valuation_policy.to_json_value(),
            "historical_valuation_policy_sha256": self.historical_valuation_policy.digest,
            "historical_valuation_book": self.historical_valuation_book.to_json_value(),
            "historical_valuation_book_sha256": self.historical_valuation_book.digest,
            "transaction_hash": self.package.signed_transaction.transaction_hash_hex,
            "block_number": str(self.inclusion.block.block_number),
            "transaction_index": str(self.inclusion.transaction_index),
            "disposition": self.disposition.value,
            "capital_at_risk": str(self.capital_at_risk),
            "predicted_conservative_net_profit": str(self.predicted_conservative_net_profit),
            "predicted_external_cost_base_upper_bound": str(
                self.predicted_external_cost_base_upper_bound
            ),
            "actual_external_cost_base_upper_bound": (
                str(self.actual_external_cost_base_upper_bound)
                if self.actual_external_cost_base_upper_bound is not None
                else None
            ),
            "historical_conservative_surplus": (
                str(self.historical_conservative_surplus)
                if self.historical_conservative_surplus is not None
                else None
            ),
            "prediction_error": (
                str(self.prediction_error) if self.prediction_error is not None else None
            ),
            "absolute_prediction_error": (
                str(self.absolute_prediction_error)
                if self.absolute_prediction_error is not None
                else None
            ),
            "execution_success": self.execution_success,
            "settlement_observed": self.settlement_observed,
            "outcome_evidence_complete": self.outcome_evidence_complete,
            "economics_scoreable": self.economics_scoreable,
            "simulation_exact_match": self.simulation_exact_match,
            "cost_upper_bounds_respected": self.cost_upper_bounds_respected,
            "native_cost_overrun": (
                str(self.native_cost_overrun) if self.native_cost_overrun is not None else None
            ),
            "conservative_floor_preserved": self.conservative_floor_preserved,
            "positive_historical_surplus": self.positive_historical_surplus,
            "recorded_at_unix_ms": str(self.recorded_at_unix_ms),
            "economic_authority": "authenticated-settlement-minus-historical-conservative-cost-upper-bound-only",
            "inclusion_conditioned": True,
            "realized_profit_claimed": False,
            "production_promotion_authority": False,
            "submission_authority": "none",
            "execution_authority": "none",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class HistoricalAttemptReference:
    chain: Chain
    package_sha256: str
    inclusion_sha256: str
    transaction_hash: bytes
    block_number: int
    transaction_index: int
    schema: str = ATTEMPT_REFERENCE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != ATTEMPT_REFERENCE_SCHEMA:
            raise ValueError("unsupported historical-attempt-reference schema")
        if type(self.chain) is not Chain or self.chain not in {Chain.ETHEREUM, Chain.BASE}:
            raise ValueError("historical attempt references support Ethereum and Base only")
        require_sha256("package_sha256", self.package_sha256)
        require_sha256("inclusion_sha256", self.inclusion_sha256)
        if type(self.transaction_hash) is not bytes or len(self.transaction_hash) != 32:
            raise ValueError("transaction_hash must be exact immutable 32-byte data")
        if self.transaction_hash == bytes(32):
            raise ValueError("transaction_hash cannot be zero")
        _uint64("block_number", self.block_number)
        _uint64("transaction_index", self.transaction_index)
        canonical_json_bytes(self.to_json_value())

    @classmethod
    def from_record(cls, record: HistoricalExecutionRecord) -> HistoricalAttemptReference:
        if type(record) is not HistoricalExecutionRecord:
            raise TypeError("record must be an exact HistoricalExecutionRecord")
        return cls(
            chain=record.cohort.chain,
            package_sha256=record.package.digest,
            inclusion_sha256=record.inclusion.digest,
            transaction_hash=record.package.signed_transaction.transaction_hash,
            block_number=record.inclusion.block.block_number,
            transaction_index=record.inclusion.transaction_index,
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "chain": self.chain.value,
            "package_sha256": self.package_sha256,
            "inclusion_sha256": self.inclusion_sha256,
            "transaction_hash": to_hex_data(self.transaction_hash),
            "block_number": str(self.block_number),
            "transaction_index": str(self.transaction_index),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class HistoricalCorpusSourceManifest:
    manifest_id: str
    source_id: str
    source_sha256: str
    chain: Chain
    start_block_number: int
    end_block_number: int
    references: tuple[HistoricalAttemptReference, ...]
    created_at_unix_ms: int
    schema: str = SOURCE_MANIFEST_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SOURCE_MANIFEST_SCHEMA:
            raise ValueError("unsupported historical-corpus-source-manifest schema")
        require_bounded_text("manifest_id", self.manifest_id, maximum=128)
        require_bounded_text("source_id", self.source_id, maximum=128)
        require_sha256("source_sha256", self.source_sha256)
        if type(self.chain) is not Chain or self.chain not in {Chain.ETHEREUM, Chain.BASE}:
            raise ValueError("historical source manifests support Ethereum and Base only")
        _uint64("start_block_number", self.start_block_number)
        _uint64("end_block_number", self.end_block_number)
        if self.end_block_number < self.start_block_number:
            raise ValueError("historical source manifest block window is inverted")
        if type(self.references) is not tuple or not self.references:
            raise TypeError("historical source manifest references must be a non-empty exact tuple")
        if len(self.references) > MAX_CORPUS_RECORDS:
            raise ValueError("historical source manifest exceeds the governed attempt ceiling")
        if any(type(item) is not HistoricalAttemptReference for item in self.references):
            raise TypeError("historical source manifest contains an ungoverned attempt reference")
        ordered = tuple(
            sorted(
                self.references,
                key=lambda item: (
                    item.block_number,
                    item.transaction_index,
                    item.transaction_hash,
                    item.digest,
                ),
            )
        )
        object.__setattr__(self, "references", ordered)
        for item in ordered:
            if item.chain is not self.chain:
                raise ValueError("historical source manifest contains a cross-chain reference")
            if not self.start_block_number <= item.block_number <= self.end_block_number:
                raise ValueError("historical attempt lies outside the declared source block window")
        _uint64("created_at_unix_ms", self.created_at_unix_ms)
        for name, values in (
            ("attempt reference", [item.digest for item in ordered]),
            ("package", [item.package_sha256 for item in ordered]),
            ("inclusion", [item.inclusion_sha256 for item in ordered]),
            ("transaction", [item.transaction_hash for item in ordered]),
            (
                "inclusion position",
                [(item.block_number, item.transaction_index) for item in ordered],
            ),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"historical source manifest contains duplicate {name} identity")
        canonical_json_bytes(self.to_json_value())

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "manifest_id": self.manifest_id,
            "source_id": self.source_id,
            "source_sha256": self.source_sha256,
            "chain": self.chain.value,
            "start_block_number": str(self.start_block_number),
            "end_block_number": str(self.end_block_number),
            "references": [item.to_json_value() for item in self.references],
            "reference_sha256": [item.digest for item in self.references],
            "reference_count": str(len(self.references)),
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "completeness_scope": "exact-declared-source-window-reference-set-only",
            "global_completeness_guarantee": False,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class HistoricalOutcomeCorpus:
    source_manifest: HistoricalCorpusSourceManifest
    records: tuple[HistoricalExecutionRecord, ...]
    created_at_unix_ms: int
    schema: str = CORPUS_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != CORPUS_SCHEMA:
            raise ValueError("unsupported historical-outcome-corpus schema")
        if type(self.source_manifest) is not HistoricalCorpusSourceManifest:
            raise TypeError("source_manifest must be an exact HistoricalCorpusSourceManifest")
        if type(self.records) is not tuple or not self.records:
            raise TypeError("records must be a non-empty exact tuple")
        if len(self.records) > MAX_CORPUS_RECORDS:
            raise ValueError("historical corpus exceeds the governed record ceiling")
        if any(type(item) is not HistoricalExecutionRecord for item in self.records):
            raise TypeError("historical corpus contains an ungoverned record")
        ordered = tuple(
            sorted(
                self.records,
                key=lambda item: (
                    item.cohort.chain.value,
                    item.inclusion.block.block_number,
                    item.inclusion.transaction_index,
                    item.package.signed_transaction.transaction_hash,
                    item.digest,
                ),
            )
        )
        object.__setattr__(self, "records", ordered)
        _uint64("created_at_unix_ms", self.created_at_unix_ms)
        latest = max(
            self.source_manifest.created_at_unix_ms,
            max(item.recorded_at_unix_ms for item in ordered),
        )
        if self.created_at_unix_ms < latest:
            raise ValueError("corpus creation time predates its source manifest or a retained record")
        record_ids = [item.record_id for item in ordered]
        if len(record_ids) != len(set(record_ids)):
            raise ValueError("historical corpus contains duplicate record identity")
        transactions = [
            (item.cohort.chain, item.package.signed_transaction.transaction_hash)
            for item in ordered
        ]
        if len(transactions) != len(set(transactions)):
            raise ValueError("historical corpus contains duplicate transaction identity")
        positions = [
            (
                item.cohort.chain,
                item.inclusion.block.block_number,
                item.inclusion.transaction_index,
            )
            for item in ordered
        ]
        if len(positions) != len(set(positions)):
            raise ValueError("historical corpus contains duplicate inclusion position")
        references = tuple(HistoricalAttemptReference.from_record(item) for item in ordered)
        expected = tuple(item.digest for item in self.source_manifest.references)
        actual = tuple(sorted(item.digest for item in references))
        if actual != tuple(sorted(expected)) or len(actual) != len(expected):
            raise ValueError("historical corpus does not consume the exact source-manifest reference set")
        canonical_json_bytes(self.to_json_value())

    @property
    def cohort_sha256(self) -> tuple[str, ...]:
        return tuple(sorted({item.cohort.digest for item in self.records}))

    def records_for(self, cohort: HistoricalCohortKey) -> tuple[HistoricalExecutionRecord, ...]:
        if type(cohort) is not HistoricalCohortKey:
            raise TypeError("cohort must be an exact HistoricalCohortKey")
        return tuple(item for item in self.records if item.cohort.digest == cohort.digest)

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "source_manifest": self.source_manifest.to_json_value(),
            "source_manifest_sha256": self.source_manifest.digest,
            "records": [item.to_json_value() for item in self.records],
            "record_sha256": [item.digest for item in self.records],
            "cohort_sha256": list(self.cohort_sha256),
            "record_count": str(len(self.records)),
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "corpus_authority": "offline-exact-declared-source-window-inclusion-conditioned-history-only",
            "selection_bias_control": "all-declared-source-references-consumed-with-explicit-scoreability",
            "global_completeness_guarantee": False,
            "realized_profit_authority": "none",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class HistoricalEconomicScoreboard:
    corpus: HistoricalOutcomeCorpus
    cohort: HistoricalCohortKey
    created_at_unix_ms: int
    schema: str = SCOREBOARD_SCHEMA
    _records: tuple[HistoricalExecutionRecord, ...] = field(init=False, repr=False)
    _metrics: tuple[tuple[str, int], ...] = field(init=False, repr=False)
    _scoreboard_id: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != SCOREBOARD_SCHEMA:
            raise ValueError("unsupported historical-economic-scoreboard schema")
        if type(self.corpus) is not HistoricalOutcomeCorpus:
            raise TypeError("corpus must be an exact HistoricalOutcomeCorpus")
        if type(self.cohort) is not HistoricalCohortKey:
            raise TypeError("cohort must be an exact HistoricalCohortKey")
        _uint64("created_at_unix_ms", self.created_at_unix_ms)
        if self.created_at_unix_ms < self.corpus.created_at_unix_ms:
            raise ValueError("scoreboard creation time predates its corpus")
        records = self.corpus.records_for(self.cohort)
        if not records:
            raise ValueError("scoreboard cohort is absent from the exact corpus")
        attempts = len(records)
        scoreable = tuple(item for item in records if item.economics_scoreable)
        successes = sum(1 for item in records if item.execution_success)
        settlement_observed = sum(1 for item in records if item.settlement_observed)
        outcome_complete = sum(1 for item in records if item.outcome_evidence_complete)
        settled = sum(
            1 for item in records if item.disposition is HistoricalDisposition.SETTLED
        )
        reverted = sum(
            1 for item in records if item.disposition is HistoricalDisposition.REVERTED
        )
        settlement_missing = sum(
            1
            for item in records
            if item.disposition is HistoricalDisposition.SETTLEMENT_MISSING
        )
        settlement_evidence_incomplete = sum(
            1
            for item in records
            if item.disposition
            is HistoricalDisposition.SETTLEMENT_EVIDENCE_INCOMPLETE
        )
        floor_count = sum(1 for item in scoreable if item.conservative_floor_preserved)
        simulation_exact = sum(1 for item in scoreable if item.simulation_exact_match)
        cost_bound = sum(1 for item in scoreable if item.cost_upper_bounds_respected)
        positive = sum(1 for item in scoreable if item.positive_historical_surplus)
        native_overrun = sum(1 for item in scoreable if (item.native_cost_overrun or 0) > 0)
        predicted_sum = _checked_sum(
            tuple(item.predicted_conservative_net_profit for item in scoreable),
            "predicted conservative net sum",
        )
        historical_sum = _checked_sum(
            tuple(item.historical_conservative_surplus or 0 for item in scoreable),
            "historical conservative surplus sum",
        )
        error_sum = _checked_sum(
            tuple(item.prediction_error or 0 for item in scoreable),
            "prediction error sum",
        )
        absolute_error_sum = _checked_sum(
            tuple(item.absolute_prediction_error or 0 for item in scoreable),
            "absolute prediction error sum",
        )
        total_capital = _checked_sum(
            tuple(item.capital_at_risk for item in records),
            "attempt capital at risk sum",
        )
        scoreable_capital = _checked_sum(
            tuple(item.capital_at_risk for item in scoreable),
            "scoreable capital at risk sum",
        )
        mean_surplus = historical_sum // len(scoreable) if scoreable else 0
        mean_abs_error = _ceil_div(absolute_error_sum, len(scoreable)) if scoreable else 0
        guarded_mean = _checked_add(mean_surplus, -mean_abs_error, "guarded mean surplus")
        unique_blocks = len({item.inclusion.block.block_number for item in records})
        unique_scoreable_blocks = len(
            {item.inclusion.block.block_number for item in scoreable}
        )
        aggregate_return = (
            _signed_ratio_bps_floor(historical_sum, scoreable_capital)
            if scoreable_capital
            else 0
        )
        mae_bps = (
            _unsigned_ratio_bps_ceiling_saturated(
                absolute_error_sum,
                scoreable_capital,
            )
            if scoreable_capital
            else 0
        )
        metrics = {
            "attempt_count": attempts,
            "execution_success_count": successes,
            "settled_count": settled,
            "reverted_count": reverted,
            "settlement_missing_count": settlement_missing,
            "settlement_evidence_incomplete_count": settlement_evidence_incomplete,
            "settlement_observed_count": settlement_observed,
            "outcome_evidence_complete_count": outcome_complete,
            "scoreable_count": len(scoreable),
            "unscoreable_count": attempts - len(scoreable),
            "unique_inclusion_block_count": unique_blocks,
            "unique_scoreable_inclusion_block_count": unique_scoreable_blocks,
            "floor_preserved_count": floor_count,
            "simulation_exact_match_count": simulation_exact,
            "cost_upper_bounds_respected_count": cost_bound,
            "positive_historical_surplus_count": positive,
            "native_cost_overrun_count": native_overrun,
            "execution_success_rate_bps": _ratio_bps(successes, attempts),
            "settlement_observed_rate_bps": _ratio_bps(
                settlement_observed,
                attempts,
            ),
            "outcome_evidence_complete_rate_bps": _ratio_bps(
                outcome_complete,
                attempts,
            ),
            "scoreable_rate_bps": _ratio_bps(len(scoreable), attempts),
            "floor_preservation_rate_bps": _ratio_bps(floor_count, len(scoreable)),
            "simulation_exact_match_rate_bps": _ratio_bps(simulation_exact, len(scoreable)),
            "cost_upper_bound_respect_rate_bps": _ratio_bps(cost_bound, len(scoreable)),
            "positive_historical_surplus_rate_bps": _ratio_bps(positive, len(scoreable)),
            "native_cost_overrun_rate_bps": _ratio_bps(native_overrun, len(scoreable)),
            "predicted_conservative_net_profit_sum": predicted_sum,
            "historical_conservative_surplus_sum": historical_sum,
            "prediction_error_sum": error_sum,
            "absolute_prediction_error_sum": absolute_error_sum,
            "attempt_capital_at_risk_sum": total_capital,
            "scoreable_capital_at_risk_sum": scoreable_capital,
            "mean_historical_conservative_surplus_floor": mean_surplus,
            "mean_absolute_prediction_error_ceiling": mean_abs_error,
            "mean_absolute_prediction_error_bps_of_capital_ceiling": mae_bps,
            "guarded_mean_historical_surplus_floor": guarded_mean,
            "aggregate_historical_return_bps_floor": aggregate_return,
        }
        ordered_metrics = tuple(sorted(metrics.items()))
        identity = {
            "schema": self.schema,
            "corpus_sha256": self.corpus.digest,
            "cohort_sha256": self.cohort.digest,
            "record_sha256": [item.digest for item in records],
            "metrics": {key: str(value) for key, value in ordered_metrics},
            "created_at_unix_ms": str(self.created_at_unix_ms),
        }
        object.__setattr__(self, "_records", records)
        object.__setattr__(self, "_metrics", ordered_metrics)
        object.__setattr__(self, "_scoreboard_id", "historical-scoreboard-" + canonical_sha256(identity))
        canonical_json_bytes(self.to_json_value())

    @property
    def records(self) -> tuple[HistoricalExecutionRecord, ...]:
        return self._records

    @property
    def metrics(self) -> dict[str, int]:
        return dict(self._metrics)

    @property
    def scoreboard_id(self) -> str:
        return self._scoreboard_id

    def __getattr__(self, name: str) -> int:
        metrics = dict(object.__getattribute__(self, "_metrics"))
        if name in metrics:
            return metrics[name]
        raise AttributeError(name)

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "scoreboard_id": self.scoreboard_id,
            "corpus_sha256": self.corpus.digest,
            "source_manifest_sha256": self.corpus.source_manifest.digest,
            "source_completeness_scope": "exact-declared-source-window-reference-set-only",
            "global_completeness_guarantee": False,
            "cohort": self.cohort.to_json_value(),
            "cohort_sha256": self.cohort.digest,
            "record_sha256": [item.digest for item in self.records],
            "metrics": {key: str(value) for key, value in self._metrics},
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "scoreboard_scope": "exact-cohort-inclusion-conditioned-history",
            "unscoreable_records_retained": True,
            "confidence_guarantee": False,
            "realized_profit_claimed": False,
            "production_promotion_authority": False,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class CalibrationPolicy:
    policy_id: str
    predicted_return_upper_bounds_bps: tuple[int, ...]
    schema: str = CALIBRATION_POLICY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != CALIBRATION_POLICY_SCHEMA:
            raise ValueError("unsupported calibration-policy schema")
        require_bounded_text("policy_id", self.policy_id, maximum=128)
        if type(self.predicted_return_upper_bounds_bps) is not tuple:
            raise TypeError("predicted_return_upper_bounds_bps must be an exact tuple")
        if len(self.predicted_return_upper_bounds_bps) > MAX_CALIBRATION_BUCKETS - 1:
            raise ValueError("calibration policy exceeds the governed bucket ceiling")
        for value in self.predicted_return_upper_bounds_bps:
            _uint256("predicted return upper bound", value, positive=True)
        if tuple(sorted(set(self.predicted_return_upper_bounds_bps))) != self.predicted_return_upper_bounds_bps:
            raise ValueError("calibration upper bounds must be strictly increasing and unique")
        canonical_json_bytes(self.to_json_value())

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "policy_id": self.policy_id,
            "predicted_return_upper_bounds_bps": [
                str(value) for value in self.predicted_return_upper_bounds_bps
            ],
            "bucket_semantics": "lower-inclusive-upper-exclusive-plus-open-ended-final-bucket",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class CalibrationBucket:
    lower_bound_bps: int
    upper_bound_bps: int | None
    attempt_count: int
    scoreable_count: int
    floor_preserved_count: int
    predicted_sum: int
    historical_sum: int
    prediction_error_sum: int
    absolute_prediction_error_sum: int
    schema: str = CALIBRATION_BUCKET_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != CALIBRATION_BUCKET_SCHEMA:
            raise ValueError("unsupported calibration-bucket schema")
        _uint256("lower_bound_bps", self.lower_bound_bps)
        if self.upper_bound_bps is not None:
            _uint256("upper_bound_bps", self.upper_bound_bps)
            if self.upper_bound_bps <= self.lower_bound_bps:
                raise ValueError("calibration bucket upper bound must exceed lower bound")
        for name in ("attempt_count", "scoreable_count", "floor_preserved_count"):
            value = getattr(self, name)
            if type(value) is not int or value < 0 or value > MAX_CORPUS_RECORDS:
                raise ValueError(f"{name} is outside the governed record domain")
        if self.scoreable_count > self.attempt_count:
            raise ValueError("scoreable_count exceeds attempt_count")
        if self.floor_preserved_count > self.scoreable_count:
            raise ValueError("floor_preserved_count exceeds scoreable_count")
        for name in (
            "predicted_sum",
            "historical_sum",
            "prediction_error_sum",
            "absolute_prediction_error_sum",
        ):
            _signed_aggregate(name, getattr(self, name))
        if self.absolute_prediction_error_sum < 0:
            raise ValueError("absolute_prediction_error_sum cannot be negative")
        if self.scoreable_count == 0 and any(
            value != 0
            for value in (
                self.predicted_sum,
                self.historical_sum,
                self.prediction_error_sum,
                self.absolute_prediction_error_sum,
                self.floor_preserved_count,
            )
        ):
            raise ValueError("empty scoreable calibration bucket cannot carry economic aggregates")
        if self.prediction_error_sum != self.historical_sum - self.predicted_sum:
            raise ValueError("calibration prediction error does not reconcile")
        canonical_json_bytes(self.to_json_value())

    @property
    def scoreable_rate_bps(self) -> int:
        return _ratio_bps(self.scoreable_count, self.attempt_count)

    @property
    def floor_preservation_rate_bps(self) -> int:
        return _ratio_bps(self.floor_preserved_count, self.scoreable_count)

    @property
    def mean_prediction_error_floor(self) -> int:
        return self.prediction_error_sum // self.scoreable_count if self.scoreable_count else 0

    @property
    def mean_absolute_prediction_error_ceiling(self) -> int:
        return (
            _ceil_div(self.absolute_prediction_error_sum, self.scoreable_count)
            if self.scoreable_count
            else 0
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "lower_bound_bps": str(self.lower_bound_bps),
            "upper_bound_bps": str(self.upper_bound_bps) if self.upper_bound_bps is not None else None,
            "attempt_count": str(self.attempt_count),
            "scoreable_count": str(self.scoreable_count),
            "floor_preserved_count": str(self.floor_preserved_count),
            "scoreable_rate_bps": str(self.scoreable_rate_bps),
            "floor_preservation_rate_bps": str(self.floor_preservation_rate_bps),
            "predicted_sum": str(self.predicted_sum),
            "historical_sum": str(self.historical_sum),
            "prediction_error_sum": str(self.prediction_error_sum),
            "absolute_prediction_error_sum": str(self.absolute_prediction_error_sum),
            "mean_prediction_error_floor": str(self.mean_prediction_error_floor),
            "mean_absolute_prediction_error_ceiling": str(
                self.mean_absolute_prediction_error_ceiling
            ),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class HistoricalCalibrationReport:
    scoreboard: HistoricalEconomicScoreboard
    policy: CalibrationPolicy
    created_at_unix_ms: int
    schema: str = CALIBRATION_REPORT_SCHEMA
    _buckets: tuple[CalibrationBucket, ...] = field(init=False, repr=False)
    _report_id: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != CALIBRATION_REPORT_SCHEMA:
            raise ValueError("unsupported historical-calibration-report schema")
        if type(self.scoreboard) is not HistoricalEconomicScoreboard:
            raise TypeError("scoreboard must be an exact HistoricalEconomicScoreboard")
        if type(self.policy) is not CalibrationPolicy:
            raise TypeError("policy must be an exact CalibrationPolicy")
        _uint64("created_at_unix_ms", self.created_at_unix_ms)
        if self.created_at_unix_ms < self.scoreboard.created_at_unix_ms:
            raise ValueError("calibration report predates its scoreboard")
        bounds = self.policy.predicted_return_upper_bounds_bps
        bucket_records: list[list[HistoricalExecutionRecord]] = [
            [] for _ in range(len(bounds) + 1)
        ]
        for record in self.scoreboard.records:
            predicted_return = _signed_ratio_bps_floor(
                record.predicted_conservative_net_profit,
                record.capital_at_risk,
            )
            if predicted_return < 0:
                raise ValueError("approved F5 package cannot carry negative predicted return")
            index = len(bounds)
            for candidate, upper in enumerate(bounds):
                if predicted_return < upper:
                    index = candidate
                    break
            bucket_records[index].append(record)
        buckets: list[CalibrationBucket] = []
        lower = 0
        for index, records in enumerate(bucket_records):
            upper = bounds[index] if index < len(bounds) else None
            scoreable = tuple(item for item in records if item.economics_scoreable)
            predicted_sum = _checked_sum(
                tuple(item.predicted_conservative_net_profit for item in scoreable),
                "calibration predicted sum",
            )
            historical_sum = _checked_sum(
                tuple(item.historical_conservative_surplus or 0 for item in scoreable),
                "calibration historical sum",
            )
            error_sum = _checked_sum(
                tuple(item.prediction_error or 0 for item in scoreable),
                "calibration error sum",
            )
            abs_error_sum = _checked_sum(
                tuple(item.absolute_prediction_error or 0 for item in scoreable),
                "calibration absolute error sum",
            )
            buckets.append(
                CalibrationBucket(
                    lower_bound_bps=lower,
                    upper_bound_bps=upper,
                    attempt_count=len(records),
                    scoreable_count=len(scoreable),
                    floor_preserved_count=sum(
                        1 for item in scoreable if item.conservative_floor_preserved
                    ),
                    predicted_sum=predicted_sum,
                    historical_sum=historical_sum,
                    prediction_error_sum=error_sum,
                    absolute_prediction_error_sum=abs_error_sum,
                )
            )
            if upper is not None:
                lower = upper
        bucket_tuple = tuple(buckets)
        if sum(item.attempt_count for item in bucket_tuple) != self.scoreboard.attempt_count:
            raise RuntimeError("calibration buckets do not partition the exact scoreboard")
        identity = {
            "schema": self.schema,
            "scoreboard_sha256": self.scoreboard.digest,
            "policy_sha256": self.policy.digest,
            "bucket_sha256": [item.digest for item in bucket_tuple],
            "created_at_unix_ms": str(self.created_at_unix_ms),
        }
        object.__setattr__(self, "_buckets", bucket_tuple)
        object.__setattr__(self, "_report_id", "historical-calibration-" + canonical_sha256(identity))
        canonical_json_bytes(self.to_json_value())

    @property
    def buckets(self) -> tuple[CalibrationBucket, ...]:
        return self._buckets

    @property
    def report_id(self) -> str:
        return self._report_id

    @property
    def nonempty_bucket_count(self) -> int:
        return sum(1 for item in self.buckets if item.attempt_count > 0)

    @property
    def worst_nonempty_bucket_mean_absolute_error_ceiling(self) -> int:
        values = [
            item.mean_absolute_prediction_error_ceiling
            for item in self.buckets
            if item.scoreable_count > 0
        ]
        return max(values, default=0)

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "report_id": self.report_id,
            "scoreboard_sha256": self.scoreboard.digest,
            "source_manifest_sha256": self.scoreboard.corpus.source_manifest.digest,
            "source_completeness_scope": "exact-declared-source-window-reference-set-only",
            "global_completeness_guarantee": False,
            "policy": self.policy.to_json_value(),
            "policy_sha256": self.policy.digest,
            "buckets": [item.to_json_value() for item in self.buckets],
            "bucket_sha256": [item.digest for item in self.buckets],
            "nonempty_bucket_count": str(self.nonempty_bucket_count),
            "worst_nonempty_bucket_mean_absolute_error_ceiling": str(
                self.worst_nonempty_bucket_mean_absolute_error_ceiling
            ),
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "calibration_scope": "exact-cohort-inclusion-conditioned-scoreable-subset",
            "unscoreable_records_retained_in_bucket_attempt_counts": True,
            "confidence_guarantee": False,
            "production_promotion_authority": False,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class HistoricalExpectedValueEvidence:
    scoreboard: HistoricalEconomicScoreboard
    created_at_unix_ms: int
    schema: str = EXPECTED_VALUE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != EXPECTED_VALUE_SCHEMA:
            raise ValueError("unsupported historical-expected-value schema")
        if type(self.scoreboard) is not HistoricalEconomicScoreboard:
            raise TypeError("scoreboard must be an exact HistoricalEconomicScoreboard")
        _uint64("created_at_unix_ms", self.created_at_unix_ms)
        if self.created_at_unix_ms < self.scoreboard.created_at_unix_ms:
            raise ValueError("expected-value evidence predates its scoreboard")
        canonical_json_bytes(self.to_json_value())

    @property
    def available(self) -> bool:
        return self.scoreboard.scoreable_count > 0

    @property
    def sample_count(self) -> int:
        return self.scoreboard.scoreable_count

    @property
    def unscoreable_record_count(self) -> int:
        return self.scoreboard.unscoreable_count

    @property
    def unique_scoreable_inclusion_block_count(self) -> int:
        return self.scoreboard.unique_scoreable_inclusion_block_count

    @property
    def historical_surplus_sum(self) -> int:
        return self.scoreboard.historical_conservative_surplus_sum

    @property
    def sample_mean_floor(self) -> int:
        return self.scoreboard.mean_historical_conservative_surplus_floor

    @property
    def mean_absolute_prediction_error_ceiling(self) -> int:
        return self.scoreboard.mean_absolute_prediction_error_ceiling

    @property
    def guarded_sample_mean_floor(self) -> int:
        return self.scoreboard.guarded_mean_historical_surplus_floor

    @property
    def aggregate_return_bps_floor(self) -> int:
        return self.scoreboard.aggregate_historical_return_bps_floor

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "scoreboard_sha256": self.scoreboard.digest,
            "source_manifest_sha256": self.scoreboard.corpus.source_manifest.digest,
            "source_completeness_scope": "exact-declared-source-window-reference-set-only",
            "global_completeness_guarantee": False,
            "available": self.available,
            "sample_count": str(self.sample_count),
            "unscoreable_record_count": str(self.unscoreable_record_count),
            "unique_scoreable_inclusion_block_count": str(
                self.unique_scoreable_inclusion_block_count
            ),
            "historical_surplus_sum": str(self.historical_surplus_sum),
            "sample_mean_floor": str(self.sample_mean_floor),
            "mean_absolute_prediction_error_ceiling": str(
                self.mean_absolute_prediction_error_ceiling
            ),
            "guarded_sample_mean_floor": str(self.guarded_sample_mean_floor),
            "aggregate_return_bps_floor": str(self.aggregate_return_bps_floor),
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "conditioning": "authenticated-successful-settlement-with-scoreable-economics-only",
            "availability_semantics": "available-only-when-scoreable-sample-count-is-positive",
            "selection_bias_disclosure": "unscoreable-declared-source-records-retained-but-excluded-from-economic-mean-and-scoreable-block-diversity-no-global-completeness-guarantee",
            "sample_diversity_semantics": "unique-inclusion-blocks-among-scoreable-economic-sample-only",
            "statistical_semantics": "empirical-mean-minus-mean-absolute-prediction-error-screen",
            "confidence_guarantee": False,
            "realized_profit_claimed": False,
            "production_promotion_authority": False,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class ResearchPromotionPolicy:
    policy_id: str
    minimum_attempts: int
    minimum_scoreable_records: int
    minimum_scoreable_rate_bps: int
    minimum_execution_success_rate_bps: int
    minimum_floor_preservation_rate_bps: int
    minimum_cost_upper_bound_respect_rate_bps: int
    minimum_positive_surplus_rate_bps: int
    minimum_unique_scoreable_inclusion_blocks: int
    maximum_native_cost_overrun_rate_bps: int
    maximum_mean_absolute_error_bps_of_capital: int
    minimum_guarded_mean_surplus: int
    minimum_scoreable_records_per_nonempty_bucket: int
    schema: str = PROMOTION_POLICY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != PROMOTION_POLICY_SCHEMA:
            raise ValueError("unsupported research-promotion-policy schema")
        require_bounded_text("policy_id", self.policy_id, maximum=128)
        for name in (
            "minimum_attempts",
            "minimum_scoreable_records",
            "minimum_unique_scoreable_inclusion_blocks",
            "minimum_scoreable_records_per_nonempty_bucket",
        ):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= MAX_CORPUS_RECORDS:
                raise ValueError(f"{name} must be a positive governed record count")
        if self.minimum_scoreable_records > self.minimum_attempts:
            raise ValueError("minimum_scoreable_records cannot exceed minimum_attempts")
        if self.minimum_unique_scoreable_inclusion_blocks > self.minimum_attempts:
            raise ValueError(
                "minimum_unique_scoreable_inclusion_blocks cannot exceed minimum_attempts"
            )
        for name in (
            "minimum_scoreable_rate_bps",
            "minimum_execution_success_rate_bps",
            "minimum_floor_preservation_rate_bps",
            "minimum_cost_upper_bound_respect_rate_bps",
            "minimum_positive_surplus_rate_bps",
            "maximum_native_cost_overrun_rate_bps",
            "maximum_mean_absolute_error_bps_of_capital",
        ):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= BASIS_POINTS:
                raise ValueError(f"{name} must be an exact basis-point value")
        _signed_aggregate("minimum_guarded_mean_surplus", self.minimum_guarded_mean_surplus)
        canonical_json_bytes(self.to_json_value())

    def to_json_value(self) -> dict[str, str]:
        return {
            "schema": self.schema,
            "policy_id": self.policy_id,
            "minimum_attempts": str(self.minimum_attempts),
            "minimum_scoreable_records": str(self.minimum_scoreable_records),
            "minimum_scoreable_rate_bps": str(self.minimum_scoreable_rate_bps),
            "minimum_execution_success_rate_bps": str(
                self.minimum_execution_success_rate_bps
            ),
            "minimum_floor_preservation_rate_bps": str(
                self.minimum_floor_preservation_rate_bps
            ),
            "minimum_cost_upper_bound_respect_rate_bps": str(
                self.minimum_cost_upper_bound_respect_rate_bps
            ),
            "minimum_positive_surplus_rate_bps": str(
                self.minimum_positive_surplus_rate_bps
            ),
            "minimum_unique_scoreable_inclusion_blocks": str(
                self.minimum_unique_scoreable_inclusion_blocks
            ),
            "inclusion_block_diversity_semantics": (
                "minimum-applies-to-scoreable-economic-sample-only"
            ),
            "maximum_native_cost_overrun_rate_bps": str(
                self.maximum_native_cost_overrun_rate_bps
            ),
            "maximum_mean_absolute_error_bps_of_capital": str(
                self.maximum_mean_absolute_error_bps_of_capital
            ),
            "minimum_guarded_mean_surplus": str(self.minimum_guarded_mean_surplus),
            "minimum_scoreable_records_per_nonempty_bucket": str(
                self.minimum_scoreable_records_per_nonempty_bucket
            ),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class ResearchPromotionDecision:
    scoreboard: HistoricalEconomicScoreboard
    calibration: HistoricalCalibrationReport
    expected_value: HistoricalExpectedValueEvidence
    policy: ResearchPromotionPolicy
    created_at_unix_ms: int
    schema: str = PROMOTION_DECISION_SCHEMA
    _allowed: bool = field(init=False, repr=False)
    _reasons: tuple[ResearchPromotionReason, ...] = field(init=False, repr=False)
    _decision_id: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != PROMOTION_DECISION_SCHEMA:
            raise ValueError("unsupported research-promotion-decision schema")
        if type(self.scoreboard) is not HistoricalEconomicScoreboard:
            raise TypeError("scoreboard must be an exact HistoricalEconomicScoreboard")
        if type(self.calibration) is not HistoricalCalibrationReport:
            raise TypeError("calibration must be an exact HistoricalCalibrationReport")
        if type(self.expected_value) is not HistoricalExpectedValueEvidence:
            raise TypeError("expected_value must be exact HistoricalExpectedValueEvidence")
        if type(self.policy) is not ResearchPromotionPolicy:
            raise TypeError("policy must be an exact ResearchPromotionPolicy")
        _uint64("created_at_unix_ms", self.created_at_unix_ms)
        latest = max(
            self.scoreboard.created_at_unix_ms,
            self.calibration.created_at_unix_ms,
            self.expected_value.created_at_unix_ms,
        )
        if self.created_at_unix_ms < latest:
            raise ValueError("promotion decision predates its bound evidence")
        if self.calibration.scoreboard.digest != self.scoreboard.digest:
            raise ValueError("calibration does not bind the exact scoreboard")
        if self.expected_value.scoreboard.digest != self.scoreboard.digest:
            raise ValueError("expected value does not bind the exact scoreboard")
        reasons: list[ResearchPromotionReason] = []
        if not self.expected_value.available:
            reasons.append(ResearchPromotionReason.EXPECTED_VALUE_UNAVAILABLE)
        if self.scoreboard.attempt_count < self.policy.minimum_attempts:
            reasons.append(ResearchPromotionReason.INSUFFICIENT_ATTEMPTS)
        if self.scoreboard.scoreable_count < self.policy.minimum_scoreable_records:
            reasons.append(ResearchPromotionReason.INSUFFICIENT_SCOREABLE_RECORDS)
        if self.scoreboard.scoreable_rate_bps < self.policy.minimum_scoreable_rate_bps:
            reasons.append(ResearchPromotionReason.INSUFFICIENT_SCOREABLE_RATE)
        if (
            self.scoreboard.execution_success_rate_bps
            < self.policy.minimum_execution_success_rate_bps
        ):
            reasons.append(ResearchPromotionReason.INSUFFICIENT_EXECUTION_SUCCESS_RATE)
        if (
            self.scoreboard.floor_preservation_rate_bps
            < self.policy.minimum_floor_preservation_rate_bps
        ):
            reasons.append(ResearchPromotionReason.INSUFFICIENT_FLOOR_PRESERVATION_RATE)
        if (
            self.scoreboard.cost_upper_bound_respect_rate_bps
            < self.policy.minimum_cost_upper_bound_respect_rate_bps
        ):
            reasons.append(ResearchPromotionReason.INSUFFICIENT_COST_BOUND_RATE)
        if (
            self.scoreboard.positive_historical_surplus_rate_bps
            < self.policy.minimum_positive_surplus_rate_bps
        ):
            reasons.append(ResearchPromotionReason.INSUFFICIENT_POSITIVE_SURPLUS_RATE)
        if (
            self.scoreboard.unique_scoreable_inclusion_block_count
            < self.policy.minimum_unique_scoreable_inclusion_blocks
        ):
            reasons.append(
                ResearchPromotionReason.INSUFFICIENT_UNIQUE_SCOREABLE_BLOCKS
            )
        if (
            self.scoreboard.native_cost_overrun_rate_bps
            > self.policy.maximum_native_cost_overrun_rate_bps
        ):
            reasons.append(ResearchPromotionReason.EXCESSIVE_NATIVE_COST_OVERRUN_RATE)
        if (
            self.scoreboard.mean_absolute_prediction_error_bps_of_capital_ceiling
            > self.policy.maximum_mean_absolute_error_bps_of_capital
        ):
            reasons.append(ResearchPromotionReason.EXCESSIVE_MEAN_ABSOLUTE_ERROR)
        if (
            self.expected_value.guarded_sample_mean_floor
            != self.scoreboard.guarded_mean_historical_surplus_floor
        ):
            raise RuntimeError("expected-value guarded mean drifted from scoreboard")
        if (
            self.scoreboard.guarded_mean_historical_surplus_floor
            < self.policy.minimum_guarded_mean_surplus
        ):
            reasons.append(ResearchPromotionReason.GUARDED_EXPECTED_VALUE_BELOW_FLOOR)
        if any(
            bucket.attempt_count > 0
            and bucket.scoreable_count
            < self.policy.minimum_scoreable_records_per_nonempty_bucket
            for bucket in self.calibration.buckets
        ):
            reasons.append(ResearchPromotionReason.CALIBRATION_BUCKET_UNDERSAMPLED)
        reason_tuple = tuple(reasons)
        identity = {
            "schema": self.schema,
            "scoreboard_sha256": self.scoreboard.digest,
            "source_manifest_sha256": self.scoreboard.corpus.source_manifest.digest,
            "source_completeness_scope": "exact-declared-source-window-reference-set-only",
            "global_completeness_guarantee": False,
            "calibration_sha256": self.calibration.digest,
            "expected_value_sha256": self.expected_value.digest,
            "policy_sha256": self.policy.digest,
            "observed_unique_inclusion_block_count": str(
                self.scoreboard.unique_inclusion_block_count
            ),
            "observed_unique_scoreable_inclusion_block_count": str(
                self.scoreboard.unique_scoreable_inclusion_block_count
            ),
            "inclusion_block_diversity_semantics": (
                "promotion-gate-uses-scoreable-economic-sample-only"
            ),
            "allowed": not reason_tuple,
            "reasons": [item.value for item in reason_tuple],
            "created_at_unix_ms": str(self.created_at_unix_ms),
        }
        object.__setattr__(self, "_allowed", not reason_tuple)
        object.__setattr__(self, "_reasons", reason_tuple)
        object.__setattr__(self, "_decision_id", "research-promotion-" + canonical_sha256(identity))
        canonical_json_bytes(self.to_json_value())

    @property
    def allowed(self) -> bool:
        return self._allowed

    @property
    def reasons(self) -> tuple[ResearchPromotionReason, ...]:
        return self._reasons

    @property
    def decision_id(self) -> str:
        return self._decision_id

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "decision_id": self.decision_id,
            "scoreboard_sha256": self.scoreboard.digest,
            "source_manifest_sha256": self.scoreboard.corpus.source_manifest.digest,
            "source_completeness_scope": "exact-declared-source-window-reference-set-only",
            "global_completeness_guarantee": False,
            "calibration_sha256": self.calibration.digest,
            "expected_value_sha256": self.expected_value.digest,
            "policy": self.policy.to_json_value(),
            "policy_sha256": self.policy.digest,
            "observed_unique_inclusion_block_count": str(
                self.scoreboard.unique_inclusion_block_count
            ),
            "observed_unique_scoreable_inclusion_block_count": str(
                self.scoreboard.unique_scoreable_inclusion_block_count
            ),
            "inclusion_block_diversity_semantics": (
                "promotion-gate-uses-scoreable-economic-sample-only"
            ),
            "allowed": self.allowed,
            "reasons": [item.value for item in self.reasons],
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "promotion_scope": "offline-research-candidate-only",
            "confidence_guarantee": False,
            "production_promotion_authority": False,
            "signing_authority": "none",
            "submission_authority": "none",
            "execution_authority": "none",
            "realized_profit_authority": "none",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())
