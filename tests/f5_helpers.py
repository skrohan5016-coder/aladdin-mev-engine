from __future__ import annotations

from dataclasses import replace
from functools import lru_cache

from aladdin_mev_engine.assets import (
    AssetAmount,
    AssetId,
    ConservativeValuationRate,
    ValuationBook,
)
from aladdin_mev_engine.canonical import canonical_sha256
from aladdin_mev_engine.constant_product import (
    AuthenticatedConstantProductPool,
    ConstantProductModelRegistry,
    ConstantProductPoolSpec,
    PoolUniverse,
)
from aladdin_mev_engine.context_evidence import ChainHealthEvidence, RiskBudgetEvidence
from aladdin_mev_engine.cost_evidence import (
    ConservativeNetProfitEvidence,
    Eip1559CostEnvelope,
    ExecutionCostEnvelope,
    ReserveCostCategory,
    ReserveCostComponent,
    RouteSimulationResult,
)
from aladdin_mev_engine.deployments import (
    AuthenticatedExecutorDeployment,
    ExecutorDeploymentRegistry,
    ExecutorDeploymentSpec,
    ExecutorInterfaceSpec,
)
from aladdin_mev_engine.domain import ChainHealth
from aladdin_mev_engine.evm_abi import ExecutionConstraintPolicy, GovernedExecutorCall
from aladdin_mev_engine.evm_hex import to_hex_data
from aladdin_mev_engine.evm_transaction import (
    PrivateBundleIntent,
    SenderStateEvidence,
    UnsignedEip1559Transaction,
)
from aladdin_mev_engine.execution_package import (
    TransactionSimulationResult,
    UnsignedExecutionPackageEvidence,
)
from aladdin_mev_engine.execution_plan import AtomicExecutionPlan, FundingKind, FundingPlan
from aladdin_mev_engine.keccak import keccak256
from aladdin_mev_engine.mpt import EMPTY_TRIE_ROOT
from aladdin_mev_engine.observation import ObservationEnvelope
from aladdin_mev_engine.opportunity import OpportunitySearchReport
from aladdin_mev_engine.optimizer import OptimizationLimits
from aladdin_mev_engine.profit import ProfitPolicy
from aladdin_mev_engine.risk import RiskLimits
from aladdin_mev_engine.rlp import rlp_encode
from aladdin_mev_engine.source_contracts import Finality, ObservationKind, Visibility
from aladdin_mev_engine.state_proof import (
    BLOCK_STATE_PAYLOAD_SCHEMA,
    EMPTY_CODE_HASH,
    STATE_PROOF_PAYLOAD_SCHEMA,
    EvmBlockStateAnchor,
    EvmStateProofEvidence,
    EvmStateSnapshot,
)

from f3_helpers import (
    TOKEN_A,
    TOKEN_B,
    _head_observation,
    _proof_observation,
    _state_observation,
    branch_trie,
    implementation_spec,
    pool_fixture,
    uint_bytes,
)

SENDER_ADDRESS = bytes.fromhex("2b5ad5c4795c026514f8317c7a215e218dccd6cf")
EXECUTOR_ADDRESS = bytes((11,)) * 20
EXECUTOR_CODE_HASH = keccak256(b"f5-synthetic-executor-runtime-v1")
SENDER_NONCE = 7
SENDER_BALANCE = 10**18
DEPLOYMENT_SOURCE = "10" * 32
INTERFACE_SOURCE = "20" * 32
FUNDING_SOURCE = "30" * 32
FEE_SOURCE = "40" * 32
RESERVE_SOURCE = "50" * 32
HEALTH_SOURCE = "60" * 32
RISK_SOURCE = "70" * 32
ROUTE_ENGINE_A = "80" * 32
ROUTE_ENGINE_B = "81" * 32
ROUTE_ENV = "82" * 32
ROUTE_SOURCE_A = "83" * 32
ROUTE_SOURCE_B = "84" * 32
TX_ENGINE_A = "90" * 32
TX_ENGINE_B = "91" * 32
TX_ENV = "92" * 32
TX_SOURCE_A = "93" * 32
TX_SOURCE_B = "94" * 32
TOKEN_DELTAS = "a0" * 32
LOGS = "a1" * 32
POST_STATE = "a2" * 32


def _account_value(
    *, nonce: int, balance: int, code_hash: bytes, storage_root: bytes = EMPTY_TRIE_ROOT
) -> bytes:
    return rlp_encode(
        (
            uint_bytes(nonce),
            uint_bytes(balance),
            storage_root,
            code_hash,
        )
    )


def _generic_proof_observation(
    *,
    address: bytes,
    nonce: int,
    balance: int,
    code_hash: bytes,
    state_root: bytes,
    account_proof: tuple[bytes, ...],
    anchor: EvmBlockStateAnchor,
    source_sequence: int,
    storage_root: bytes = EMPTY_TRIE_ROOT,
) -> ObservationEnvelope:
    return ObservationEnvelope.create(
        source_id=anchor.source_id,
        source_sequence=source_sequence,
        source_event_id=f"f5-proof-{address.hex()}",
        observed_at_unix_ms=anchor.state_observed_at_unix_ms + source_sequence,
        emitted_at_unix_ms=anchor.state_observed_at_unix_ms + source_sequence,
        kind=ObservationKind.EVM_STATE_PROOF,
        finality=anchor.finality,
        visibility=Visibility.FULL,
        payload={
            "schema": STATE_PROOF_PAYLOAD_SCHEMA,
            "block_number": str(anchor.block_number),
            "block_hash": to_hex_data(anchor.block_hash),
            "state_root": to_hex_data(state_root),
            "address": to_hex_data(address),
            "nonce": str(nonce),
            "balance": str(balance),
            "storage_root": to_hex_data(storage_root),
            "code_hash": to_hex_data(code_hash),
            "account_proof": [to_hex_data(node) for node in account_proof],
            "storage_proofs": [],
        },
    )


@lru_cache(maxsize=1)
def authenticated_f5_state():
    pools = (
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
    accounts = (
        *( (keccak256(item.address), item.account_value) for item in pools ),
        (
            keccak256(SENDER_ADDRESS),
            _account_value(
                nonce=SENDER_NONCE,
                balance=SENDER_BALANCE,
                code_hash=EMPTY_CODE_HASH,
            ),
        ),
        (
            keccak256(EXECUTOR_ADDRESS),
            _account_value(nonce=1, balance=0, code_hash=EXECUTOR_CODE_HASH),
        ),
    )
    material = branch_trie(tuple(accounts))
    block_number = 19_100_005
    block_hash = bytes.fromhex("bc" * 32)
    source_id = "ethereum-json-rpc"
    finality = Finality.CONFIRMED
    head = _head_observation(
        source_id=source_id,
        finality=finality,
        block_number=block_number,
        block_hash=block_hash,
    )
    state = _state_observation(
        source_id=source_id,
        finality=finality,
        block_number=block_number,
        block_hash=block_hash,
        state_root=material.root_hash,
    )
    anchor = EvmBlockStateAnchor.from_observations(head, state)

    pool_evidence = []
    for index, item in enumerate(pools):
        observation = _proof_observation(
            item,
            state_root=material.root_hash,
            account_proof=material.proofs[keccak256(item.address)],
            source_id=source_id,
            finality=finality,
            block_number=block_number,
            block_hash=block_hash,
            source_sequence=12 + index,
        )
        pool_evidence.append(EvmStateProofEvidence.verify(anchor, observation))
    sender_evidence = EvmStateProofEvidence.verify(
        anchor,
        _generic_proof_observation(
            address=SENDER_ADDRESS,
            nonce=SENDER_NONCE,
            balance=SENDER_BALANCE,
            code_hash=EMPTY_CODE_HASH,
            state_root=material.root_hash,
            account_proof=material.proofs[keccak256(SENDER_ADDRESS)],
            anchor=anchor,
            source_sequence=14,
        ),
    )
    executor_evidence = EvmStateProofEvidence.verify(
        anchor,
        _generic_proof_observation(
            address=EXECUTOR_ADDRESS,
            nonce=1,
            balance=0,
            code_hash=EXECUTOR_CODE_HASH,
            state_root=material.root_hash,
            account_proof=material.proofs[keccak256(EXECUTOR_ADDRESS)],
            anchor=anchor,
            source_sequence=15,
        ),
    )
    snapshot = EvmStateSnapshot.create(anchor, tuple(pool_evidence))
    model = implementation_spec()
    registry = ConstantProductModelRegistry(
        registry_id="f5-synthetic-pool-models",
        implementations=(model,),
    )
    authenticated_pools = tuple(
        AuthenticatedConstantProductPool(
            ConstantProductPoolSpec(
                spec_id=f"f5-pool-{index + 1}",
                chain=anchor.chain,
                pool_address=item.address,
                token0=item.token0,
                token1=item.token1,
                implementation=model,
            ),
            evidence,
        )
        for index, (item, evidence) in enumerate(zip(pools, pool_evidence))
    )
    universe = PoolUniverse(snapshot, registry, authenticated_pools)
    return universe, sender_evidence, executor_evidence


def executor_evidence_with_nonempty_storage() -> EvmStateProofEvidence:
    slot = (1).to_bytes(32, "big")
    storage_material = branch_trie(
        ((keccak256(slot), rlp_encode(uint_bytes(1))),)
    )
    account_value = _account_value(
        nonce=1,
        balance=0,
        code_hash=EXECUTOR_CODE_HASH,
        storage_root=storage_material.root_hash,
    )
    state_material = branch_trie(
        ((keccak256(EXECUTOR_ADDRESS), account_value),)
    )
    block_number = 19_100_006
    block_hash = bytes.fromhex("bd" * 32)
    source_id = "ethereum-json-rpc"
    finality = Finality.CONFIRMED
    head = _head_observation(
        source_id=source_id,
        finality=finality,
        block_number=block_number,
        block_hash=block_hash,
    )
    state = _state_observation(
        source_id=source_id,
        finality=finality,
        block_number=block_number,
        block_hash=block_hash,
        state_root=state_material.root_hash,
    )
    anchor = EvmBlockStateAnchor.from_observations(head, state)
    observation = _generic_proof_observation(
        address=EXECUTOR_ADDRESS,
        nonce=1,
        balance=0,
        code_hash=EXECUTOR_CODE_HASH,
        state_root=state_material.root_hash,
        account_proof=state_material.proofs[keccak256(EXECUTOR_ADDRESS)],
        anchor=anchor,
        source_sequence=12,
        storage_root=storage_material.root_hash,
    )
    return EvmStateProofEvidence.verify(anchor, observation)


@lru_cache(maxsize=1)
def f5_net_evidence() -> ConservativeNetProfitEvidence:
    universe, _, _ = authenticated_f5_state()
    report = OpportunitySearchReport(
        universe,
        TOKEN_A,
        4,
        OptimizationLimits(50_000),
        universe.observed_at_unix_ms + 1,
    )
    opportunity = report.opportunities()[0]
    base = AssetId.erc20(universe.chain, TOKEN_A)
    plan_created = opportunity.created_at_unix_ms + 1
    funding = FundingPlan(
        kind=FundingKind.FLASH_LOAN,
        asset=base,
        principal=opportunity.capital_at_risk,
        fee=25,
        provider_id="recorded-lender-f5",
        observed_at_unix_ms=opportunity.created_at_unix_ms,
        valid_until_unix_ms=plan_created + 60_000,
        source_sha256=FUNDING_SOURCE,
    )
    plan = AtomicExecutionPlan(opportunity, funding, plan_created)
    fee_created = plan.created_at_unix_ms + 1
    valid_until = fee_created + 60_000
    native = AssetId.native(universe.chain)
    fee = Eip1559CostEnvelope(
        chain=universe.chain,
        native_asset=native,
        gas_units_upper_bound=250_000,
        max_fee_per_gas=2,
        max_priority_fee_per_gas=1,
        l1_data_fee_upper_bound=0,
        operator_fee_upper_bound=0,
        direct_inclusion_payment_upper_bound=3,
        observed_at_unix_ms=plan.created_at_unix_ms,
        valid_until_unix_ms=valid_until,
        source_sha256=FEE_SOURCE,
    )
    reserves = tuple(
        ReserveCostComponent(
            category=category,
            amount=AssetAmount(base, 1),
            observed_at_unix_ms=plan.created_at_unix_ms,
            valid_until_unix_ms=valid_until,
            source_sha256=RESERVE_SOURCE,
        )
        for category in ReserveCostCategory
    )
    book = ValuationBook(
        (
            ConservativeValuationRate(
                rate_id="f5-native-to-base",
                asset_in=native,
                asset_out=base,
                numerator=1,
                denominator=1_000_000,
                observed_at_unix_ms=plan.created_at_unix_ms,
                valid_until_unix_ms=valid_until,
                source_sha256=FEE_SOURCE,
            ),
        )
    )
    envelope = ExecutionCostEnvelope(
        plan=plan,
        fee_envelope=fee,
        reserve_components=reserves,
        valuation_book=book,
        created_at_unix_ms=fee_created,
    )
    state_reference_sha256 = canonical_sha256(universe.state_reference.to_json_value())
    simulation_observed = plan.created_at_unix_ms + 2
    common = dict(
        environment_sha256=ROUTE_ENV,
        state_reference_sha256=state_reference_sha256,
        success=True,
        opportunity_sha256=opportunity.digest,
        execution_plan_sha256=plan.digest,
        gas_units=200_000,
        output_amount=opportunity.route_quote.amount_out,
        token_deltas_sha256=TOKEN_DELTAS,
        post_state_sha256=POST_STATE,
        observed_at_unix_ms=simulation_observed,
        valid_until_unix_ms=valid_until,
    )
    simulations = (
        RouteSimulationResult(
            engine_id="f5-route-engine-a",
            engine_implementation_sha256=ROUTE_ENGINE_A,
            result_source_sha256=ROUTE_SOURCE_A,
            **common,
        ),
        RouteSimulationResult(
            engine_id="f5-route-engine-b",
            engine_implementation_sha256=ROUTE_ENGINE_B,
            result_source_sha256=ROUTE_SOURCE_B,
            **common,
        ),
    )
    health = ChainHealthEvidence(
        chain=universe.chain,
        health=ChainHealth.HEALTHY,
        observed_at_unix_ms=simulation_observed,
        valid_until_unix_ms=valid_until,
        source_sha256=HEALTH_SOURCE,
    )
    total = envelope.costs.total_cost
    risk = RiskBudgetEvidence(
        risk_policy_id="f5-shadow-risk",
        execution_plan_sha256=plan.digest,
        limits=RiskLimits(
            maximum_daily_loss=total + 10_000,
            maximum_single_execution_cost=total + 10_000,
            maximum_pending_execution_cost=total + 10_000,
            maximum_concurrent_candidates=8,
            maximum_notional=opportunity.capital_at_risk + 10_000,
        ),
        realized_net_profit=0,
        reserved_execution_cost=0,
        concurrent_candidates=0,
        requested_execution_cost=total,
        requested_notional=opportunity.capital_at_risk,
        observed_at_unix_ms=envelope.created_at_unix_ms,
        valid_until_unix_ms=valid_until,
        source_sha256=RISK_SOURCE,
    )
    return ConservativeNetProfitEvidence(
        cost_envelope=envelope,
        simulations=simulations,
        profit_policy=ProfitPolicy(
            policy_id="f5-shadow-profit-policy",
            minimum_absolute_profit=1,
            minimum_return_bps=0,
            maximum_bid_fraction_bps=10_000,
            maximum_state_age_ms=1_000_000,
        ),
        chain_health_evidence=health,
        risk_budget_evidence=risk,
        created_at_unix_ms=envelope.created_at_unix_ms + 3,
    )


def f5_net_evidence_with_fee(
    *,
    gas_units_upper_bound: int,
    max_fee_per_gas: int,
    route_simulation_gas_units: int | None = None,
    valuation_denominator: int = 1_000_000,
) -> ConservativeNetProfitEvidence:
    """Rebuild exact F4 evidence around a governed alternate native-fee envelope."""

    base = f5_net_evidence()
    old_envelope = base.cost_envelope
    old_fee = old_envelope.fee_envelope
    fee = Eip1559CostEnvelope(
        chain=old_fee.chain,
        native_asset=old_fee.native_asset,
        gas_units_upper_bound=gas_units_upper_bound,
        max_fee_per_gas=max_fee_per_gas,
        max_priority_fee_per_gas=min(old_fee.max_priority_fee_per_gas, max_fee_per_gas),
        l1_data_fee_upper_bound=old_fee.l1_data_fee_upper_bound,
        operator_fee_upper_bound=old_fee.operator_fee_upper_bound,
        direct_inclusion_payment_upper_bound=old_fee.direct_inclusion_payment_upper_bound,
        observed_at_unix_ms=old_fee.observed_at_unix_ms,
        valid_until_unix_ms=old_fee.valid_until_unix_ms,
        source_sha256=old_fee.source_sha256,
    )
    base_asset = old_envelope.plan.base_asset
    valuation_book = ValuationBook(
        (
            ConservativeValuationRate(
                rate_id="f5-alternate-native-to-base",
                asset_in=old_fee.native_asset,
                asset_out=base_asset,
                numerator=1,
                denominator=valuation_denominator,
                observed_at_unix_ms=old_fee.observed_at_unix_ms,
                valid_until_unix_ms=old_fee.valid_until_unix_ms,
                source_sha256=old_fee.source_sha256,
            ),
        )
    )
    envelope = ExecutionCostEnvelope(
        plan=old_envelope.plan,
        fee_envelope=fee,
        reserve_components=old_envelope.reserve_components,
        valuation_book=valuation_book,
        created_at_unix_ms=old_envelope.created_at_unix_ms,
    )
    simulated_gas = (
        min(base.simulations[0].gas_units, gas_units_upper_bound)
        if route_simulation_gas_units is None
        else route_simulation_gas_units
    )
    simulations = tuple(
        replace(item, gas_units=simulated_gas) for item in base.simulations
    )
    total = envelope.costs.total_cost
    risk = RiskBudgetEvidence(
        risk_policy_id="f5-alternate-shadow-risk",
        execution_plan_sha256=envelope.plan.digest,
        limits=RiskLimits(
            maximum_daily_loss=total + 100_000,
            maximum_single_execution_cost=total + 100_000,
            maximum_pending_execution_cost=total + 100_000,
            maximum_concurrent_candidates=8,
            maximum_notional=envelope.plan.opportunity.capital_at_risk + 100_000,
        ),
        realized_net_profit=0,
        reserved_execution_cost=0,
        concurrent_candidates=0,
        requested_execution_cost=total,
        requested_notional=envelope.plan.opportunity.capital_at_risk,
        observed_at_unix_ms=envelope.created_at_unix_ms,
        valid_until_unix_ms=base.risk_budget_evidence.valid_until_unix_ms,
        source_sha256=base.risk_budget_evidence.source_sha256,
    )
    return ConservativeNetProfitEvidence(
        cost_envelope=envelope,
        simulations=simulations,
        profit_policy=base.profit_policy,
        chain_health_evidence=base.chain_health_evidence,
        risk_budget_evidence=risk,
        created_at_unix_ms=base.created_at_unix_ms,
    )


@lru_cache(maxsize=1)
def f5_deployment_registry() -> ExecutorDeploymentRegistry:
    evidence = authenticated_f5_state()[2]
    interface = ExecutorInterfaceSpec(
        interface_id="amev-f5-executor-v1",
        interface_source_sha256=INTERFACE_SOURCE,
        flash_loan_provider_id="recorded-lender-f5",
        flash_loan_source_sha256=FUNDING_SOURCE,
    )
    spec = ExecutorDeploymentSpec(
        deployment_id="ethereum-f5-executor-shadow",
        chain=evidence.chain,
        address=EXECUTOR_ADDRESS,
        runtime_code_hash=EXECUTOR_CODE_HASH,
        interface=interface,
        valid_from_block=evidence.block_number,
        valid_until_block=evidence.block_number + 100_000,
        deployment_source_sha256=DEPLOYMENT_SOURCE,
    )
    return ExecutorDeploymentRegistry(
        registry_id="f5-synthetic-executor-deployments",
        deployments=(spec,),
    )


@lru_cache(maxsize=1)
def f5_deployment() -> AuthenticatedExecutorDeployment:
    evidence = authenticated_f5_state()[2]
    registry = f5_deployment_registry()
    spec = registry.resolve(evidence.chain, evidence.address, evidence.block_number)
    return AuthenticatedExecutorDeployment(spec, evidence, registry)


@lru_cache(maxsize=1)
def f5_call() -> GovernedExecutorCall:
    evidence = f5_net_evidence()
    return GovernedExecutorCall(
        net_profit_evidence=evidence,
        deployment=f5_deployment(),
        constraints=ExecutionConstraintPolicy(
            policy_id="f5-call-constraints",
            maximum_slippage_bps=50,
            maximum_deadline_horizon_ms=30_000,
        ),
        created_at_unix_ms=max(
            evidence.created_at_unix_ms + 1,
            f5_deployment().evidence.proof_observed_at_unix_ms,
        ),
    )


@lru_cache(maxsize=1)
def f5_transaction() -> UnsignedEip1559Transaction:
    call = f5_call()
    sender = SenderStateEvidence(authenticated_f5_state()[1])
    return UnsignedEip1559Transaction(
        call=call,
        sender_state=sender,
        created_at_unix_ms=max(
            call.created_at_unix_ms + 1,
            sender.evidence.proof_observed_at_unix_ms,
        ),
    )


@lru_cache(maxsize=1)
def f5_bundle() -> PrivateBundleIntent:
    transaction = f5_transaction()
    anchor_block = transaction.sender_state.evidence.block_number
    return PrivateBundleIntent(
        transactions=(transaction,),
        target_block_number=anchor_block + 1,
        maximum_block_number=anchor_block + 2,
        created_at_unix_ms=transaction.created_at_unix_ms + 1,
    )


def transaction_simulations(*, output_delta: int = 0, gas_delta: int = 0):
    transaction = f5_transaction()
    bundle = f5_bundle()
    evidence = f5_net_evidence()
    observed = bundle.created_at_unix_ms + 1
    common = dict(
        environment_sha256=TX_ENV,
        state_anchor_sha256=transaction.sender_state.anchor_sha256,
        transaction_sha256=transaction.digest,
        transaction_signing_hash=transaction.signing_hash_hex,
        bundle_sha256=bundle.digest,
        simulated_block_number=bundle.target_block_number,
        simulated_block_timestamp_unix_s=bundle.created_at_unix_ms // 1000 + 1,
        simulated_base_fee_per_gas=1,
        success=True,
        gas_used=200_000 + gas_delta,
        operator_fee_paid=0,
        output_amount=evidence.plan.opportunity.route_quote.amount_out + output_delta,
        base_token=evidence.plan.base_asset.address,
        flash_loan_principal_repaid=evidence.plan.funding.principal,
        flash_loan_fee_paid=evidence.plan.funding.fee,
        base_token_residual_before_external_costs=(
            evidence.plan.residual_before_external_costs + output_delta
        ),
        base_token_beneficiary=transaction.sender,
        base_token_beneficiary_delta=(
            evidence.plan.residual_before_external_costs + output_delta
        ),
        token_deltas_sha256=TOKEN_DELTAS,
        logs_sha256=LOGS,
        post_state_sha256=POST_STATE,
        coinbase_payment=transaction.value,
        observed_at_unix_ms=observed,
        valid_until_unix_ms=evidence.inputs_valid_until_unix_ms,
    )
    return (
        TransactionSimulationResult(
            engine_id="f5-transaction-engine-a",
            engine_implementation_sha256=TX_ENGINE_A,
            result_source_sha256=TX_SOURCE_A,
            **common,
        ),
        TransactionSimulationResult(
            engine_id="f5-transaction-engine-b",
            engine_implementation_sha256=TX_ENGINE_B,
            result_source_sha256=TX_SOURCE_B,
            **common,
        ),
    )


@lru_cache(maxsize=1)
def f5_package() -> UnsignedExecutionPackageEvidence:
    bundle = f5_bundle()
    return UnsignedExecutionPackageEvidence(
        net_profit_evidence=f5_net_evidence(),
        call=f5_call(),
        transaction=f5_transaction(),
        bundle=bundle,
        simulations=transaction_simulations(),
        created_at_unix_ms=bundle.created_at_unix_ms + 2,
    )
