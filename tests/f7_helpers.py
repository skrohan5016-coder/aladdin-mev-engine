from __future__ import annotations

from dataclasses import replace
from functools import lru_cache

from aladdin_mev_engine.evm_hex import to_hex_data
from aladdin_mev_engine.evm_receipt import EvmLogEntry, EvmTransactionReceipt, compute_logs_bloom
from aladdin_mev_engine.execution_outcome import (
    AuthenticatedExecutionBlockEvidence,
    AuthenticatedTransactionReceiptInclusionEvidence,
    ExecutionTrieKind,
    ExecutorSettlementEventRegistry,
    ExecutorSettlementEventSpec,
    IndexedTrieProofEvidence,
    RealizedExecutionOutcomeEvidence,
    RecordedExecutionBlockEvidence,
    RecordedRollupFeeEvidence,
)
from aladdin_mev_engine.execution_package import UnsignedExecutionPackageEvidence
from aladdin_mev_engine.keccak import keccak256
from aladdin_mev_engine.mpt import EMPTY_TRIE_ROOT, bytes_to_nibbles, hex_prefix_encode
from aladdin_mev_engine.observation import ObservationEnvelope
from aladdin_mev_engine.relay_evidence import ExternallySignedExecutionPackageEvidence
from aladdin_mev_engine.rlp import rlp_encode, rlp_encode_uint
from aladdin_mev_engine.source_contracts import Finality, ObservationKind, Visibility
from aladdin_mev_engine.state_proof import (
    BLOCK_STATE_PAYLOAD_SCHEMA,
    STATE_PROOF_PAYLOAD_SCHEMA,
    EvmBlockStateAnchor,
    EvmStateProofEvidence,
)

from f6_helpers import f6_package

BLOCK_SOURCE = "c0" * 32
PROOF_SOURCE = "c1" * 32
ROLLUP_FEE_SOURCE = "c2" * 32
SETTLEMENT_SOURCE = "c3" * 32


class IndexedTrie:
    def __init__(self, root_hash: bytes, proofs: dict[int, tuple[bytes, ...]]) -> None:
        self.root_hash = root_hash
        self.proofs = proofs


def indexed_trie(entries: tuple[tuple[int, bytes], ...]) -> IndexedTrie:
    if type(entries) is not tuple or not entries:
        raise TypeError("indexed trie entries must be a non-empty exact tuple")
    keyed = tuple((index, rlp_encode_uint(index), value) for index, value in entries)
    if len(keyed) == 1:
        index, key, value = keyed[0]
        leaf = (hex_prefix_encode(bytes_to_nibbles(key), is_leaf=True), value)
        encoded = rlp_encode(leaf)
        return IndexedTrie(keccak256(encoded), {index: (encoded,)})

    branch: list[object] = [b""] * 17
    encoded_by_index: dict[int, bytes] = {}
    embedded_by_index: dict[int, bool] = {}
    first_nibbles: set[int] = set()
    for index, key, value in keyed:
        nibbles = bytes_to_nibbles(key)
        first = nibbles[0]
        if first in first_nibbles:
            raise ValueError("indexed trie fixture keys collide in their first nibble")
        first_nibbles.add(first)
        leaf = (hex_prefix_encode(nibbles[1:], is_leaf=True), value)
        encoded = rlp_encode(leaf)
        embedded = len(encoded) < 32
        branch[first] = leaf if embedded else keccak256(encoded)
        encoded_by_index[index] = encoded
        embedded_by_index[index] = embedded
    root = rlp_encode(tuple(branch))
    return IndexedTrie(
        keccak256(root),
        {
            index: (root,) if embedded_by_index[index] else (root, encoded_by_index[index])
            for index, _key, _value in keyed
        },
    )


def _uint_bytes(value: int) -> bytes:
    return b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")


def encode_receipt(
    *,
    cumulative_gas_used: int,
    logs: tuple[EvmLogEntry, ...],
    status: int = 1,
    transaction_type: int = 2,
) -> bytes:
    bloom = compute_logs_bloom(logs)
    payload = rlp_encode(
        (
            _uint_bytes(status),
            _uint_bytes(cumulative_gas_used),
            bloom,
            tuple(item.rlp_value for item in logs),
        )
    )
    raw = bytes((transaction_type,)) + payload
    EvmTransactionReceipt.decode(raw)
    return raw


def settlement_log(
    package: ExternallySignedExecutionPackageEvidence,
    *,
    gross_output: int | None = None,
    base_token_residual_before_external_costs: int | None = None,
    direct_inclusion_payment: int | None = None,
) -> EvmLogEntry:
    plan = package.unsigned_package.net_profit_evidence.plan
    tx = package.signed_transaction.unsigned_transaction
    spec = settlement_spec(package)
    actual_output = (
        plan.opportunity.route_quote.amount_out
        if gross_output is None
        else gross_output
    )
    actual_residual = (
        actual_output - plan.funding.principal - plan.funding.fee
        if base_token_residual_before_external_costs is None
        else base_token_residual_before_external_costs
    )
    actual_direct_payment = (
        tx.value if direct_inclusion_payment is None else direct_inclusion_payment
    )
    words = (
        actual_output,
        plan.funding.principal,
        plan.funding.fee,
        actual_residual,
        actual_direct_payment,
    )
    return EvmLogEntry(
        address=tx.call.deployment.address,
        topics=(
            spec.topic0,
            bytes.fromhex(plan.digest),
            bytes(12) + tx.sender,
            bytes(12) + plan.base_asset.address,
        ),
        data=b"".join(item.to_bytes(32, "big") for item in words),
    )


def settlement_spec(
    package: ExternallySignedExecutionPackageEvidence | None = None,
) -> ExecutorSettlementEventSpec:
    package = f6_package() if package is None else package
    deployment = package.unsigned_package.call.deployment.spec
    return ExecutorSettlementEventSpec(
        spec_id="f7-synthetic-settlement-event-v1",
        runtime_code_hash=deployment.runtime_code_hash,
        valid_from_block=deployment.valid_from_block,
        valid_until_block=deployment.valid_until_block,
        implementation_source_sha256=SETTLEMENT_SOURCE,
    )


def package_with_logs(logs: tuple[EvmLogEntry, ...]) -> ExternallySignedExecutionPackageEvidence:
    package = f6_package()
    logs_sha256 = EvmTransactionReceipt(
        transaction_type=2,
        status=1,
        cumulative_gas_used=200_000,
        logs_bloom=compute_logs_bloom(logs),
        logs=logs,
        raw_receipt=encode_receipt(cumulative_gas_used=200_000, logs=logs),
    ).logs_sha256
    simulations = tuple(replace(item, logs_sha256=logs_sha256) for item in package.unsigned_package.simulations)
    unsigned = UnsignedExecutionPackageEvidence(
        net_profit_evidence=package.unsigned_package.net_profit_evidence,
        call=package.unsigned_package.call,
        transaction=package.unsigned_package.transaction,
        bundle=package.unsigned_package.bundle,
        simulations=simulations,
        created_at_unix_ms=package.unsigned_package.created_at_unix_ms,
    )
    return ExternallySignedExecutionPackageEvidence(
        unsigned_package=unsigned,
        signed_transaction=package.signed_transaction,
        signed_bundle=package.signed_bundle,
        relay_request=package.relay_request,
        relay_responses=package.relay_responses,
        created_at_unix_ms=package.created_at_unix_ms,
    )


@lru_cache(maxsize=1)
def f7_package() -> ExternallySignedExecutionPackageEvidence:
    provisional = f6_package()
    return package_with_logs((settlement_log(provisional),))


class InclusionFixture:
    def __init__(
        self,
        *,
        package: ExternallySignedExecutionPackageEvidence,
        authenticated_block: AuthenticatedExecutionBlockEvidence,
        executor_state: EvmStateProofEvidence,
        transaction_proof: IndexedTrieProofEvidence,
        receipt_proof: IndexedTrieProofEvidence,
        previous_receipt_proof: IndexedTrieProofEvidence,
        raw_receipt: bytes,
        previous_raw_receipt: bytes,
    ) -> None:
        self.package = package
        self.authenticated_block = authenticated_block
        self.executor_state = executor_state
        self.transaction_proof = transaction_proof
        self.receipt_proof = receipt_proof
        self.previous_receipt_proof = previous_receipt_proof
        self.raw_receipt = raw_receipt
        self.previous_raw_receipt = previous_raw_receipt


def inclusion_fixture(
    *,
    receipt_status: int = 1,
    settlement_logs: tuple[EvmLogEntry, ...] | None = None,
    target_gas_used: int = 200_000,
    header_logs_bloom: bytes | None = None,
    executor_code_hash: bytes | None = None,
    executor_storage_root: bytes = EMPTY_TRIE_ROOT,
) -> InclusionFixture:
    package = f7_package()
    logs = (settlement_log(package),) if settlement_logs is None else settlement_logs
    previous_raw_receipt = encode_receipt(cumulative_gas_used=50_000, logs=())
    raw_receipt = encode_receipt(
        cumulative_gas_used=50_000 + target_gas_used,
        logs=logs,
        status=receipt_status,
    )
    tx_trie = indexed_trie(((0, b"\xc0"), (1, package.signed_transaction.raw_transaction)))
    receipt_trie = indexed_trie(((0, previous_raw_receipt), (1, raw_receipt)))
    receipt = EvmTransactionReceipt.decode(raw_receipt)
    block_logs_bloom = receipt.logs_bloom if header_logs_bloom is None else header_logs_bloom

    bundle = package.signed_bundle.unsigned_bundle
    block_number = bundle.target_block_number
    parent_hash = bytes.fromhex("d2" * 32)
    deployment = package.unsigned_package.call.deployment
    post_state_code_hash = (
        deployment.spec.runtime_code_hash
        if executor_code_hash is None
        else executor_code_hash
    )
    account_value = rlp_encode(
        (
            _uint_bytes(1),
            b"",
            executor_storage_root,
            post_state_code_hash,
        )
    )
    account_key = keccak256(deployment.address)
    account_leaf = rlp_encode(
        (
            hex_prefix_encode(bytes_to_nibbles(account_key), is_leaf=True),
            account_value,
        )
    )
    state_root = keccak256(account_leaf)
    timestamp = package.unsigned_package.call.deadline_unix_s - 1
    header = (
        parent_hash,
        bytes.fromhex("d4" * 32),
        bytes.fromhex("d5" * 20),
        state_root,
        tx_trie.root_hash,
        receipt_trie.root_hash,
        block_logs_bloom,
        b"",
        _uint_bytes(block_number),
        _uint_bytes(30_000_000),
        _uint_bytes(50_000 + target_gas_used),
        _uint_bytes(timestamp),
        b"",
        bytes.fromhex("d6" * 32),
        bytes(8),
        _uint_bytes(1),
    )
    raw_header = rlp_encode(header)
    block_hash = keccak256(raw_header)
    observed = timestamp * 1000
    source_id = "ethereum-json-rpc"
    head = ObservationEnvelope.create(
        source_id=source_id,
        source_sequence=100,
        source_event_id="f7-execution-head",
        observed_at_unix_ms=observed,
        emitted_at_unix_ms=observed,
        kind=ObservationKind.BLOCK_HEAD,
        finality=Finality.CONFIRMED,
        visibility=Visibility.FULL,
        payload={
            "block_number": str(block_number),
            "block_hash": "0x" + block_hash.hex(),
            "parent_hash": "0x" + parent_hash.hex(),
            "block_timestamp_unix_s": str(timestamp),
        },
    )
    state = ObservationEnvelope.create(
        source_id=source_id,
        source_sequence=101,
        source_event_id="f7-execution-state",
        observed_at_unix_ms=observed + 1,
        emitted_at_unix_ms=observed + 1,
        kind=ObservationKind.EVM_BLOCK_STATE,
        finality=Finality.CONFIRMED,
        visibility=Visibility.FULL,
        payload={
            "schema": BLOCK_STATE_PAYLOAD_SCHEMA,
            "block_number": str(block_number),
            "block_hash": "0x" + block_hash.hex(),
            "state_root": "0x" + state_root.hex(),
        },
    )
    anchor = EvmBlockStateAnchor.from_observations(head, state)
    executor_proof_observation = ObservationEnvelope.create(
        source_id=source_id,
        source_sequence=102,
        source_event_id="f7-executor-post-state-proof",
        observed_at_unix_ms=observed + 2,
        emitted_at_unix_ms=observed + 2,
        kind=ObservationKind.EVM_STATE_PROOF,
        finality=Finality.CONFIRMED,
        visibility=Visibility.FULL,
        payload={
            "schema": STATE_PROOF_PAYLOAD_SCHEMA,
            "block_number": str(block_number),
            "block_hash": to_hex_data(block_hash),
            "state_root": to_hex_data(state_root),
            "address": to_hex_data(deployment.address),
            "nonce": "1",
            "balance": "0",
            "storage_root": to_hex_data(executor_storage_root),
            "code_hash": to_hex_data(post_state_code_hash),
            "account_proof": [to_hex_data(account_leaf)],
            "storage_proofs": [],
        },
    )
    executor_state = EvmStateProofEvidence.verify(
        anchor,
        executor_proof_observation,
    )
    recorded = RecordedExecutionBlockEvidence(
        chain=bundle.chain,
        finality=Finality.CONFIRMED,
        block_number=block_number,
        block_hash=block_hash,
        parent_hash=parent_hash,
        state_root=state_root,
        transactions_root=tx_trie.root_hash,
        receipts_root=receipt_trie.root_hash,
        logs_bloom=block_logs_bloom,
        gas_used=50_000 + target_gas_used,
        base_fee_per_gas=1,
        block_timestamp_unix_s=timestamp,
        observed_at_unix_ms=observed + 2,
        source_id=source_id,
        source_sha256=BLOCK_SOURCE,
        raw_header=raw_header,
    )
    authenticated_block = AuthenticatedExecutionBlockEvidence(anchor, recorded)
    proof_observed = observed + 3
    transaction_proof = IndexedTrieProofEvidence(
        kind=ExecutionTrieKind.TRANSACTION,
        index=1,
        raw_value=package.signed_transaction.raw_transaction,
        proof_nodes=tx_trie.proofs[1],
        observed_at_unix_ms=proof_observed,
        source_id="f7-recorded-transaction-proof",
        source_sha256=PROOF_SOURCE,
    )
    receipt_proof = IndexedTrieProofEvidence(
        kind=ExecutionTrieKind.RECEIPT,
        index=1,
        raw_value=raw_receipt,
        proof_nodes=receipt_trie.proofs[1],
        observed_at_unix_ms=proof_observed,
        source_id="f7-recorded-receipt-proof",
        source_sha256="c4" * 32,
    )
    previous_receipt_proof = IndexedTrieProofEvidence(
        kind=ExecutionTrieKind.PREVIOUS_RECEIPT,
        index=0,
        raw_value=previous_raw_receipt,
        proof_nodes=receipt_trie.proofs[0],
        observed_at_unix_ms=proof_observed,
        source_id="f7-recorded-previous-receipt-proof",
        source_sha256="c5" * 32,
    )
    return InclusionFixture(
        package=package,
        authenticated_block=authenticated_block,
        executor_state=executor_state,
        transaction_proof=transaction_proof,
        receipt_proof=receipt_proof,
        previous_receipt_proof=previous_receipt_proof,
        raw_receipt=raw_receipt,
        previous_raw_receipt=previous_raw_receipt,
    )


@lru_cache(maxsize=1)
def f7_inclusion() -> AuthenticatedTransactionReceiptInclusionEvidence:
    fixture = inclusion_fixture()
    return AuthenticatedTransactionReceiptInclusionEvidence(
        package=fixture.package,
        block=fixture.authenticated_block,
        executor_state=fixture.executor_state,
        transaction_proof=fixture.transaction_proof,
        receipt_proof=fixture.receipt_proof,
        previous_receipt_proof=fixture.previous_receipt_proof,
        created_at_unix_ms=fixture.receipt_proof.observed_at_unix_ms + 1,
    )


@lru_cache(maxsize=1)
def f7_outcome() -> RealizedExecutionOutcomeEvidence:
    inclusion = f7_inclusion()
    package = inclusion.package
    spec = settlement_spec(package)
    registry = ExecutorSettlementEventRegistry(
        registry_id="f7-synthetic-settlement-registry",
        specs=(spec,),
    )
    rollup = RecordedRollupFeeEvidence(
        chain=inclusion.block.chain,
        transaction_hash=package.signed_transaction.transaction_hash,
        l1_data_fee_paid=0,
        operator_fee_paid=0,
        observed_at_unix_ms=inclusion.created_at_unix_ms + 1,
        source_id="f7-recorded-rollup-fees",
        source_sha256=ROLLUP_FEE_SOURCE,
    )
    return RealizedExecutionOutcomeEvidence(
        package=package,
        inclusion=inclusion,
        settlement_registry=registry,
        settlement_spec=spec,
        rollup_fee=rollup,
        created_at_unix_ms=rollup.observed_at_unix_ms + 1,
    )
