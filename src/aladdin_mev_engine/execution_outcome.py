from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib

from .canonical import canonical_json_bytes, canonical_sha256
from .constant_product import MAX_UINT256
from .domain import Chain, require_bounded_text, require_sha256
from .evm_hex import to_hex_data
from .evm_receipt import (
    EIP1559_TRANSACTION_TYPE,
    EvmLogEntry,
    EvmTransactionReceipt,
)
from .head_tracker import EvmHead
from .keccak import keccak256
from .mpt import (
    EMPTY_TRIE_ROOT,
    MAX_PROOF_NODES,
    MAX_PROOF_NODE_BYTES,
    MAX_PROOF_TOTAL_BYTES,
    verify_mpt_proof,
)
from .relay_evidence import ExternallySignedExecutionPackageEvidence
from .rlp import require_rlp_bytes, require_rlp_list, rlp_decode, rlp_decode_uint, rlp_encode_uint
from .source_contracts import Finality
from .state_proof import EMPTY_CODE_HASH, EvmBlockStateAnchor, EvmStateProofEvidence

RECORDED_BLOCK_SCHEMA = "aladdin-mev-recorded-execution-block/v1"
AUTHENTICATED_BLOCK_SCHEMA = "aladdin-mev-authenticated-execution-block/v1"
INDEXED_TRIE_PROOF_SCHEMA = "aladdin-mev-indexed-trie-proof/v1"
INCLUSION_SCHEMA = "aladdin-mev-authenticated-transaction-receipt-inclusion/v1"
SETTLEMENT_SPEC_SCHEMA = "aladdin-mev-executor-settlement-event-spec/v1"
SETTLEMENT_REGISTRY_SCHEMA = "aladdin-mev-executor-settlement-event-registry/v1"
SETTLEMENT_EVENT_SCHEMA = "aladdin-mev-executor-settlement-event/v1"
ROLLUP_FEE_SCHEMA = "aladdin-mev-recorded-rollup-fee/v1"
REALIZED_OUTCOME_SCHEMA = "aladdin-mev-realized-execution-outcome/v1"

SETTLEMENT_EVENT_SIGNATURE = (
    "ExecutionSettled(bytes32,address,address,uint256,uint256,uint256,uint256,uint256)"
)
SETTLEMENT_VALUE_SEMANTICS = (
    "msg-value-unused-balance-is-refunded-to-authenticated-sender"
)
MAX_UINT64 = (1 << 64) - 1
MAX_SETTLEMENT_REGISTRY_SIZE = 32
MAX_TRIE_VALUE_BYTES = 1_048_576


class ExecutionTrieKind(StrEnum):
    TRANSACTION = "transaction"
    RECEIPT = "receipt"
    PREVIOUS_RECEIPT = "previous-receipt"


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


def _hash(name: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 32 or value == bytes(32):
        raise ValueError(f"{name} must be a non-zero exact 32-byte hash")
    return value


def _address(name: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 20 or value == bytes(20):
        raise ValueError(f"{name} must be a non-zero exact 20-byte address")
    return value


def _checked_add(left: int, right: int, name: str) -> int:
    _uint256(f"{name} left", left)
    _uint256(f"{name} right", right)
    if right > MAX_UINT256 - left:
        raise ValueError(f"{name} exceeds uint256")
    return left + right


def _checked_mul(left: int, right: int, name: str) -> int:
    _uint256(f"{name} left", left)
    _uint256(f"{name} right", right)
    if left and right > MAX_UINT256 // left:
        raise ValueError(f"{name} exceeds uint256")
    return left * right


def _topic_address(name: str, value: bytes) -> bytes:
    if type(value) is not bytes or len(value) != 32 or value[:12] != bytes(12):
        raise ValueError(f"{name} must be a canonical indexed EVM address topic")
    return _address(name, value[12:])


@dataclass(frozen=True, slots=True)
class RecordedExecutionBlockEvidence:
    chain: Chain
    finality: Finality
    block_number: int
    block_hash: bytes
    parent_hash: bytes
    state_root: bytes
    transactions_root: bytes
    receipts_root: bytes
    logs_bloom: bytes
    gas_used: int
    base_fee_per_gas: int
    block_timestamp_unix_s: int
    observed_at_unix_ms: int
    source_id: str
    source_sha256: str
    raw_header: bytes
    schema: str = RECORDED_BLOCK_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != RECORDED_BLOCK_SCHEMA:
            raise ValueError("unsupported recorded-execution-block schema")
        if type(self.chain) is not Chain or self.chain not in {Chain.ETHEREUM, Chain.BASE}:
            raise ValueError("F7 execution blocks support Ethereum and Base only")
        if type(self.finality) is not Finality or self.finality not in {
            Finality.CONFIRMED,
            Finality.FINALIZED,
        }:
            raise ValueError("execution block finality must be confirmed or finalized")
        _uint64("block_number", self.block_number)
        _hash("block_hash", self.block_hash)
        _hash("parent_hash", self.parent_hash)
        _hash("state_root", self.state_root)
        _hash("transactions_root", self.transactions_root)
        _hash("receipts_root", self.receipts_root)
        if type(self.logs_bloom) is not bytes or len(self.logs_bloom) != 256:
            raise ValueError("logs_bloom must be exact immutable 256-byte data")
        _uint256("gas_used", self.gas_used, positive=True)
        _uint256("base_fee_per_gas", self.base_fee_per_gas)
        _uint64("block_timestamp_unix_s", self.block_timestamp_unix_s)
        _uint64("observed_at_unix_ms", self.observed_at_unix_ms)
        require_bounded_text("source_id", self.source_id, maximum=128)
        require_sha256("source_sha256", self.source_sha256)
        if type(self.raw_header) is not bytes or not self.raw_header:
            raise ValueError("raw_header must be non-empty exact immutable bytes")
        header = require_rlp_list("execution block header", rlp_decode(self.raw_header))
        if not 16 <= len(header) <= 24:
            raise ValueError("execution block header field count is outside the governed range")
        parent_hash = require_rlp_bytes("header parent hash", header[0])
        state_root = require_rlp_bytes("header state root", header[3])
        transactions_root = require_rlp_bytes("header transactions root", header[4])
        receipts_root = require_rlp_bytes("header receipts root", header[5])
        logs_bloom = require_rlp_bytes("header logs bloom", header[6])
        if len(logs_bloom) != 256:
            raise ValueError("execution block header logs bloom must be exact 256-byte data")
        number = rlp_decode_uint(require_rlp_bytes("header number", header[8]), maximum_bits=64)
        gas_limit = rlp_decode_uint(require_rlp_bytes("header gas limit", header[9]), maximum_bits=256)
        gas_used = rlp_decode_uint(require_rlp_bytes("header gas used", header[10]), maximum_bits=256)
        timestamp = rlp_decode_uint(require_rlp_bytes("header timestamp", header[11]), maximum_bits=64)
        base_fee = rlp_decode_uint(require_rlp_bytes("header base fee", header[15]), maximum_bits=256)
        if gas_used > gas_limit:
            raise ValueError("execution block gas used exceeds the header gas limit")
        if keccak256(self.raw_header) != self.block_hash:
            raise ValueError("recorded execution block hash is not the legacy-Keccak header hash")
        if (
            parent_hash != self.parent_hash
            or state_root != self.state_root
            or transactions_root != self.transactions_root
            or receipts_root != self.receipts_root
            or logs_bloom != self.logs_bloom
            or number != self.block_number
            or gas_used != self.gas_used
            or timestamp != self.block_timestamp_unix_s
            or base_fee != self.base_fee_per_gas
        ):
            raise ValueError("recorded execution block fields disagree with the canonical header")
        canonical_json_bytes(self.to_json_value())

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "chain": self.chain.value,
            "finality": self.finality.value,
            "block_number": str(self.block_number),
            "block_hash": to_hex_data(self.block_hash),
            "parent_hash": to_hex_data(self.parent_hash),
            "state_root": to_hex_data(self.state_root),
            "transactions_root": to_hex_data(self.transactions_root),
            "receipts_root": to_hex_data(self.receipts_root),
            "logs_bloom": to_hex_data(self.logs_bloom),
            "gas_used": str(self.gas_used),
            "base_fee_per_gas": str(self.base_fee_per_gas),
            "block_timestamp_unix_s": str(self.block_timestamp_unix_s),
            "observed_at_unix_ms": str(self.observed_at_unix_ms),
            "source_id": self.source_id,
            "source_sha256": self.source_sha256,
            "raw_header": to_hex_data(self.raw_header),
            "header_sha256": hashlib.sha256(self.raw_header).hexdigest(),
            "network_authority": "recorded-input-only",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class AuthenticatedExecutionBlockEvidence:
    state_anchor: EvmBlockStateAnchor
    block: RecordedExecutionBlockEvidence
    schema: str = AUTHENTICATED_BLOCK_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != AUTHENTICATED_BLOCK_SCHEMA:
            raise ValueError("unsupported authenticated-execution-block schema")
        if type(self.state_anchor) is not EvmBlockStateAnchor:
            raise TypeError("state_anchor must be an exact EvmBlockStateAnchor")
        if type(self.block) is not RecordedExecutionBlockEvidence:
            raise TypeError("block must be exact RecordedExecutionBlockEvidence")
        if self.block.chain is not self.state_anchor.chain:
            raise ValueError("recorded execution block chain disagrees with state anchor")
        if self.block.finality is not self.state_anchor.finality:
            raise ValueError("recorded execution block finality disagrees with state anchor")
        if self.block.source_id != self.state_anchor.source_id:
            raise ValueError("recorded execution block source disagrees with state anchor")
        if self.block.block_number != self.state_anchor.block_number:
            raise ValueError("recorded execution block number disagrees with state anchor")
        if self.block.block_hash != self.state_anchor.block_hash:
            raise ValueError("recorded execution block hash disagrees with state anchor")
        if self.block.state_root != self.state_anchor.state_root:
            raise ValueError("recorded execution state root disagrees with state anchor")
        head = EvmHead.from_observation(self.state_anchor.head_observation)
        if self.block.parent_hash != bytes.fromhex(head.parent_hash[2:]):
            raise ValueError("recorded execution parent hash disagrees with block head")
        if self.block.block_timestamp_unix_s != head.block_timestamp_unix_s:
            raise ValueError("recorded execution timestamp disagrees with block head")
        if self.block.observed_at_unix_ms < self.state_anchor.state_observed_at_unix_ms:
            raise ValueError("recorded execution block predates its authenticated state anchor")
        canonical_json_bytes(self.to_json_value())

    @property
    def chain(self) -> Chain:
        return self.block.chain

    @property
    def block_number(self) -> int:
        return self.block.block_number

    @property
    def block_hash(self) -> bytes:
        return self.block.block_hash

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "state_anchor": self.state_anchor.to_json_value(),
            "state_anchor_sha256": self.state_anchor.digest,
            "block": self.block.to_json_value(),
            "block_sha256": self.block.digest,
            "authentication_authority": "state-root-and-recorded-header-cross-check-only",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class IndexedTrieProofEvidence:
    kind: ExecutionTrieKind
    index: int
    raw_value: bytes
    proof_nodes: tuple[bytes, ...]
    observed_at_unix_ms: int
    source_id: str
    source_sha256: str
    schema: str = INDEXED_TRIE_PROOF_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != INDEXED_TRIE_PROOF_SCHEMA:
            raise ValueError("unsupported indexed-trie-proof schema")
        if type(self.kind) is not ExecutionTrieKind:
            raise TypeError("kind must be an exact ExecutionTrieKind")
        _uint64("index", self.index)
        if type(self.raw_value) is not bytes or not self.raw_value:
            raise ValueError("raw_value must be non-empty exact immutable bytes")
        if len(self.raw_value) > MAX_TRIE_VALUE_BYTES:
            raise ValueError("raw_value exceeds the governed byte ceiling")
        if type(self.proof_nodes) is not tuple or not self.proof_nodes:
            raise TypeError("proof_nodes must be a non-empty exact tuple")
        if len(self.proof_nodes) > MAX_PROOF_NODES:
            raise ValueError("proof node count exceeds the governed ceiling")
        if any(
            type(node) is not bytes or not node or len(node) > MAX_PROOF_NODE_BYTES
            for node in self.proof_nodes
        ):
            raise ValueError("proof_nodes contain an empty, oversized, or non-bytes value")
        if sum(len(node) for node in self.proof_nodes) > MAX_PROOF_TOTAL_BYTES:
            raise ValueError("proof_nodes exceed the governed byte ceiling")
        _uint64("observed_at_unix_ms", self.observed_at_unix_ms)
        require_bounded_text("source_id", self.source_id, maximum=128)
        require_sha256("source_sha256", self.source_sha256)
        canonical_json_bytes(self.to_json_value())

    @property
    def trie_key(self) -> bytes:
        return rlp_encode_uint(self.index)

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "kind": self.kind.value,
            "index": str(self.index),
            "trie_key": to_hex_data(self.trie_key),
            "raw_value": to_hex_data(self.raw_value),
            "proof": [to_hex_data(node) for node in self.proof_nodes],
            "observed_at_unix_ms": str(self.observed_at_unix_ms),
            "source_id": self.source_id,
            "source_sha256": self.source_sha256,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class AuthenticatedTransactionReceiptInclusionEvidence:
    package: ExternallySignedExecutionPackageEvidence
    block: AuthenticatedExecutionBlockEvidence
    executor_state: EvmStateProofEvidence
    transaction_proof: IndexedTrieProofEvidence
    receipt_proof: IndexedTrieProofEvidence
    previous_receipt_proof: IndexedTrieProofEvidence | None
    created_at_unix_ms: int
    schema: str = INCLUSION_SCHEMA
    _receipt: EvmTransactionReceipt = field(init=False, repr=False)
    _previous_receipt: EvmTransactionReceipt | None = field(init=False, repr=False)
    _gas_used: int = field(init=False, repr=False)
    _effective_gas_price: int = field(init=False, repr=False)
    _execution_gas_cost: int = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != INCLUSION_SCHEMA:
            raise ValueError("unsupported authenticated-inclusion schema")
        if type(self.package) is not ExternallySignedExecutionPackageEvidence:
            raise TypeError("package must be exact ExternallySignedExecutionPackageEvidence")
        if type(self.block) is not AuthenticatedExecutionBlockEvidence:
            raise TypeError("block must be exact AuthenticatedExecutionBlockEvidence")
        if type(self.executor_state) is not EvmStateProofEvidence:
            raise TypeError("executor_state must be exact EvmStateProofEvidence")
        if type(self.transaction_proof) is not IndexedTrieProofEvidence:
            raise TypeError("transaction_proof must be exact IndexedTrieProofEvidence")
        if type(self.receipt_proof) is not IndexedTrieProofEvidence:
            raise TypeError("receipt_proof must be exact IndexedTrieProofEvidence")
        if self.previous_receipt_proof is not None and type(self.previous_receipt_proof) is not IndexedTrieProofEvidence:
            raise TypeError("previous_receipt_proof must be exact IndexedTrieProofEvidence or null")
        _uint64("created_at_unix_ms", self.created_at_unix_ms)
        if self.package.signed_bundle.unsigned_bundle.chain is not self.block.chain:
            raise ValueError("signed package chain disagrees with inclusion block")
        deployment = self.package.unsigned_package.call.deployment
        if self.executor_state.anchor.digest != self.block.state_anchor.digest:
            raise ValueError("executor post-state proof does not bind the exact inclusion block")
        if not self.executor_state.account_exists:
            raise ValueError("executor account must exist in authenticated inclusion post-state")
        if self.executor_state.address != deployment.address:
            raise ValueError("executor post-state proof address disagrees with deployment")
        if self.executor_state.code_hash != deployment.spec.runtime_code_hash:
            raise ValueError("executor runtime code hash changed at the inclusion block")
        if self.executor_state.storage_root != EMPTY_TRIE_ROOT:
            raise ValueError("executor storage root changed at the inclusion block")
        if self.executor_state.storage_values:
            raise ValueError("executor post-state proof must not carry unused storage proofs")
        if not deployment.spec.is_valid_at_block(self.block.block_number):
            raise ValueError("executor deployment is not governed at the inclusion block")
        if self.executor_state.proof_observed_at_unix_ms < self.block.block.observed_at_unix_ms:
            raise ValueError("executor post-state proof predates the recorded execution block")
        if self.created_at_unix_ms < self.executor_state.proof_observed_at_unix_ms:
            raise ValueError("inclusion evidence predates the executor post-state proof")
        bundle = self.package.signed_bundle.unsigned_bundle
        if not bundle.target_block_number <= self.block.block_number <= bundle.maximum_block_number:
            raise ValueError("inclusion block lies outside the exact signed-bundle range")
        if self.block.block.block_timestamp_unix_s > self.package.unsigned_package.call.deadline_unix_s:
            raise ValueError("inclusion block timestamp exceeds the executor deadline")
        if self.transaction_proof.kind is not ExecutionTrieKind.TRANSACTION:
            raise ValueError("transaction_proof has the wrong trie kind")
        if self.receipt_proof.kind is not ExecutionTrieKind.RECEIPT:
            raise ValueError("receipt_proof has the wrong trie kind")
        if self.transaction_proof.index != self.receipt_proof.index:
            raise ValueError("transaction and receipt proof indices disagree")
        for proof in (self.transaction_proof, self.receipt_proof):
            if proof.observed_at_unix_ms < self.block.block.observed_at_unix_ms:
                raise ValueError("trie proof predates the recorded execution block")
            if self.created_at_unix_ms < proof.observed_at_unix_ms:
                raise ValueError("inclusion evidence predates a bound trie proof")
        expected_transaction = self.package.signed_transaction.raw_transaction
        if self.transaction_proof.raw_value != expected_transaction:
            raise ValueError("transaction proof raw value is not the exact F6 signed transaction")
        transaction_result = verify_mpt_proof(
            root_hash=self.block.block.transactions_root,
            key=self.transaction_proof.trie_key,
            proof_nodes=self.transaction_proof.proof_nodes,
        )
        if not transaction_result.found or transaction_result.value != expected_transaction:
            raise ValueError("transaction proof does not authenticate the exact signed transaction")
        if keccak256(expected_transaction) != self.package.signed_transaction.transaction_hash:
            raise ValueError("authenticated transaction bytes disagree with the F6 transaction hash")
        receipt_result = verify_mpt_proof(
            root_hash=self.block.block.receipts_root,
            key=self.receipt_proof.trie_key,
            proof_nodes=self.receipt_proof.proof_nodes,
        )
        if not receipt_result.found or receipt_result.value != self.receipt_proof.raw_value:
            raise ValueError("receipt proof does not authenticate its exact raw receipt")
        receipt = EvmTransactionReceipt.decode(self.receipt_proof.raw_value)
        if receipt.transaction_type != EIP1559_TRANSACTION_TYPE:
            raise ValueError("F7 target receipt type does not match the exact F6 type-2 transaction")
        if any(
            receipt_byte & block_byte != receipt_byte
            for receipt_byte, block_byte in zip(
                receipt.logs_bloom,
                self.block.block.logs_bloom,
            )
        ):
            raise ValueError("receipt logs bloom is not a subset of the authenticated block bloom")

        if self.receipt_proof.index == 0:
            if self.previous_receipt_proof is not None:
                raise ValueError("transaction index zero cannot carry a previous receipt proof")
            previous = None
            gas_used = receipt.cumulative_gas_used
        else:
            previous_proof = self.previous_receipt_proof
            if previous_proof is None:
                raise ValueError("non-zero transaction index requires a previous receipt proof")
            if previous_proof.kind is not ExecutionTrieKind.PREVIOUS_RECEIPT:
                raise ValueError("previous receipt proof has the wrong trie kind")
            if previous_proof.index != self.receipt_proof.index - 1:
                raise ValueError("previous receipt proof index is not immediately preceding")
            if previous_proof.observed_at_unix_ms < self.block.block.observed_at_unix_ms:
                raise ValueError("previous receipt proof predates the recorded execution block")
            if self.created_at_unix_ms < previous_proof.observed_at_unix_ms:
                raise ValueError("inclusion evidence predates its previous receipt proof")
            previous_result = verify_mpt_proof(
                root_hash=self.block.block.receipts_root,
                key=previous_proof.trie_key,
                proof_nodes=previous_proof.proof_nodes,
            )
            if not previous_result.found or previous_result.value != previous_proof.raw_value:
                raise ValueError("previous receipt proof does not authenticate its exact value")
            previous = EvmTransactionReceipt.decode(previous_proof.raw_value)
            if receipt.cumulative_gas_used <= previous.cumulative_gas_used:
                raise ValueError("receipt cumulative gas does not strictly follow the previous receipt")
            gas_used = receipt.cumulative_gas_used - previous.cumulative_gas_used
        _uint256("transaction gas_used", gas_used, positive=True)
        if receipt.cumulative_gas_used > self.block.block.gas_used:
            raise ValueError("receipt cumulative gas exceeds the authenticated block gas used")
        unsigned = self.package.signed_transaction.unsigned_transaction
        if gas_used < unsigned.intrinsic_gas:
            raise ValueError("authenticated transaction gas is below canonical intrinsic gas")
        if gas_used > unsigned.gas_limit:
            raise ValueError("authenticated transaction gas exceeds its exact gas limit")
        base_fee = self.block.block.base_fee_per_gas
        if base_fee > unsigned.max_fee_per_gas:
            raise ValueError("authenticated block base fee exceeds the transaction max fee")
        priority = min(
            unsigned.max_priority_fee_per_gas,
            unsigned.max_fee_per_gas - base_fee,
        )
        effective_gas_price = _checked_add(base_fee, priority, "effective gas price")
        execution_gas_cost = _checked_mul(gas_used, effective_gas_price, "execution gas cost")
        object.__setattr__(self, "_receipt", receipt)
        object.__setattr__(self, "_previous_receipt", previous)
        object.__setattr__(self, "_gas_used", gas_used)
        object.__setattr__(self, "_effective_gas_price", effective_gas_price)
        object.__setattr__(self, "_execution_gas_cost", execution_gas_cost)
        canonical_json_bytes(self.to_json_value())

    @property
    def transaction_index(self) -> int:
        return self.receipt_proof.index

    @property
    def receipt(self) -> EvmTransactionReceipt:
        return self._receipt

    @property
    def previous_receipt(self) -> EvmTransactionReceipt | None:
        return self._previous_receipt

    @property
    def gas_used(self) -> int:
        return self._gas_used

    @property
    def effective_gas_price(self) -> int:
        return self._effective_gas_price

    @property
    def execution_gas_cost(self) -> int:
        return self._execution_gas_cost

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "package_sha256": self.package.digest,
            "block": self.block.to_json_value(),
            "block_sha256": self.block.digest,
            "executor_state": self.executor_state.to_json_value(),
            "executor_state_sha256": self.executor_state.digest,
            "transaction_proof": self.transaction_proof.to_json_value(),
            "transaction_proof_sha256": self.transaction_proof.digest,
            "receipt_proof": self.receipt_proof.to_json_value(),
            "receipt_proof_sha256": self.receipt_proof.digest,
            "previous_receipt_proof": (
                None
                if self.previous_receipt_proof is None
                else self.previous_receipt_proof.to_json_value()
            ),
            "previous_receipt_proof_sha256": (
                None
                if self.previous_receipt_proof is None
                else self.previous_receipt_proof.digest
            ),
            "transaction_hash": self.package.signed_transaction.transaction_hash_hex,
            "transaction_index": str(self.transaction_index),
            "receipt": self.receipt.to_json_value(),
            "receipt_sha256": self.receipt.digest,
            "gas_used": str(self.gas_used),
            "effective_gas_price": str(self.effective_gas_price),
            "execution_gas_cost": str(self.execution_gas_cost),
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "inclusion_authority": "authenticated-transaction-receipt-and-executor-post-state-inclusion",
            "inclusion_observed": True,
            "execution_success": self.receipt.success,
            "submission_authority": "none",
            "execution_authority": "none",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class ExecutorSettlementEventSpec:
    spec_id: str
    runtime_code_hash: bytes
    valid_from_block: int
    valid_until_block: int
    implementation_source_sha256: str
    event_signature: str = SETTLEMENT_EVENT_SIGNATURE
    value_semantics: str = SETTLEMENT_VALUE_SEMANTICS
    schema: str = SETTLEMENT_SPEC_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SETTLEMENT_SPEC_SCHEMA:
            raise ValueError("unsupported settlement-event-spec schema")
        require_bounded_text("spec_id", self.spec_id, maximum=128)
        _hash("runtime_code_hash", self.runtime_code_hash)
        if self.runtime_code_hash == EMPTY_CODE_HASH:
            raise ValueError("settlement event model cannot bind the canonical empty-code hash")
        _uint64("valid_from_block", self.valid_from_block)
        _uint64("valid_until_block", self.valid_until_block)
        if self.valid_until_block < self.valid_from_block:
            raise ValueError("settlement spec validity cannot end before it begins")
        require_sha256("implementation_source_sha256", self.implementation_source_sha256)
        if self.event_signature != SETTLEMENT_EVENT_SIGNATURE:
            raise ValueError("settlement event signature is not the exact governed signature")
        if self.value_semantics != SETTLEMENT_VALUE_SEMANTICS:
            raise ValueError("settlement value semantics are not the exact governed semantics")
        canonical_json_bytes(self.to_json_value())

    @property
    def topic0(self) -> bytes:
        return keccak256(self.event_signature.encode("ascii"))

    def is_valid_at_block(self, block_number: int) -> bool:
        _uint64("block_number", block_number)
        return self.valid_from_block <= block_number <= self.valid_until_block

    def decode(self, log: EvmLogEntry) -> ExecutorSettlementEvent:
        if type(log) is not EvmLogEntry:
            raise TypeError("log must be an exact EvmLogEntry")
        if len(log.topics) != 4 or log.topics[0] != self.topic0:
            raise ValueError("log does not match the exact settlement-event topic contract")
        if len(log.data) != 5 * 32:
            raise ValueError("settlement-event data must contain exactly five ABI words")
        plan_sha256 = log.topics[1].hex()
        require_sha256("settlement plan_sha256", plan_sha256)
        beneficiary = _topic_address("settlement beneficiary", log.topics[2])
        base_token = _topic_address("settlement base token", log.topics[3])
        values = tuple(
            int.from_bytes(log.data[index : index + 32], "big")
            for index in range(0, len(log.data), 32)
        )
        return ExecutorSettlementEvent(
            spec_sha256=self.digest,
            log=log,
            plan_sha256=plan_sha256,
            beneficiary=beneficiary,
            base_token=base_token,
            gross_output=values[0],
            principal_repaid=values[1],
            flash_loan_fee_paid=values[2],
            base_token_residual_before_external_costs=values[3],
            direct_inclusion_payment=values[4],
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "spec_id": self.spec_id,
            "runtime_code_hash": to_hex_data(self.runtime_code_hash),
            "event_signature": self.event_signature,
            "value_semantics": self.value_semantics,
            "topic0": to_hex_data(self.topic0),
            "indexed_fields": ["execution_plan_sha256", "beneficiary", "base_token"],
            "data_fields": [
                "gross_output",
                "principal_repaid",
                "flash_loan_fee_paid",
                "base_token_residual_before_external_costs",
                "direct_inclusion_payment",
            ],
            "valid_from_block": str(self.valid_from_block),
            "valid_until_block": str(self.valid_until_block),
            "implementation_source_sha256": self.implementation_source_sha256,
            "authority": "recorded-runtime-event-model-only",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class ExecutorSettlementEventRegistry:
    registry_id: str
    specs: tuple[ExecutorSettlementEventSpec, ...]
    schema: str = SETTLEMENT_REGISTRY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SETTLEMENT_REGISTRY_SCHEMA:
            raise ValueError("unsupported settlement-event-registry schema")
        require_bounded_text("registry_id", self.registry_id, maximum=128)
        if type(self.specs) is not tuple or not self.specs:
            raise TypeError("specs must be a non-empty exact tuple")
        if len(self.specs) > MAX_SETTLEMENT_REGISTRY_SIZE:
            raise ValueError("settlement registry exceeds the governed ceiling")
        if any(type(item) is not ExecutorSettlementEventSpec for item in self.specs):
            raise TypeError("settlement registry contains an ungoverned spec")
        ordered = tuple(
            sorted(
                self.specs,
                key=lambda item: (
                    item.runtime_code_hash,
                    item.valid_from_block,
                    item.spec_id,
                    item.digest,
                ),
            )
        )
        object.__setattr__(self, "specs", ordered)
        ids = [item.spec_id for item in ordered]
        if len(ids) != len(set(ids)):
            raise ValueError("settlement registry contains duplicate spec_id")
        for index, left in enumerate(ordered):
            for right in ordered[index + 1 :]:
                if left.runtime_code_hash != right.runtime_code_hash:
                    continue
                if max(left.valid_from_block, right.valid_from_block) <= min(
                    left.valid_until_block,
                    right.valid_until_block,
                ):
                    raise ValueError("one runtime code hash has overlapping settlement-event authority")
        canonical_json_bytes(self.to_json_value())

    def resolve(self, runtime_code_hash: bytes, block_number: int) -> ExecutorSettlementEventSpec:
        _hash("runtime_code_hash", runtime_code_hash)
        _uint64("block_number", block_number)
        matches = [
            item
            for item in self.specs
            if item.runtime_code_hash == runtime_code_hash
            and item.is_valid_at_block(block_number)
        ]
        if len(matches) != 1:
            raise ValueError("settlement registry does not resolve exactly one event spec")
        return matches[0]

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "registry_id": self.registry_id,
            "specs": [item.to_json_value() for item in self.specs],
            "spec_sha256": [item.digest for item in self.specs],
            "production_approval": False,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class ExecutorSettlementEvent:
    spec_sha256: str
    log: EvmLogEntry
    plan_sha256: str
    beneficiary: bytes
    base_token: bytes
    gross_output: int
    principal_repaid: int
    flash_loan_fee_paid: int
    base_token_residual_before_external_costs: int
    direct_inclusion_payment: int
    schema: str = SETTLEMENT_EVENT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SETTLEMENT_EVENT_SCHEMA:
            raise ValueError("unsupported executor-settlement-event schema")
        require_sha256("spec_sha256", self.spec_sha256)
        if type(self.log) is not EvmLogEntry:
            raise TypeError("log must be an exact EvmLogEntry")
        require_sha256("plan_sha256", self.plan_sha256)
        _address("beneficiary", self.beneficiary)
        _address("base_token", self.base_token)
        for name in (
            "gross_output",
            "principal_repaid",
            "flash_loan_fee_paid",
            "base_token_residual_before_external_costs",
            "direct_inclusion_payment",
        ):
            _uint256(name, getattr(self, name))
        repayment = _checked_add(
            self.principal_repaid,
            self.flash_loan_fee_paid,
            "event repayment",
        )
        if self.gross_output < repayment:
            raise ValueError("settlement gross output cannot cover principal and fee")
        if self.base_token_residual_before_external_costs != self.gross_output - repayment:
            raise ValueError("settlement residual does not reconcile")
        if len(self.log.topics) != 4:
            raise ValueError("settlement log must contain exactly four topics")
        expected_topic0 = keccak256(SETTLEMENT_EVENT_SIGNATURE.encode("ascii"))
        if self.log.topics[0] != expected_topic0:
            raise ValueError("settlement log topic0 is not the exact governed event signature")
        if self.log.topics[1] != bytes.fromhex(self.plan_sha256):
            raise ValueError("settlement log plan topic does not match the decoded plan")
        if _topic_address("settlement log beneficiary", self.log.topics[2]) != self.beneficiary:
            raise ValueError("settlement log beneficiary topic does not match the decoded beneficiary")
        if _topic_address("settlement log base token", self.log.topics[3]) != self.base_token:
            raise ValueError("settlement log base-token topic does not match the decoded base token")
        expected_data = b"".join(
            item.to_bytes(32, "big")
            for item in (
                self.gross_output,
                self.principal_repaid,
                self.flash_loan_fee_paid,
                self.base_token_residual_before_external_costs,
                self.direct_inclusion_payment,
            )
        )
        if self.log.data != expected_data:
            raise ValueError("settlement log data does not match the decoded settlement values")
        canonical_json_bytes(self.to_json_value())

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "spec_sha256": self.spec_sha256,
            "log": self.log.to_json_value(),
            "log_sha256": self.log.digest,
            "plan_sha256": self.plan_sha256,
            "beneficiary": to_hex_data(self.beneficiary),
            "base_token": to_hex_data(self.base_token),
            "gross_output": str(self.gross_output),
            "principal_repaid": str(self.principal_repaid),
            "flash_loan_fee_paid": str(self.flash_loan_fee_paid),
            "base_token_residual_before_external_costs": str(
                self.base_token_residual_before_external_costs
            ),
            "direct_inclusion_payment": str(self.direct_inclusion_payment),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class RecordedRollupFeeEvidence:
    chain: Chain
    transaction_hash: bytes
    l1_data_fee_paid: int
    operator_fee_paid: int
    observed_at_unix_ms: int
    source_id: str
    source_sha256: str
    schema: str = ROLLUP_FEE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != ROLLUP_FEE_SCHEMA:
            raise ValueError("unsupported recorded-rollup-fee schema")
        if type(self.chain) is not Chain or self.chain not in {Chain.ETHEREUM, Chain.BASE}:
            raise ValueError("recorded rollup fees support Ethereum and Base only")
        _hash("transaction_hash", self.transaction_hash)
        _uint256("l1_data_fee_paid", self.l1_data_fee_paid)
        _uint256("operator_fee_paid", self.operator_fee_paid)
        if self.chain is Chain.ETHEREUM and (
            self.l1_data_fee_paid != 0 or self.operator_fee_paid != 0
        ):
            raise ValueError("Ethereum cannot carry OP Stack L1 or operator fees")
        _uint64("observed_at_unix_ms", self.observed_at_unix_ms)
        require_bounded_text("source_id", self.source_id, maximum=128)
        require_sha256("source_sha256", self.source_sha256)
        canonical_json_bytes(self.to_json_value())

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "chain": self.chain.value,
            "transaction_hash": to_hex_data(self.transaction_hash),
            "l1_data_fee_paid": str(self.l1_data_fee_paid),
            "operator_fee_paid": str(self.operator_fee_paid),
            "observed_at_unix_ms": str(self.observed_at_unix_ms),
            "source_id": self.source_id,
            "source_sha256": self.source_sha256,
            "fee_authority": "recorded-input-only",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class RealizedExecutionOutcomeEvidence:
    package: ExternallySignedExecutionPackageEvidence
    inclusion: AuthenticatedTransactionReceiptInclusionEvidence
    settlement_registry: ExecutorSettlementEventRegistry
    settlement_spec: ExecutorSettlementEventSpec
    rollup_fee: RecordedRollupFeeEvidence
    created_at_unix_ms: int
    schema: str = REALIZED_OUTCOME_SCHEMA
    _settlement_event: ExecutorSettlementEvent = field(init=False, repr=False)
    _actual_native_cost: int = field(init=False, repr=False)
    _native_cost_upper_bound: int = field(init=False, repr=False)
    _native_cost_overrun: int = field(init=False, repr=False)
    _base_token_residual_shortfall_before_external_costs: int = field(
        init=False, repr=False
    )
    _simulation_gas_match: bool = field(init=False, repr=False)
    _simulation_logs_match: bool = field(init=False, repr=False)
    _simulation_output_match: bool = field(init=False, repr=False)
    _simulation_residual_match: bool = field(init=False, repr=False)
    _simulation_direct_payment_match: bool = field(init=False, repr=False)
    _cost_upper_bounds_respected: bool = field(init=False, repr=False)
    _conservative_shadow_floor_preserved: bool = field(init=False, repr=False)
    _outcome_id: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != REALIZED_OUTCOME_SCHEMA:
            raise ValueError("unsupported realized-execution-outcome schema")
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
        _uint64("created_at_unix_ms", self.created_at_unix_ms)
        if self.inclusion.package.digest != self.package.digest:
            raise ValueError("inclusion evidence does not bind the exact F6 package")
        if not self.inclusion.receipt.success:
            raise ValueError("realized settlement requires a successful authenticated receipt")
        if self.created_at_unix_ms < self.inclusion.created_at_unix_ms:
            raise ValueError("realized outcome cannot predate authenticated inclusion")
        if self.rollup_fee.chain is not self.inclusion.block.chain:
            raise ValueError("rollup fee chain disagrees with the authenticated inclusion")
        if self.rollup_fee.transaction_hash != self.package.signed_transaction.transaction_hash:
            raise ValueError("rollup fee evidence does not bind the exact transaction hash")
        if self.rollup_fee.observed_at_unix_ms < self.inclusion.block.block.observed_at_unix_ms:
            raise ValueError("rollup fee evidence predates the included execution block")
        if self.created_at_unix_ms < self.rollup_fee.observed_at_unix_ms:
            raise ValueError("realized outcome predates rollup fee evidence")

        deployment = self.package.unsigned_package.call.deployment
        runtime_code_hash = deployment.spec.runtime_code_hash
        resolved = self.settlement_registry.resolve(
            runtime_code_hash,
            self.inclusion.block.block_number,
        )
        if resolved.digest != self.settlement_spec.digest:
            raise ValueError("settlement spec is not the exact registry authority")
        if self.settlement_spec.runtime_code_hash != runtime_code_hash:
            raise ValueError("settlement spec runtime code hash disagrees with deployment")
        if not deployment.spec.is_valid_at_block(self.inclusion.block.block_number):
            raise ValueError("executor deployment is not governed at the inclusion block")
        candidates = [
            item
            for item in self.inclusion.receipt.logs
            if item.address == deployment.address
            and len(item.topics) == 4
            and item.topics[0] == self.settlement_spec.topic0
        ]
        if len(candidates) != 1:
            raise ValueError("receipt must contain exactly one governed executor settlement event")
        event = self.settlement_spec.decode(candidates[0])
        plan = self.package.unsigned_package.net_profit_evidence.plan
        transaction = self.package.signed_transaction.unsigned_transaction
        if event.plan_sha256 != plan.digest:
            raise ValueError("settlement event does not bind the exact execution plan")
        if event.beneficiary != transaction.sender:
            raise ValueError("settlement beneficiary is not the authenticated transaction sender")
        if plan.base_asset.address is None or event.base_token != plan.base_asset.address:
            raise ValueError("settlement base token is not the exact F4 base asset")
        if event.principal_repaid != plan.funding.principal:
            raise ValueError("settlement principal repayment disagrees with F4 funding")
        if event.flash_loan_fee_paid != plan.funding.fee:
            raise ValueError("settlement flash fee disagrees with F4 funding")
        if event.gross_output < self.package.unsigned_package.call.minimum_final_output:
            raise ValueError("settlement output violates the governed minimum final output")
        if event.direct_inclusion_payment > transaction.value:
            raise ValueError("settlement direct payment exceeds the unsigned transaction value")

        fee_envelope = self.package.unsigned_package.net_profit_evidence.cost_envelope.fee_envelope
        actual_native_cost = self.inclusion.execution_gas_cost
        actual_native_cost = _checked_add(
            actual_native_cost,
            self.rollup_fee.l1_data_fee_paid,
            "actual native cost",
        )
        actual_native_cost = _checked_add(
            actual_native_cost,
            self.rollup_fee.operator_fee_paid,
            "actual native cost",
        )
        actual_native_cost = _checked_add(
            actual_native_cost,
            event.direct_inclusion_payment,
            "actual native cost",
        )
        native_cost_upper_bound = fee_envelope.total_native_upper_bound
        native_cost_overrun = max(actual_native_cost - native_cost_upper_bound, 0)
        residual_shortfall = max(
            plan.residual_before_external_costs
            - event.base_token_residual_before_external_costs,
            0,
        )
        cost_upper_bounds_respected = (
            self.inclusion.execution_gas_cost
            <= fee_envelope.execution_gas_cost_upper_bound
            and self.rollup_fee.l1_data_fee_paid
            <= fee_envelope.l1_data_fee_upper_bound
            and self.rollup_fee.operator_fee_paid
            <= fee_envelope.operator_fee_upper_bound
            and event.direct_inclusion_payment
            <= fee_envelope.direct_inclusion_payment_upper_bound
            and actual_native_cost <= native_cost_upper_bound
        )
        conservative_shadow_floor_preserved = (
            cost_upper_bounds_respected and residual_shortfall == 0
        )

        simulation = self.package.unsigned_package.simulations[0]
        if event.principal_repaid != simulation.flash_loan_principal_repaid:
            raise ValueError("settlement principal disagrees with exact simulation agreement")
        if event.flash_loan_fee_paid != simulation.flash_loan_fee_paid:
            raise ValueError("settlement fee disagrees with exact simulation agreement")
        if event.beneficiary != simulation.base_token_beneficiary:
            raise ValueError("settlement beneficiary disagrees with exact simulation agreement")
        simulation_gas_match = self.inclusion.gas_used == simulation.gas_used
        simulation_logs_match = self.inclusion.receipt.logs_sha256 == simulation.logs_sha256
        simulation_output_match = event.gross_output == simulation.output_amount
        simulation_residual_match = (
            event.base_token_residual_before_external_costs
            == simulation.base_token_residual_before_external_costs
        )
        simulation_direct_payment_match = (
            event.direct_inclusion_payment == simulation.coinbase_payment
        )

        identity = {
            "schema": self.schema,
            "package_sha256": self.package.digest,
            "inclusion_sha256": self.inclusion.digest,
            "settlement_registry_sha256": self.settlement_registry.digest,
            "settlement_spec_sha256": self.settlement_spec.digest,
            "settlement_event_sha256": event.digest,
            "rollup_fee_sha256": self.rollup_fee.digest,
            "actual_native_cost": str(actual_native_cost),
            "native_cost_upper_bound": str(native_cost_upper_bound),
            "native_cost_overrun": str(native_cost_overrun),
            "base_token_residual_shortfall_before_external_costs": str(
                residual_shortfall
            ),
            "created_at_unix_ms": str(self.created_at_unix_ms),
        }
        object.__setattr__(self, "_settlement_event", event)
        object.__setattr__(self, "_actual_native_cost", actual_native_cost)
        object.__setattr__(self, "_native_cost_upper_bound", native_cost_upper_bound)
        object.__setattr__(self, "_native_cost_overrun", native_cost_overrun)
        object.__setattr__(
            self,
            "_base_token_residual_shortfall_before_external_costs",
            residual_shortfall,
        )
        object.__setattr__(self, "_simulation_gas_match", simulation_gas_match)
        object.__setattr__(self, "_simulation_logs_match", simulation_logs_match)
        object.__setattr__(self, "_simulation_output_match", simulation_output_match)
        object.__setattr__(self, "_simulation_residual_match", simulation_residual_match)
        object.__setattr__(
            self,
            "_simulation_direct_payment_match",
            simulation_direct_payment_match,
        )
        object.__setattr__(
            self,
            "_cost_upper_bounds_respected",
            cost_upper_bounds_respected,
        )
        object.__setattr__(
            self,
            "_conservative_shadow_floor_preserved",
            conservative_shadow_floor_preserved,
        )
        object.__setattr__(self, "_outcome_id", "realized-outcome-" + canonical_sha256(identity))
        canonical_json_bytes(self.to_json_value())

    @property
    def outcome_id(self) -> str:
        return self._outcome_id

    @property
    def settlement_event(self) -> ExecutorSettlementEvent:
        return self._settlement_event

    @property
    def actual_native_cost(self) -> int:
        return self._actual_native_cost

    @property
    def native_cost_upper_bound(self) -> int:
        return self._native_cost_upper_bound

    @property
    def native_cost_overrun(self) -> int:
        return self._native_cost_overrun

    @property
    def base_token_residual_shortfall_before_external_costs(self) -> int:
        return self._base_token_residual_shortfall_before_external_costs

    @property
    def simulation_gas_match(self) -> bool:
        return self._simulation_gas_match

    @property
    def simulation_logs_match(self) -> bool:
        return self._simulation_logs_match

    @property
    def simulation_output_match(self) -> bool:
        return self._simulation_output_match

    @property
    def simulation_residual_match(self) -> bool:
        return self._simulation_residual_match

    @property
    def simulation_direct_payment_match(self) -> bool:
        return self._simulation_direct_payment_match

    @property
    def simulation_economic_match(self) -> bool:
        return (
            self.simulation_output_match
            and self.simulation_residual_match
            and self.simulation_direct_payment_match
        )

    @property
    def simulation_exact_match(self) -> bool:
        return (
            self.simulation_gas_match
            and self.simulation_logs_match
            and self.simulation_economic_match
        )

    @property
    def cost_upper_bounds_respected(self) -> bool:
        return self._cost_upper_bounds_respected

    @property
    def conservative_shadow_floor_preserved(self) -> bool:
        return self._conservative_shadow_floor_preserved

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "outcome_id": self.outcome_id,
            "package_sha256": self.package.digest,
            "inclusion": self.inclusion.to_json_value(),
            "inclusion_sha256": self.inclusion.digest,
            "settlement_registry": self.settlement_registry.to_json_value(),
            "settlement_registry_sha256": self.settlement_registry.digest,
            "settlement_spec": self.settlement_spec.to_json_value(),
            "settlement_spec_sha256": self.settlement_spec.digest,
            "settlement_event": self.settlement_event.to_json_value(),
            "settlement_event_sha256": self.settlement_event.digest,
            "rollup_fee": self.rollup_fee.to_json_value(),
            "rollup_fee_sha256": self.rollup_fee.digest,
            "transaction_hash": self.package.signed_transaction.transaction_hash_hex,
            "block_number": str(self.inclusion.block.block_number),
            "transaction_index": str(self.inclusion.transaction_index),
            "gas_used": str(self.inclusion.gas_used),
            "effective_gas_price": str(self.inclusion.effective_gas_price),
            "execution_gas_cost": str(self.inclusion.execution_gas_cost),
            "l1_data_fee_paid": str(self.rollup_fee.l1_data_fee_paid),
            "operator_fee_paid": str(self.rollup_fee.operator_fee_paid),
            "direct_inclusion_payment": str(
                self.settlement_event.direct_inclusion_payment
            ),
            "actual_native_cost": str(self.actual_native_cost),
            "native_cost_upper_bound": str(self.native_cost_upper_bound),
            "native_cost_overrun": str(self.native_cost_overrun),
            "base_token": to_hex_data(self.settlement_event.base_token),
            "planned_base_token_residual_before_external_costs": str(
                self.package.unsigned_package.net_profit_evidence.plan.residual_before_external_costs
            ),
            "realized_base_token_residual_before_external_costs": str(
                self.settlement_event.base_token_residual_before_external_costs
            ),
            "base_token_residual_shortfall_before_external_costs": str(
                self.base_token_residual_shortfall_before_external_costs
            ),
            "simulation_gas_match": self.simulation_gas_match,
            "simulation_logs_match": self.simulation_logs_match,
            "simulation_output_match": self.simulation_output_match,
            "simulation_residual_match": self.simulation_residual_match,
            "simulation_direct_payment_match": self.simulation_direct_payment_match,
            "simulation_economic_match": self.simulation_economic_match,
            "simulation_exact_match": self.simulation_exact_match,
            "cost_upper_bounds_respected": self.cost_upper_bounds_respected,
            "conservative_shadow_floor_preserved": (
                self.conservative_shadow_floor_preserved
            ),
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "outcome_authority": "authenticated-inclusion-receipt-code-hash-bound-settlement-and-recorded-rollup-fees-only",
            "cost_completeness": "authenticated-eip1559-gas-plus-recorded-rollup-and-direct-payment-only",
            "inclusion_observed": True,
            "execution_success": True,
            "settlement_observed": True,
            "realized_profit_claimed": False,
            "key_authority": "none",
            "submission_authority": "none",
            "execution_authority": "none",
            "inclusion_guarantee": False,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())
