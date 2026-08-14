from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from .canonical import canonical_json_bytes, canonical_sha256
from .constant_product import MAX_UINT256
from .domain import Chain, require_bounded_text, require_sha256
from .evm_abi import GovernedExecutorCall
from .evm_hex import to_hex_data
from .keccak import keccak256
from .mpt import EMPTY_TRIE_ROOT
from .rlp import rlp_encode
from .state_proof import EMPTY_CODE_HASH, EvmStateProofEvidence

SENDER_STATE_SCHEMA = "aladdin-mev-sender-state-evidence/v1"
UNSIGNED_TX_SCHEMA = "aladdin-mev-unsigned-eip1559-transaction/v1"
BUNDLE_INTENT_SCHEMA = "aladdin-mev-private-bundle-intent/v1"

MAX_UINT64 = (1 << 64) - 1
MAX_BUNDLE_TRANSACTIONS = 8
MAX_TARGET_BLOCK_DISTANCE = 8
MAX_BUNDLE_ANCHOR_AGE_MS = 1_000
EIP1559_TYPE_BYTE = b"\x02"
BASE_INTRINSIC_GAS = 21_000
ZERO_DATA_GAS = 4
NONZERO_DATA_GAS = 16

CHAIN_IDS: dict[Chain, int] = {
    Chain.ETHEREUM: 1,
    Chain.BASE: 8453,
}


class PrivateDeliveryClass(StrEnum):
    BUILDER = "private-builder"
    SEQUENCER = "private-sequencer"


def _uint256(name: str, value: object, *, positive: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT256:
        raise ValueError(f"{name} must be an unsigned 256-bit exact integer")
    if positive and value == 0:
        raise ValueError(f"{name} must be positive")
    return value


def _uint64(name: str, value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT64:
        raise ValueError(f"{name} must be an unsigned 64-bit exact integer")
    return value


def _uint_bytes(value: int) -> bytes:
    _uint256("RLP integer", value)
    return b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")


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


@dataclass(frozen=True, slots=True)
class SenderStateEvidence:
    evidence: EvmStateProofEvidence
    schema: str = SENDER_STATE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SENDER_STATE_SCHEMA:
            raise ValueError("unsupported sender-state-evidence schema")
        if type(self.evidence) is not EvmStateProofEvidence:
            raise TypeError("evidence must be exact EvmStateProofEvidence")
        if not self.evidence.account_exists:
            raise ValueError("sender account must exist in authenticated state")
        if self.evidence.chain not in CHAIN_IDS:
            raise ValueError("F5 sender state supports Ethereum and Base only")
        if self.evidence.address == bytes(20):
            raise ValueError("sender address cannot be zero")
        if self.evidence.code_hash != EMPTY_CODE_HASH:
            raise ValueError("F5 sender must be an authenticated externally owned account")
        if self.evidence.storage_root != EMPTY_TRIE_ROOT:
            raise ValueError("authenticated EOA sender must have the empty storage root")
        if self.evidence.storage_values:
            raise ValueError("sender-state evidence cannot carry unused storage proofs")
        _uint64("sender nonce", self.evidence.nonce)
        _uint256("sender balance", self.evidence.balance)
        canonical_json_bytes(self.to_json_value())

    @property
    def chain(self) -> Chain:
        return self.evidence.chain

    @property
    def sender(self) -> bytes:
        return self.evidence.address

    @property
    def nonce(self) -> int:
        return self.evidence.nonce

    @property
    def balance(self) -> int:
        return self.evidence.balance

    @property
    def anchor_sha256(self) -> str:
        return self.evidence.anchor.digest

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "evidence": self.evidence.to_json_value(),
            "evidence_sha256": self.evidence.digest,
            "sender": to_hex_data(self.sender),
            "nonce": str(self.nonce),
            "balance": str(self.balance),
            "account_kind": "externally-owned-account",
            "signing_authority": "none",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class UnsignedEip1559Transaction:
    call: GovernedExecutorCall
    sender_state: SenderStateEvidence
    created_at_unix_ms: int
    nonce_offset: int = 0
    schema: str = UNSIGNED_TX_SCHEMA
    _signing_payload: bytes = field(init=False, repr=False)
    _signing_hash: bytes = field(init=False, repr=False)
    _intrinsic_gas: int = field(init=False, repr=False)
    _maximum_upfront_native: int = field(init=False, repr=False)
    _inputs_valid_until_unix_ms: int = field(init=False, repr=False)
    _transaction_id: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != UNSIGNED_TX_SCHEMA:
            raise ValueError("unsupported unsigned-EIP-1559-transaction schema")
        if type(self.call) is not GovernedExecutorCall:
            raise TypeError("call must be an exact GovernedExecutorCall")
        if type(self.sender_state) is not SenderStateEvidence:
            raise TypeError("sender_state must be exact SenderStateEvidence")
        _uint64("created_at_unix_ms", self.created_at_unix_ms)
        _uint64("nonce_offset", self.nonce_offset)
        if self.nonce_offset >= MAX_BUNDLE_TRANSACTIONS:
            raise ValueError("nonce_offset exceeds the governed bundle transaction ceiling")
        if self.sender_state.nonce > MAX_UINT64 - self.nonce_offset:
            raise ValueError("sender nonce plus offset exceeds uint64")
        if self.created_at_unix_ms < self.call.created_at_unix_ms:
            raise ValueError("unsigned transaction cannot precede its executor call")
        if self.created_at_unix_ms < self.sender_state.evidence.proof_observed_at_unix_ms:
            raise ValueError("unsigned transaction cannot precede sender proof observation")
        chain = self.call.deployment.chain
        if self.sender_state.chain is not chain:
            raise ValueError("sender state chain does not match the executor call")
        if self.sender_state.anchor_sha256 != self.call.deployment.anchor_sha256:
            raise ValueError("sender, deployment, and execution plan must share one exact state anchor")
        evidence = self.call.net_profit_evidence
        inputs_valid_until = min(
            evidence.inputs_valid_until_unix_ms,
            self.call.inputs_valid_until_unix_ms,
        )
        if self.created_at_unix_ms > inputs_valid_until:
            raise ValueError("F4 inputs or executor-call deadline are expired at unsigned-transaction creation")
        fee = evidence.cost_envelope.fee_envelope
        _uint64("gas_limit", fee.gas_units_upper_bound)
        zero_bytes = self.call.calldata.count(0)
        nonzero_bytes = len(self.call.calldata) - zero_bytes
        intrinsic = _checked_add(
            BASE_INTRINSIC_GAS,
            _checked_add(
                _checked_mul(zero_bytes, ZERO_DATA_GAS, "zero calldata intrinsic gas"),
                _checked_mul(nonzero_bytes, NONZERO_DATA_GAS, "nonzero calldata intrinsic gas"),
                "calldata intrinsic gas",
            ),
            "transaction intrinsic gas",
        )
        _uint64("intrinsic_gas", intrinsic)
        if fee.gas_units_upper_bound < intrinsic:
            raise ValueError("gas limit is below the canonical intrinsic gas requirement")
        value = fee.direct_inclusion_payment_upper_bound
        maximum_upfront = _checked_add(
            _checked_mul(fee.gas_units_upper_bound, fee.max_fee_per_gas, "maximum gas charge"),
            value,
            "maximum upfront native amount",
        )
        maximum_with_l1 = _checked_add(
            maximum_upfront,
            fee.l1_data_fee_upper_bound,
            "maximum funded native amount before operator fee",
        )
        maximum_funded = _checked_add(
            maximum_with_l1,
            fee.operator_fee_upper_bound,
            "maximum funded native amount",
        )
        if self.sender_state.balance < maximum_funded:
            raise ValueError("authenticated sender balance cannot cover the recorded native upper bound")
        chain_id = CHAIN_IDS[chain]
        access_list: tuple[object, ...] = ()
        unsigned_fields = (
            _uint_bytes(chain_id),
            _uint_bytes(self.nonce),
            _uint_bytes(fee.max_priority_fee_per_gas),
            _uint_bytes(fee.max_fee_per_gas),
            _uint_bytes(fee.gas_units_upper_bound),
            self.call.deployment.address,
            _uint_bytes(value),
            self.call.calldata,
            access_list,
        )
        payload = EIP1559_TYPE_BYTE + rlp_encode(unsigned_fields)
        signing_hash = keccak256(payload)
        identity = {
            "schema": self.schema,
            "call_sha256": self.call.digest,
            "sender_state_sha256": self.sender_state.digest,
            "chain_id": str(chain_id),
            "nonce": str(self.nonce),
            "nonce_offset": str(self.nonce_offset),
            "signing_hash": to_hex_data(signing_hash),
            "created_at_unix_ms": str(self.created_at_unix_ms),
        }
        object.__setattr__(self, "_signing_payload", payload)
        object.__setattr__(self, "_signing_hash", signing_hash)
        object.__setattr__(self, "_intrinsic_gas", intrinsic)
        object.__setattr__(self, "_maximum_upfront_native", maximum_funded)
        object.__setattr__(self, "_inputs_valid_until_unix_ms", inputs_valid_until)
        object.__setattr__(self, "_transaction_id", "unsigned-tx-" + canonical_sha256(identity))
        canonical_json_bytes(self.to_json_value())

    @property
    def chain(self) -> Chain:
        return self.call.deployment.chain

    @property
    def chain_id(self) -> int:
        return CHAIN_IDS[self.chain]

    @property
    def nonce(self) -> int:
        return self.sender_state.nonce + self.nonce_offset

    @property
    def sender(self) -> bytes:
        return self.sender_state.sender

    @property
    def to(self) -> bytes:
        return self.call.deployment.address

    @property
    def value(self) -> int:
        return self.call.net_profit_evidence.cost_envelope.fee_envelope.direct_inclusion_payment_upper_bound

    @property
    def gas_limit(self) -> int:
        return self.call.net_profit_evidence.cost_envelope.fee_envelope.gas_units_upper_bound

    @property
    def max_fee_per_gas(self) -> int:
        return self.call.net_profit_evidence.cost_envelope.fee_envelope.max_fee_per_gas

    @property
    def max_priority_fee_per_gas(self) -> int:
        return self.call.net_profit_evidence.cost_envelope.fee_envelope.max_priority_fee_per_gas

    @property
    def operator_fee_upper_bound(self) -> int:
        return self.call.net_profit_evidence.cost_envelope.fee_envelope.operator_fee_upper_bound

    @property
    def data(self) -> bytes:
        return self.call.calldata

    @property
    def signing_payload(self) -> bytes:
        return self._signing_payload

    @property
    def signing_hash(self) -> bytes:
        return self._signing_hash

    @property
    def signing_hash_hex(self) -> str:
        return to_hex_data(self.signing_hash)

    @property
    def intrinsic_gas(self) -> int:
        return self._intrinsic_gas

    @property
    def maximum_upfront_native(self) -> int:
        return self._maximum_upfront_native

    @property
    def inputs_valid_until_unix_ms(self) -> int:
        return self._inputs_valid_until_unix_ms

    @property
    def transaction_id(self) -> str:
        return self._transaction_id

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "transaction_id": self.transaction_id,
            "call": self.call.to_json_value(),
            "call_sha256": self.call.digest,
            "sender_state": self.sender_state.to_json_value(),
            "sender_state_sha256": self.sender_state.digest,
            "transaction_type": "0x02",
            "chain": self.chain.value,
            "chain_id": str(self.chain_id),
            "sender": to_hex_data(self.sender),
            "nonce": str(self.nonce),
            "nonce_offset": str(self.nonce_offset),
            "max_priority_fee_per_gas": str(self.max_priority_fee_per_gas),
            "max_fee_per_gas": str(self.max_fee_per_gas),
            "gas_limit": str(self.gas_limit),
            "intrinsic_gas": str(self.intrinsic_gas),
            "to": to_hex_data(self.to),
            "value": str(self.value),
            "data": to_hex_data(self.data),
            "access_list": [],
            "operator_fee_upper_bound": str(self.operator_fee_upper_bound),
            "maximum_upfront_native": str(self.maximum_upfront_native),
            "signing_payload": to_hex_data(self.signing_payload),
            "signing_hash": self.signing_hash_hex,
            "signature": None,
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "inputs_valid_until_unix_ms": str(self.inputs_valid_until_unix_ms),
            "transaction_authority": "unsigned-deterministic-preimage-only",
            "signing_eligible": False,
            "submission_eligible": False,
            "execution_eligible": False,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class PrivateBundleIntent:
    transactions: tuple[UnsignedEip1559Transaction, ...]
    target_block_number: int
    maximum_block_number: int
    created_at_unix_ms: int
    schema: str = BUNDLE_INTENT_SCHEMA
    _delivery_class: PrivateDeliveryClass = field(init=False, repr=False)
    _anchor_fresh_until_unix_ms: int = field(init=False, repr=False)
    _inputs_valid_until_unix_ms: int = field(init=False, repr=False)
    _maximum_bundle_upfront_native: int = field(init=False, repr=False)
    _bundle_id: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != BUNDLE_INTENT_SCHEMA:
            raise ValueError("unsupported private-bundle-intent schema")
        if type(self.transactions) is not tuple or not self.transactions:
            raise TypeError("transactions must be a non-empty exact tuple")
        if len(self.transactions) > MAX_BUNDLE_TRANSACTIONS:
            raise ValueError("private bundle exceeds the governed transaction ceiling")
        if any(type(item) is not UnsignedEip1559Transaction for item in self.transactions):
            raise TypeError("private bundle contains an ungoverned transaction")
        _uint64("target_block_number", self.target_block_number)
        _uint64("maximum_block_number", self.maximum_block_number)
        _uint64("created_at_unix_ms", self.created_at_unix_ms)
        first = self.transactions[0]
        if self.created_at_unix_ms < max(item.created_at_unix_ms for item in self.transactions):
            raise ValueError("bundle intent cannot precede an unsigned transaction")
        chain = first.chain
        sender = first.sender
        anchor = first.sender_state.evidence.anchor
        if any(item.chain is not chain for item in self.transactions):
            raise ValueError("private bundle transactions must share one exact chain")
        if any(item.sender != sender for item in self.transactions):
            raise ValueError("private bundle transactions must share one exact sender")
        if any(item.sender_state.anchor_sha256 != first.sender_state.anchor_sha256 for item in self.transactions):
            raise ValueError("private bundle transactions must share one exact state anchor")
        if any(item.sender_state.digest != first.sender_state.digest for item in self.transactions):
            raise ValueError("private bundle transactions must share one exact sender-state evidence")
        if first.nonce_offset != 0 or first.nonce != first.sender_state.nonce:
            raise ValueError("private bundle must start at the authenticated sender nonce")
        nonces = [item.nonce for item in self.transactions]
        if nonces != list(range(nonces[0], nonces[0] + len(nonces))):
            raise ValueError("private bundle transaction nonces must be contiguous and ordered")
        signing_hashes = [item.signing_hash for item in self.transactions]
        if len(signing_hashes) != len(set(signing_hashes)):
            raise ValueError("private bundle reuses an unsigned transaction signing hash")
        if not anchor.block_number < self.target_block_number:
            raise ValueError("private bundle target block must follow the authenticated state block")
        if self.target_block_number > anchor.block_number + MAX_TARGET_BLOCK_DISTANCE:
            raise ValueError("private bundle target block exceeds the governed distance")
        if not self.target_block_number <= self.maximum_block_number:
            raise ValueError("maximum bundle block cannot precede target block")
        if self.maximum_block_number > anchor.block_number + MAX_TARGET_BLOCK_DISTANCE:
            raise ValueError("private bundle maximum block exceeds the authenticated-state horizon")
        if any(
            not item.call.deployment.spec.is_valid_at_block(self.maximum_block_number)
            for item in self.transactions
        ):
            raise ValueError("executor deployment is not governed through the complete bundle block horizon")
        anchor_fresh_until = _checked_add(
            anchor.state_observed_at_unix_ms,
            MAX_BUNDLE_ANCHOR_AGE_MS,
            "bundle anchor freshness ceiling",
        )
        _uint64("anchor_fresh_until_unix_ms", anchor_fresh_until)
        if self.created_at_unix_ms > anchor_fresh_until:
            raise ValueError("private bundle intent exceeds the governed authenticated-anchor freshness window")
        maximum_bundle_upfront = 0
        for item in self.transactions:
            maximum_bundle_upfront = _checked_add(
                maximum_bundle_upfront,
                item.maximum_upfront_native,
                "maximum bundle upfront native amount",
            )
        if maximum_bundle_upfront > first.sender_state.balance:
            raise ValueError("authenticated sender balance cannot cover the complete private bundle")
        valid_until = min(
            anchor_fresh_until,
            *(item.inputs_valid_until_unix_ms for item in self.transactions),
        )
        if self.created_at_unix_ms > valid_until:
            raise ValueError("private bundle inputs are expired at intent creation")
        if any(self.created_at_unix_ms // 1000 >= item.call.deadline_unix_s for item in self.transactions):
            raise ValueError("executor-call deadline has expired before bundle-intent creation")
        delivery = (
            PrivateDeliveryClass.BUILDER
            if chain is Chain.ETHEREUM
            else PrivateDeliveryClass.SEQUENCER
        )
        identity = {
            "schema": self.schema,
            "transaction_sha256": [item.digest for item in self.transactions],
            "target_block_number": str(self.target_block_number),
            "maximum_block_number": str(self.maximum_block_number),
            "delivery_class": delivery.value,
            "maximum_bundle_upfront_native": str(maximum_bundle_upfront),
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "inputs_valid_until_unix_ms": str(valid_until),
        }
        object.__setattr__(self, "_delivery_class", delivery)
        object.__setattr__(self, "_anchor_fresh_until_unix_ms", anchor_fresh_until)
        object.__setattr__(self, "_inputs_valid_until_unix_ms", valid_until)
        object.__setattr__(self, "_maximum_bundle_upfront_native", maximum_bundle_upfront)
        object.__setattr__(self, "_bundle_id", "bundle-intent-" + canonical_sha256(identity))
        canonical_json_bytes(self.to_json_value())

    @property
    def bundle_id(self) -> str:
        return self._bundle_id

    @property
    def chain(self) -> Chain:
        return self.transactions[0].chain

    @property
    def sender(self) -> bytes:
        return self.transactions[0].sender

    @property
    def delivery_class(self) -> PrivateDeliveryClass:
        return self._delivery_class

    @property
    def anchor_fresh_until_unix_ms(self) -> int:
        return self._anchor_fresh_until_unix_ms

    @property
    def inputs_valid_until_unix_ms(self) -> int:
        return self._inputs_valid_until_unix_ms

    @property
    def maximum_bundle_upfront_native(self) -> int:
        return self._maximum_bundle_upfront_native

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "bundle_id": self.bundle_id,
            "chain": self.chain.value,
            "sender": to_hex_data(self.sender),
            "transactions": [item.to_json_value() for item in self.transactions],
            "transaction_sha256": [item.digest for item in self.transactions],
            "transaction_signing_hash": [item.signing_hash_hex for item in self.transactions],
            "target_block_number": str(self.target_block_number),
            "maximum_block_number": str(self.maximum_block_number),
            "delivery_class": self.delivery_class.value,
            "relay_url": None,
            "relay_credentials": None,
            "signed_transaction_count": "0",
            "maximum_bundle_upfront_native": str(self.maximum_bundle_upfront_native),
            "anchor_fresh_until_unix_ms": str(self.anchor_fresh_until_unix_ms),
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "inputs_valid_until_unix_ms": str(self.inputs_valid_until_unix_ms),
            "submission_authority": "none",
            "signing_eligible": False,
            "submission_eligible": False,
            "execution_eligible": False,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())
