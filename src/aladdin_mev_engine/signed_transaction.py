from __future__ import annotations

from dataclasses import dataclass, field

from .canonical import canonical_json_bytes, canonical_sha256
from .constant_product import MAX_UINT256
from .domain import require_bounded_text, require_sha256
from .evm_hex import to_hex_data
from .evm_transaction import (
    EIP1559_TYPE_BYTE,
    MAX_BUNDLE_TRANSACTIONS,
    PrivateBundleIntent,
    UnsignedEip1559Transaction,
)
from .keccak import keccak256
from .rlp import rlp_encode
from .secp256k1 import (
    GROUP_ORDER,
    HALF_GROUP_ORDER,
    public_key_to_address,
    recover_public_keys,
)

SIGNATURE_SCHEMA = "aladdin-mev-eip1559-signature/v1"
SIGNED_TRANSACTION_SCHEMA = "aladdin-mev-signed-eip1559-transaction/v1"
SIGNED_BUNDLE_SCHEMA = "aladdin-mev-signed-private-bundle/v1"
MAX_UINT64 = (1 << 64) - 1


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


def _uint_bytes(value: int) -> bytes:
    _uint256("RLP integer", value)
    return b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")


@dataclass(frozen=True, slots=True)
class Eip1559Signature:
    y_parity: int
    r: int
    s: int
    observed_at_unix_ms: int
    source_id: str
    source_sha256: str
    schema: str = SIGNATURE_SCHEMA
    _digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.schema != SIGNATURE_SCHEMA:
            raise ValueError("unsupported EIP-1559 signature schema")
        if type(self.y_parity) is not int or self.y_parity not in (0, 1):
            raise ValueError("y_parity must be 0 or 1")
        _uint256("r", self.r, positive=True)
        _uint256("s", self.s, positive=True)
        if self.r >= GROUP_ORDER or self.s >= GROUP_ORDER:
            raise ValueError("signature scalars must be below the secp256k1 group order")
        if self.s > HALF_GROUP_ORDER:
            raise ValueError("signature must use canonical low-s form")
        _uint64("observed_at_unix_ms", self.observed_at_unix_ms)
        require_bounded_text("source_id", self.source_id, maximum=128)
        require_sha256("source_sha256", self.source_sha256)
        payload = self.to_json_value()
        canonical_json_bytes(payload)
        object.__setattr__(self, "_digest", canonical_sha256(payload))

    @property
    def signature_bytes(self) -> bytes:
        return self.r.to_bytes(32, "big") + self.s.to_bytes(32, "big") + bytes((self.y_parity,))

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "y_parity": str(self.y_parity),
            "r": str(self.r),
            "s": str(self.s),
            "signature_bytes": to_hex_data(self.signature_bytes),
            "observed_at_unix_ms": str(self.observed_at_unix_ms),
            "source_id": self.source_id,
            "source_sha256": self.source_sha256,
            "canonicality": "eip2-low-s",
            "private_key_present": False,
        }

    @property
    def digest(self) -> str:
        return self._digest


@dataclass(frozen=True, slots=True)
class SignedEip1559TransactionEvidence:
    unsigned_transaction: UnsignedEip1559Transaction
    signature: Eip1559Signature
    created_at_unix_ms: int
    schema: str = SIGNED_TRANSACTION_SCHEMA
    _raw_transaction: bytes = field(init=False, repr=False)
    _transaction_hash: bytes = field(init=False, repr=False)
    _recovered_sender: bytes = field(init=False, repr=False)
    _signed_transaction_id: str = field(init=False, repr=False)
    _unsigned_transaction_sha256: str = field(init=False, repr=False)
    _signature_sha256: str = field(init=False, repr=False)
    _digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.schema != SIGNED_TRANSACTION_SCHEMA:
            raise ValueError("unsupported signed-EIP-1559-transaction schema")
        if type(self.unsigned_transaction) is not UnsignedEip1559Transaction:
            raise TypeError("unsigned_transaction must be exact UnsignedEip1559Transaction")
        if type(self.signature) is not Eip1559Signature:
            raise TypeError("signature must be exact Eip1559Signature")
        _uint64("created_at_unix_ms", self.created_at_unix_ms)
        if self.signature.observed_at_unix_ms < self.unsigned_transaction.created_at_unix_ms:
            raise ValueError("signature cannot predate the unsigned transaction")
        if self.created_at_unix_ms < self.signature.observed_at_unix_ms:
            raise ValueError("signed transaction evidence cannot predate the signature")
        if self.created_at_unix_ms > self.unsigned_transaction.inputs_valid_until_unix_ms:
            raise ValueError("unsigned transaction inputs expired before signature verification")
        recovered_keys = recover_public_keys(
            self.unsigned_transaction.signing_hash,
            self.signature.r,
            self.signature.s,
            self.signature.y_parity,
        )
        matching_keys = tuple(
            item
            for item in recovered_keys
            if public_key_to_address(item) == self.unsigned_transaction.sender
        )
        if len(matching_keys) != 1:
            raise ValueError("signature does not uniquely recover the authenticated sender")
        recovered_sender = public_key_to_address(matching_keys[0])
        unsigned = self.unsigned_transaction
        signed_fields = (
            _uint_bytes(unsigned.chain_id),
            _uint_bytes(unsigned.nonce),
            _uint_bytes(unsigned.max_priority_fee_per_gas),
            _uint_bytes(unsigned.max_fee_per_gas),
            _uint_bytes(unsigned.gas_limit),
            unsigned.to,
            _uint_bytes(unsigned.value),
            unsigned.data,
            (),
            _uint_bytes(self.signature.y_parity),
            _uint_bytes(self.signature.r),
            _uint_bytes(self.signature.s),
        )
        raw = EIP1559_TYPE_BYTE + rlp_encode(signed_fields)
        transaction_hash = keccak256(raw)
        unsigned_sha256 = unsigned.digest
        signature_sha256 = self.signature.digest
        identity = {
            "schema": self.schema,
            "unsigned_transaction_sha256": unsigned_sha256,
            "signature_sha256": signature_sha256,
            "transaction_hash": to_hex_data(transaction_hash),
            "recovered_sender": to_hex_data(recovered_sender),
            "created_at_unix_ms": str(self.created_at_unix_ms),
        }
        object.__setattr__(self, "_raw_transaction", raw)
        object.__setattr__(self, "_transaction_hash", transaction_hash)
        object.__setattr__(self, "_recovered_sender", recovered_sender)
        object.__setattr__(self, "_unsigned_transaction_sha256", unsigned_sha256)
        object.__setattr__(self, "_signature_sha256", signature_sha256)
        object.__setattr__(self, "_signed_transaction_id", "signed-tx-" + canonical_sha256(identity))
        payload = self.to_json_value()
        canonical_json_bytes(payload)
        object.__setattr__(self, "_digest", canonical_sha256(payload))

    @property
    def raw_transaction(self) -> bytes:
        return self._raw_transaction

    @property
    def transaction_hash(self) -> bytes:
        return self._transaction_hash

    @property
    def transaction_hash_hex(self) -> str:
        return to_hex_data(self.transaction_hash)

    @property
    def recovered_sender(self) -> bytes:
        return self._recovered_sender

    @property
    def signed_transaction_id(self) -> str:
        return self._signed_transaction_id

    @property
    def inputs_valid_until_unix_ms(self) -> int:
        return self.unsigned_transaction.inputs_valid_until_unix_ms

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "signed_transaction_id": self.signed_transaction_id,
            "unsigned_transaction_sha256": self._unsigned_transaction_sha256,
            "unsigned_signing_hash": self.unsigned_transaction.signing_hash_hex,
            "chain": self.unsigned_transaction.chain.value,
            "chain_id": str(self.unsigned_transaction.chain_id),
            "nonce": str(self.unsigned_transaction.nonce),
            "signature": self.signature.to_json_value(),
            "signature_sha256": self._signature_sha256,
            "raw_transaction": to_hex_data(self.raw_transaction),
            "transaction_hash": self.transaction_hash_hex,
            "recovered_sender": to_hex_data(self.recovered_sender),
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "inputs_valid_until_unix_ms": str(self.inputs_valid_until_unix_ms),
            "signature_present": True,
            "private_key_present": False,
            "signature_verification_authority": "offline-secp256k1-recovery-only",
            "signing_authority": "external-unmodeled",
            "submission_eligible": False,
            "execution_eligible": False,
        }

    @property
    def digest(self) -> str:
        return self._digest


@dataclass(frozen=True, slots=True)
class SignedPrivateBundleEvidence:
    unsigned_bundle: PrivateBundleIntent
    signed_transactions: tuple[SignedEip1559TransactionEvidence, ...]
    created_at_unix_ms: int
    schema: str = SIGNED_BUNDLE_SCHEMA
    _signed_bundle_id: str = field(init=False, repr=False)
    _unsigned_bundle_sha256: str = field(init=False, repr=False)
    _signed_transaction_sha256: tuple[str, ...] = field(init=False, repr=False)
    _digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.schema != SIGNED_BUNDLE_SCHEMA:
            raise ValueError("unsupported signed-private-bundle schema")
        if type(self.unsigned_bundle) is not PrivateBundleIntent:
            raise TypeError("unsigned_bundle must be exact PrivateBundleIntent")
        if type(self.signed_transactions) is not tuple or not self.signed_transactions:
            raise TypeError("signed_transactions must be a non-empty exact tuple")
        if len(self.signed_transactions) > MAX_BUNDLE_TRANSACTIONS:
            raise ValueError("signed bundle exceeds the governed transaction ceiling")
        if any(type(item) is not SignedEip1559TransactionEvidence for item in self.signed_transactions):
            raise TypeError("signed bundle contains an ungoverned transaction")
        _uint64("created_at_unix_ms", self.created_at_unix_ms)
        if len(self.signed_transactions) != len(self.unsigned_bundle.transactions):
            raise ValueError("signed bundle transaction count does not match the unsigned intent")
        for unsigned, signed in zip(self.unsigned_bundle.transactions, self.signed_transactions):
            if signed.unsigned_transaction.digest != unsigned.digest:
                raise ValueError("signed bundle transaction order or identity disagrees with the unsigned intent")
        if self.created_at_unix_ms < max(item.created_at_unix_ms for item in self.signed_transactions):
            raise ValueError("signed bundle evidence cannot predate a signed transaction")
        if self.created_at_unix_ms < self.unsigned_bundle.created_at_unix_ms:
            raise ValueError("signed bundle evidence cannot predate the unsigned bundle intent")
        if self.created_at_unix_ms > self.unsigned_bundle.inputs_valid_until_unix_ms:
            raise ValueError("unsigned bundle inputs expired before signed bundle construction")
        unsigned_bundle_sha256 = self.unsigned_bundle.digest
        signed_transaction_sha256 = tuple(item.digest for item in self.signed_transactions)
        identity = {
            "schema": self.schema,
            "unsigned_bundle_sha256": unsigned_bundle_sha256,
            "signed_transaction_sha256": list(signed_transaction_sha256),
            "transaction_hash": [item.transaction_hash_hex for item in self.signed_transactions],
            "created_at_unix_ms": str(self.created_at_unix_ms),
        }
        object.__setattr__(self, "_unsigned_bundle_sha256", unsigned_bundle_sha256)
        object.__setattr__(self, "_signed_transaction_sha256", signed_transaction_sha256)
        object.__setattr__(self, "_signed_bundle_id", "signed-bundle-" + canonical_sha256(identity))
        payload = self.to_json_value()
        canonical_json_bytes(payload)
        object.__setattr__(self, "_digest", canonical_sha256(payload))

    @property
    def signed_bundle_id(self) -> str:
        return self._signed_bundle_id

    @property
    def raw_transactions(self) -> tuple[bytes, ...]:
        return tuple(item.raw_transaction for item in self.signed_transactions)

    @property
    def transaction_hashes(self) -> tuple[str, ...]:
        return tuple(item.transaction_hash_hex for item in self.signed_transactions)

    @property
    def inputs_valid_until_unix_ms(self) -> int:
        return min(
            self.unsigned_bundle.inputs_valid_until_unix_ms,
            *(item.inputs_valid_until_unix_ms for item in self.signed_transactions),
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "signed_bundle_id": self.signed_bundle_id,
            "unsigned_bundle_sha256": self._unsigned_bundle_sha256,
            "signed_transaction_sha256": list(self._signed_transaction_sha256),
            "raw_transactions": [to_hex_data(item) for item in self.raw_transactions],
            "transaction_hashes": list(self.transaction_hashes),
            "chain": self.unsigned_bundle.chain.value,
            "delivery_class": self.unsigned_bundle.delivery_class.value,
            "sender": to_hex_data(self.unsigned_bundle.sender),
            "target_block_number": str(self.unsigned_bundle.target_block_number),
            "maximum_block_number": str(self.unsigned_bundle.maximum_block_number),
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "inputs_valid_until_unix_ms": str(self.inputs_valid_until_unix_ms),
            "bundle_authority": "offline-externally-signed-private-intent-only",
            "relay_credentials_present": False,
            "network_dispatched": False,
            "submission_eligible": False,
            "execution_eligible": False,
            "inclusion_guarantee": False,
        }

    @property
    def digest(self) -> str:
        return self._digest
