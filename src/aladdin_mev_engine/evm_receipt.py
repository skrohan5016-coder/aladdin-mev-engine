from __future__ import annotations

from dataclasses import dataclass, field
import hashlib

from .canonical import (
    DEFAULT_MAX_JSON_BYTES,
    canonical_json_bytes,
    canonical_sha256,
)
from .constant_product import MAX_UINT256
from .evm_hex import to_hex_data
from .keccak import keccak256
from .rlp import (
    require_rlp_bytes,
    require_rlp_list,
    rlp_decode,
    rlp_decode_uint,
    rlp_encode,
)

LOG_ENTRY_SCHEMA = "aladdin-mev-evm-log-entry/v1"
RECEIPT_SCHEMA = "aladdin-mev-transaction-receipt/v1"

EIP1559_TRANSACTION_TYPE = 2
MAX_RECEIPT_BYTES = 1_048_576
MAX_RECEIPT_LOGS = 1_024
MAX_LOG_TOPICS = 4
MAX_LOG_DATA_BYTES = 262_144
LOGS_BLOOM_BYTES = 256


def _uint256(name: str, value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT256:
        raise ValueError(f"{name} must be an unsigned 256-bit exact integer")
    return value


def _address(name: str, value: object) -> bytes:
    # Consensus log addresses are exact Bytes20 values. Unlike governed
    # deployment/token identities, the receipt encoding itself does not forbid
    # the all-zero address, so the generic receipt decoder must preserve it.
    if type(value) is not bytes or len(value) != 20:
        raise ValueError(f"{name} must be an exact 20-byte address")
    return value


def _bytes32(name: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise ValueError(f"{name} must be exact immutable 32-byte data")
    return value


@dataclass(frozen=True, slots=True)
class EvmLogEntry:
    address: bytes
    topics: tuple[bytes, ...]
    data: bytes
    schema: str = LOG_ENTRY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != LOG_ENTRY_SCHEMA:
            raise ValueError("unsupported EVM-log-entry schema")
        _address("log address", self.address)
        if type(self.topics) is not tuple:
            raise TypeError("log topics must be an exact tuple")
        if len(self.topics) > MAX_LOG_TOPICS:
            raise ValueError("log topic count exceeds the governed ceiling")
        if any(type(item) is not bytes or len(item) != 32 for item in self.topics):
            raise ValueError("log topics must be exact 32-byte values")
        if type(self.data) is not bytes:
            raise TypeError("log data must be exact immutable bytes")
        if len(self.data) > MAX_LOG_DATA_BYTES:
            raise ValueError("log data exceeds the governed byte ceiling")
        canonical_json_bytes(self.to_json_value())

    @property
    def rlp_value(self) -> tuple[object, ...]:
        return (self.address, tuple(self.topics), self.data)

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "address": to_hex_data(self.address),
            "topics": [to_hex_data(item) for item in self.topics],
            "data": to_hex_data(self.data),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


def compute_logs_bloom(logs: tuple[EvmLogEntry, ...]) -> bytes:
    if type(logs) is not tuple:
        raise TypeError("logs must be an exact tuple")
    if len(logs) > MAX_RECEIPT_LOGS:
        raise ValueError("receipt log count exceeds the governed ceiling")
    if any(type(item) is not EvmLogEntry for item in logs):
        raise TypeError("logs contain an ungoverned entry")
    bloom = 0
    for entry in logs:
        for value in (entry.address, *entry.topics):
            digest = keccak256(value)
            for offset in (0, 2, 4):
                bit = int.from_bytes(digest[offset : offset + 2], "big") & 2047
                bloom |= 1 << bit
    return bloom.to_bytes(LOGS_BLOOM_BYTES, "big")


def canonical_logs_sha256(logs: tuple[EvmLogEntry, ...]) -> str:
    if type(logs) is not tuple or any(type(item) is not EvmLogEntry for item in logs):
        raise TypeError("logs must be an exact tuple of EvmLogEntry values")
    if len(logs) > MAX_RECEIPT_LOGS:
        raise ValueError("receipt log count exceeds the governed ceiling")

    # Build the exact canonical JSON array incrementally.  This prevents a
    # caller from combining many individually valid large logs into an
    # unbounded intermediate list/string before the global canonical limit is
    # checked.  Canonical JSON arrays are exactly '[' + comma-joined canonical
    # child encodings + ']'.
    digest = hashlib.sha256()
    digest.update(b"[")
    encoded_size = 1
    for index, item in enumerate(logs):
        encoded_item = canonical_json_bytes(item.to_json_value())
        separator_size = 1 if index else 0
        if encoded_size + separator_size + len(encoded_item) + 1 > DEFAULT_MAX_JSON_BYTES:
            raise ValueError("canonical receipt log array exceeds the governed byte ceiling")
        if index:
            digest.update(b",")
            encoded_size += 1
        digest.update(encoded_item)
        encoded_size += len(encoded_item)
    digest.update(b"]")
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class EvmTransactionReceipt:
    transaction_type: int | None
    status: int
    cumulative_gas_used: int
    logs_bloom: bytes
    logs: tuple[EvmLogEntry, ...]
    raw_receipt: bytes
    schema: str = RECEIPT_SCHEMA
    _logs_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != RECEIPT_SCHEMA:
            raise ValueError("unsupported transaction-receipt schema")
        if self.transaction_type is not None:
            if type(self.transaction_type) is not int or not 1 <= self.transaction_type <= 0x7F:
                raise ValueError("typed receipt transaction_type must be in [1, 127]")
        if type(self.status) is not int or self.status not in (0, 1):
            raise ValueError("receipt status must be exactly zero or one")
        _uint256("cumulative_gas_used", self.cumulative_gas_used)
        if type(self.logs_bloom) is not bytes or len(self.logs_bloom) != LOGS_BLOOM_BYTES:
            raise ValueError("logs_bloom must be exact immutable 256-byte data")
        if type(self.logs) is not tuple:
            raise TypeError("receipt logs must be an exact tuple")
        if len(self.logs) > MAX_RECEIPT_LOGS:
            raise ValueError("receipt log count exceeds the governed ceiling")
        if any(type(item) is not EvmLogEntry for item in self.logs):
            raise TypeError("receipt logs contain an ungoverned entry")
        if type(self.raw_receipt) is not bytes or not self.raw_receipt:
            raise ValueError("raw_receipt must be non-empty exact immutable bytes")
        if len(self.raw_receipt) > MAX_RECEIPT_BYTES:
            raise ValueError("raw_receipt exceeds the governed byte ceiling")
        if compute_logs_bloom(self.logs) != self.logs_bloom:
            raise ValueError("receipt logs bloom does not match its exact logs")
        payload = rlp_encode(
            (
                b"" if self.status == 0 else bytes((self.status,)),
                b"" if self.cumulative_gas_used == 0 else self.cumulative_gas_used.to_bytes(
                    (self.cumulative_gas_used.bit_length() + 7) // 8,
                    "big",
                ),
                self.logs_bloom,
                tuple(item.rlp_value for item in self.logs),
            )
        )
        expected = payload if self.transaction_type is None else bytes((self.transaction_type,)) + payload
        if expected != self.raw_receipt:
            raise ValueError("raw_receipt does not match the exact canonical receipt fields")
        logs_sha256 = canonical_logs_sha256(self.logs)
        object.__setattr__(self, "_logs_sha256", logs_sha256)
        canonical_json_bytes(self.to_json_value())

    @classmethod
    def decode(cls, raw_receipt: bytes) -> EvmTransactionReceipt:
        if type(raw_receipt) is not bytes or not raw_receipt:
            raise ValueError("raw_receipt must be non-empty exact immutable bytes")
        if len(raw_receipt) > MAX_RECEIPT_BYTES:
            raise ValueError("raw_receipt exceeds the governed byte ceiling")
        if raw_receipt[0] <= 0x7F:
            transaction_type: int | None = raw_receipt[0]
            if transaction_type == 0:
                raise ValueError("typed receipt transaction type zero is not governed")
            encoded_payload = raw_receipt[1:]
            if not encoded_payload:
                raise ValueError("typed receipt is missing its RLP payload")
        else:
            transaction_type = None
            encoded_payload = raw_receipt
        values = require_rlp_list(
            "transaction receipt",
            rlp_decode(encoded_payload),
            length=4,
        )
        encoded_status = require_rlp_bytes("receipt status", values[0])
        status = rlp_decode_uint(encoded_status, maximum_bits=8)
        if status not in (0, 1):
            raise ValueError("receipt status must be exactly zero or one")
        cumulative = rlp_decode_uint(
            require_rlp_bytes("receipt cumulative gas", values[1]),
            maximum_bits=256,
        )
        bloom = require_rlp_bytes("receipt logs bloom", values[2])
        logs_value = require_rlp_list("receipt logs", values[3])
        if len(logs_value) > MAX_RECEIPT_LOGS:
            raise ValueError("receipt log count exceeds the governed ceiling")
        logs: list[EvmLogEntry] = []
        for index, item in enumerate(logs_value):
            fields = require_rlp_list(f"receipt log {index}", item, length=3)
            address = require_rlp_bytes(f"receipt log {index} address", fields[0])
            topics_value = require_rlp_list(f"receipt log {index} topics", fields[1])
            if len(topics_value) > MAX_LOG_TOPICS:
                raise ValueError("receipt log topic count exceeds the governed ceiling")
            topics = tuple(
                _bytes32(
                    f"receipt log {index} topic {topic_index}",
                    require_rlp_bytes(
                        f"receipt log {index} topic {topic_index}",
                        topic,
                    ),
                )
                for topic_index, topic in enumerate(topics_value)
            )
            data = require_rlp_bytes(f"receipt log {index} data", fields[2])
            logs.append(EvmLogEntry(address=address, topics=topics, data=data))
        return cls(
            transaction_type=transaction_type,
            status=status,
            cumulative_gas_used=cumulative,
            logs_bloom=bloom,
            logs=tuple(logs),
            raw_receipt=raw_receipt,
        )

    @property
    def success(self) -> bool:
        return self.status == 1

    @property
    def logs_sha256(self) -> str:
        return self._logs_sha256

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "transaction_type": None if self.transaction_type is None else str(self.transaction_type),
            "status": str(self.status),
            "success": self.success,
            "cumulative_gas_used": str(self.cumulative_gas_used),
            "logs_bloom": to_hex_data(self.logs_bloom),
            "logs": [item.to_json_value() for item in self.logs],
            "log_sha256": [item.digest for item in self.logs],
            "logs_sha256": self.logs_sha256,
            "raw_receipt": to_hex_data(self.raw_receipt),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())
