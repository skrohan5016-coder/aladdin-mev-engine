from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .canonical import canonical_json_bytes, canonical_sha256
from .domain import Chain
from .evm_hex import parse_decimal_integer, parse_hex_data, to_decimal, to_hex_data
from .head_tracker import EvmHead
from .keccak import keccak256
from .mpt import MAX_PROOF_NODE_BYTES, MAX_PROOF_NODES, MAX_PROOF_TOTAL_BYTES
from .observation import ObservationEnvelope, parse_decimal, require_u64
from .source_contracts import (
    Finality,
    ObservationKind,
    SourceKind,
    Visibility,
)

BLOCK_STATE_PAYLOAD_SCHEMA = "aladdin-mev-evm-block-state-payload/v1"
STATE_PROOF_PAYLOAD_SCHEMA = "aladdin-mev-evm-state-proof-payload/v1"
STATE_PROOF_EVIDENCE_SCHEMA = "aladdin-mev-evm-state-proof-evidence/v1"
STATE_SNAPSHOT_SCHEMA = "aladdin-mev-evm-state-snapshot/v1"
EMPTY_CODE_HASH = keccak256(b"")
MAX_STORAGE_PROOFS = 128
MAX_SNAPSHOT_ACCOUNTS = 4096
MAX_STATE_PROOF_TOTAL_NODE_BYTES = 1_048_576


def _require_exact_keys(name: str, value: dict[str, Any], expected: set[str]) -> None:
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"{name} keys mismatch; missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )


def _require_nonzero_hash(name: str, value: bytes) -> None:
    if type(value) is not bytes or len(value) != 32:
        raise ValueError(f"{name} must be exact 32-byte data")
    if value == bytes(32):
        raise ValueError(f"{name} cannot be zero")


def _parse_hash(name: str, value: object, *, allow_zero: bool = False) -> bytes:
    parsed = parse_hex_data(name, value, exact_bytes=32, maximum_bytes=32)
    if not allow_zero and parsed == bytes(32):
        raise ValueError(f"{name} cannot be zero")
    return parsed


def _parse_proof_nodes(name: str, value: object) -> tuple[bytes, ...]:
    if type(value) is not list:
        raise ValueError(f"{name} must be an exact JSON array")
    if len(value) > MAX_PROOF_NODES:
        raise ValueError(f"{name} exceeds the governed node-count ceiling")
    nodes = tuple(
        parse_hex_data(
            f"{name}[{index}]",
            item,
            maximum_bytes=MAX_PROOF_NODE_BYTES,
        )
        for index, item in enumerate(value)
    )
    if any(not node for node in nodes):
        raise ValueError(f"{name} contains an empty proof node")
    if sum(len(node) for node in nodes) > MAX_PROOF_TOTAL_BYTES:
        raise ValueError(f"{name} exceeds the governed byte ceiling")
    return nodes


def _validate_anchor_observations(
    head: ObservationEnvelope,
    state: ObservationEnvelope,
) -> tuple[int, bytes, bytes]:
    if type(head) is not ObservationEnvelope or type(state) is not ObservationEnvelope:
        raise TypeError("head and state must be exact ObservationEnvelope values")
    if head.kind is not ObservationKind.BLOCK_HEAD:
        raise ValueError("head observation is not a governed confirmed block head")
    if state.kind is not ObservationKind.EVM_BLOCK_STATE:
        raise ValueError("state observation is not a governed EVM block-state event")
    if head.visibility is not Visibility.FULL or state.visibility is not Visibility.FULL:
        raise ValueError("block-state anchor observations require full visibility")
    if head.finality not in {Finality.CONFIRMED, Finality.FINALIZED}:
        raise ValueError("head finality is not eligible for a state anchor")
    if state.finality is not head.finality:
        raise ValueError("head and state finality disagree")
    if head.chain is Chain.SOLANA or state.chain is Chain.SOLANA:
        raise ValueError("EVM block-state anchors cannot use Solana observations")
    if head.chain is not state.chain or head.source_id != state.source_id:
        raise ValueError("head and state observations do not share one source stream")
    if (
        head.source_kind is not SourceKind.EVM_JSON_RPC
        or state.source_kind is not SourceKind.EVM_JSON_RPC
    ):
        raise ValueError("block-state anchors require an EVM JSON-RPC source")
    if state.source_sequence <= head.source_sequence:
        raise ValueError("state observation must follow the head source sequence")
    if state.observed_at_unix_ms < head.observed_at_unix_ms:
        raise ValueError("state observation time precedes its head")

    head_value = EvmHead.from_observation(head)
    state_payload = state.payload
    _require_exact_keys(
        "block-state payload",
        state_payload,
        {"schema", "block_number", "block_hash", "state_root"},
    )
    if state_payload["schema"] != BLOCK_STATE_PAYLOAD_SCHEMA:
        raise ValueError("unsupported block-state payload schema")
    state_number = parse_decimal("state block_number", state_payload["block_number"])
    head_hash = _parse_hash("head block_hash", head_value.block_hash)
    state_hash = _parse_hash("state block_hash", state_payload["block_hash"])
    state_root = _parse_hash("state_root", state_payload["state_root"])
    if head_value.number != state_number or head_hash != state_hash:
        raise ValueError("block-state observation does not bind the recorded head")
    return head_value.number, head_hash, state_root


@dataclass(frozen=True, slots=True)
class EvmBlockStateAnchor:
    """Authenticated block/state-root identity bound to exact recorded observations."""

    head_observation: ObservationEnvelope
    state_observation: ObservationEnvelope
    _block_number: int = field(init=False, repr=False)
    _block_hash: bytes = field(init=False, repr=False)
    _state_root: bytes = field(init=False, repr=False)

    def __post_init__(self) -> None:
        block_number, block_hash, state_root = _validate_anchor_observations(
            self.head_observation,
            self.state_observation,
        )
        object.__setattr__(self, "_block_number", block_number)
        object.__setattr__(self, "_block_hash", block_hash)
        object.__setattr__(self, "_state_root", state_root)
        canonical_json_bytes(self.to_json_value())

    @classmethod
    def from_observations(
        cls,
        head: ObservationEnvelope,
        state: ObservationEnvelope,
    ) -> EvmBlockStateAnchor:
        return cls(head_observation=head, state_observation=state)

    @property
    def chain(self) -> Chain:
        return self.head_observation.chain

    @property
    def source_id(self) -> str:
        return self.head_observation.source_id

    @property
    def finality(self) -> Finality:
        return self.head_observation.finality

    @property
    def block_number(self) -> int:
        return self._block_number

    @property
    def block_hash(self) -> bytes:
        return self._block_hash

    @property
    def state_root(self) -> bytes:
        return self._state_root

    @property
    def head_source_sequence(self) -> int:
        return self.head_observation.source_sequence

    @property
    def state_source_sequence(self) -> int:
        return self.state_observation.source_sequence

    @property
    def head_observed_at_unix_ms(self) -> int:
        return self.head_observation.observed_at_unix_ms

    @property
    def state_observed_at_unix_ms(self) -> int:
        return self.state_observation.observed_at_unix_ms

    @property
    def head_observation_sha256(self) -> str:
        return self.head_observation.digest

    @property
    def state_observation_sha256(self) -> str:
        return self.state_observation.digest

    def to_json_value(self) -> dict[str, str]:
        return {
            "chain": self.chain.value,
            "source_id": self.source_id,
            "finality": self.finality.value,
            "block_number": str(self.block_number),
            "block_hash": to_hex_data(self.block_hash),
            "state_root": to_hex_data(self.state_root),
            "head_source_sequence": str(self.head_source_sequence),
            "state_source_sequence": str(self.state_source_sequence),
            "head_observed_at_unix_ms": str(self.head_observed_at_unix_ms),
            "state_observed_at_unix_ms": str(self.state_observed_at_unix_ms),
            "head_observation_sha256": self.head_observation_sha256,
            "state_observation_sha256": self.state_observation_sha256,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class CanonicalStorageProof:
    key: bytes
    value: int
    proof_nodes: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if type(self.key) is not bytes or len(self.key) != 32:
            raise ValueError("storage proof key must be exact 32-byte data")
        if type(self.value) is not int or self.value < 0 or self.value.bit_length() > 256:
            raise ValueError("storage proof value must be an unsigned 256-bit integer")
        if type(self.proof_nodes) is not tuple or any(
            type(node) is not bytes for node in self.proof_nodes
        ):
            raise TypeError("storage proof nodes must be an exact tuple of bytes")
        if len(self.proof_nodes) > MAX_PROOF_NODES:
            raise ValueError("storage proof node count exceeds the governed ceiling")
        if any(
            not node or len(node) > MAX_PROOF_NODE_BYTES
            for node in self.proof_nodes
        ):
            raise ValueError("storage proof contains an empty or oversized node")
        if sum(len(node) for node in self.proof_nodes) > MAX_PROOF_TOTAL_BYTES:
            raise ValueError("storage proof exceeds the governed byte ceiling")

    def to_json_value(self) -> dict[str, object]:
        return {
            "key": to_hex_data(self.key),
            "value": str(self.value),
            "proof": [to_hex_data(node) for node in self.proof_nodes],
        }


@dataclass(frozen=True, slots=True)
class CanonicalStateProof:
    block_number: int
    block_hash: bytes
    state_root: bytes
    address: bytes
    nonce: int
    balance: int
    storage_root: bytes
    code_hash: bytes
    account_proof_nodes: tuple[bytes, ...]
    storage_proofs: tuple[CanonicalStorageProof, ...]

    def __post_init__(self) -> None:
        require_u64("block_number", self.block_number)
        _require_nonzero_hash("block_hash", self.block_hash)
        _require_nonzero_hash("state_root", self.state_root)
        if type(self.address) is not bytes or len(self.address) != 20:
            raise ValueError("address must be exact 20-byte data")
        for name, value in (("nonce", self.nonce), ("balance", self.balance)):
            if type(value) is not int or value < 0 or value.bit_length() > 256:
                raise ValueError(f"{name} must be an unsigned 256-bit integer")
        _require_nonzero_hash("storage_root", self.storage_root)
        _require_nonzero_hash("code_hash", self.code_hash)
        if type(self.account_proof_nodes) is not tuple or any(
            type(node) is not bytes for node in self.account_proof_nodes
        ):
            raise TypeError("account_proof_nodes must be an exact tuple of bytes")
        if len(self.account_proof_nodes) > MAX_PROOF_NODES:
            raise ValueError("account proof node count exceeds the governed ceiling")
        if any(
            not node or len(node) > MAX_PROOF_NODE_BYTES
            for node in self.account_proof_nodes
        ):
            raise ValueError("account proof contains an empty or oversized node")
        if type(self.storage_proofs) is not tuple or any(
            type(item) is not CanonicalStorageProof for item in self.storage_proofs
        ):
            raise TypeError(
                "storage_proofs must be an exact tuple of CanonicalStorageProof values"
            )
        if len(self.storage_proofs) > MAX_STORAGE_PROOFS:
            raise ValueError("storage_proofs exceeds the governed count ceiling")
        keys = [item.key for item in self.storage_proofs]
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            raise ValueError("storage_proofs must be unique and sorted by key")
        total_node_bytes = sum(len(node) for node in self.account_proof_nodes) + sum(
            len(node)
            for storage in self.storage_proofs
            for node in storage.proof_nodes
        )
        if total_node_bytes > MAX_STATE_PROOF_TOTAL_NODE_BYTES:
            raise ValueError("state proof exceeds the aggregate governed byte ceiling")

    @classmethod
    def from_payload(cls, payload: object) -> CanonicalStateProof:
        if type(payload) is not dict:
            raise ValueError("state-proof payload must be an exact JSON object")
        _require_exact_keys(
            "state-proof payload",
            payload,
            {
                "schema",
                "block_number",
                "block_hash",
                "state_root",
                "address",
                "nonce",
                "balance",
                "storage_root",
                "code_hash",
                "account_proof",
                "storage_proofs",
            },
        )
        if payload["schema"] != STATE_PROOF_PAYLOAD_SCHEMA:
            raise ValueError("unsupported state-proof payload schema")
        storage_raw = payload["storage_proofs"]
        if type(storage_raw) is not list:
            raise ValueError("storage_proofs must be an exact JSON array")
        if len(storage_raw) > MAX_STORAGE_PROOFS:
            raise ValueError("storage_proofs exceeds the governed count ceiling")
        storage: list[CanonicalStorageProof] = []
        for index, raw in enumerate(storage_raw):
            if type(raw) is not dict:
                raise ValueError(
                    f"storage_proofs[{index}] must be an exact JSON object"
                )
            _require_exact_keys(
                f"storage_proofs[{index}]",
                raw,
                {"key", "value", "proof"},
            )
            storage.append(
                CanonicalStorageProof(
                    key=parse_hex_data(
                        f"storage_proofs[{index}].key",
                        raw["key"],
                        exact_bytes=32,
                        maximum_bytes=32,
                    ),
                    value=parse_decimal_integer(
                        f"storage_proofs[{index}].value",
                        raw["value"],
                        maximum_bits=256,
                    ),
                    proof_nodes=_parse_proof_nodes(
                        f"storage_proofs[{index}].proof",
                        raw["proof"],
                    ),
                )
            )
        return cls(
            block_number=parse_decimal("block_number", payload["block_number"]),
            block_hash=_parse_hash("block_hash", payload["block_hash"]),
            state_root=_parse_hash("state_root", payload["state_root"]),
            address=parse_hex_data(
                "address", payload["address"], exact_bytes=20, maximum_bytes=20
            ),
            nonce=parse_decimal_integer("nonce", payload["nonce"], maximum_bits=256),
            balance=parse_decimal_integer(
                "balance", payload["balance"], maximum_bits=256
            ),
            storage_root=_parse_hash("storage_root", payload["storage_root"]),
            code_hash=_parse_hash("code_hash", payload["code_hash"]),
            account_proof_nodes=_parse_proof_nodes(
                "account_proof", payload["account_proof"]
            ),
            storage_proofs=tuple(storage),
        )
