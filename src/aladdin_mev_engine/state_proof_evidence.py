from __future__ import annotations

from dataclasses import dataclass, field

from .canonical import canonical_json_bytes, canonical_sha256
from .domain import Chain, require_sha256
from .evm_hex import to_decimal, to_hex_data
from .keccak import keccak256
from .mpt import EMPTY_TRIE_ROOT, FOUND_TERMINALS, MptTerminal, verify_mpt_proof
from .observation import ObservationEnvelope
from .rlp import require_rlp_bytes, require_rlp_list, rlp_decode, rlp_decode_uint
from .source_contracts import Finality, ObservationKind, SourceKind, Visibility
from .state_proof_types import (
    EMPTY_CODE_HASH,
    MAX_SNAPSHOT_ACCOUNTS,
    STATE_PROOF_EVIDENCE_SCHEMA,
    STATE_SNAPSHOT_SCHEMA,
    CanonicalStateProof,
    EvmBlockStateAnchor,
    _require_nonzero_hash,
)


@dataclass(frozen=True, slots=True)
class VerifiedStorageValue:
    key: bytes
    value: int
    included: bool
    terminal: MptTerminal
    used_node_hashes: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.key) is not bytes or len(self.key) != 32:
            raise ValueError("verified storage key must be exact 32-byte data")
        if type(self.value) is not int or self.value < 0 or self.value.bit_length() > 256:
            raise ValueError("verified storage value must be an unsigned 256-bit integer")
        if type(self.included) is not bool:
            raise TypeError("included must be an exact bool")
        if type(self.terminal) is not MptTerminal:
            raise TypeError("terminal must be an exact MptTerminal")
        if self.included != (self.terminal in FOUND_TERMINALS):
            raise ValueError("included/terminal state is inconsistent")
        if type(self.used_node_hashes) is not tuple:
            raise TypeError("used_node_hashes must be an exact tuple")
        for digest in self.used_node_hashes:
            require_sha256("used_node_hash", digest)
        if len(self.used_node_hashes) != len(set(self.used_node_hashes)):
            raise ValueError("used_node_hashes contains a duplicate")
        if self.terminal is MptTerminal.ABSENT_EMPTY_TRIE:
            if self.used_node_hashes:
                raise ValueError("empty-trie storage evidence cannot use nodes")
        elif not self.used_node_hashes:
            raise ValueError("non-empty storage proof must authenticate its root node")
        if self.included and self.value == 0:
            raise ValueError("included Ethereum storage value cannot be zero")
        if not self.included and self.value != 0:
            raise ValueError("absent Ethereum storage value must be zero")

    def to_json_value(self) -> dict[str, object]:
        return {
            "key": to_hex_data(self.key),
            "value": str(self.value),
            "included": self.included,
            "terminal": self.terminal.value,
            "used_node_hashes": list(self.used_node_hashes),
        }


@dataclass(frozen=True, slots=True)
class _VerifiedProofData:
    proof: CanonicalStateProof
    account_exists: bool
    account_terminal: MptTerminal
    account_used_node_hashes: tuple[str, ...]
    storage_values: tuple[VerifiedStorageValue, ...]


def _verify_proof_data(
    anchor: EvmBlockStateAnchor,
    proof_observation: ObservationEnvelope,
) -> _VerifiedProofData:
    if type(anchor) is not EvmBlockStateAnchor:
        raise TypeError("anchor must be an exact EvmBlockStateAnchor")
    if type(proof_observation) is not ObservationEnvelope:
        raise TypeError("proof_observation must be an exact ObservationEnvelope")
    if proof_observation.kind is not ObservationKind.EVM_STATE_PROOF:
        raise ValueError("observation is not a governed EVM state proof")
    if proof_observation.visibility is not Visibility.FULL:
        raise ValueError("state proof requires full visibility")
    if proof_observation.chain is not anchor.chain:
        raise ValueError("state proof chain does not match its anchor")
    if proof_observation.source_id != anchor.source_id:
        raise ValueError("state proof source does not match its anchor")
    if proof_observation.source_kind is not SourceKind.EVM_JSON_RPC:
        raise ValueError("state proof requires an EVM JSON-RPC source")
    if proof_observation.finality is not anchor.finality:
        raise ValueError("state proof finality does not match its anchor")
    if proof_observation.source_sequence <= anchor.state_source_sequence:
        raise ValueError("state proof must follow its block-state observation")
    if proof_observation.observed_at_unix_ms < anchor.state_observed_at_unix_ms:
        raise ValueError("state proof observation time precedes its block-state anchor")

    proof = CanonicalStateProof.from_payload(proof_observation.payload)
    if (
        proof.block_number != anchor.block_number
        or proof.block_hash != anchor.block_hash
        or proof.state_root != anchor.state_root
    ):
        raise ValueError("state proof does not bind the exact block-state anchor")

    account_result = verify_mpt_proof(
        root_hash=anchor.state_root,
        key=keccak256(proof.address),
        proof_nodes=proof.account_proof_nodes,
    )
    if account_result.found:
        if account_result.value is None:
            raise RuntimeError("account proof result lost its value")
        account = require_rlp_list(
            "Ethereum account",
            rlp_decode(account_result.value),
            length=4,
        )
        encoded_nonce = require_rlp_bytes("account nonce", account[0])
        encoded_balance = require_rlp_bytes("account balance", account[1])
        encoded_storage_root = require_rlp_bytes("account storage root", account[2])
        encoded_code_hash = require_rlp_bytes("account code hash", account[3])
        nonce = rlp_decode_uint(encoded_nonce, maximum_bits=256)
        balance = rlp_decode_uint(encoded_balance, maximum_bits=256)
        _require_nonzero_hash("authenticated account storage root", encoded_storage_root)
        _require_nonzero_hash("authenticated account code hash", encoded_code_hash)
        if (
            nonce != proof.nonce
            or balance != proof.balance
            or encoded_storage_root != proof.storage_root
            or encoded_code_hash != proof.code_hash
        ):
            raise ValueError(
                "EIP-1186 account fields disagree with the authenticated leaf"
            )
        account_exists = True
    else:
        if (
            proof.nonce != 0
            or proof.balance != 0
            or proof.storage_root != EMPTY_TRIE_ROOT
            or proof.code_hash != EMPTY_CODE_HASH
        ):
            raise ValueError("absent account carries non-empty EIP-1186 fields")
        account_exists = False

    verified_storage: list[VerifiedStorageValue] = []
    for storage in proof.storage_proofs:
        result = verify_mpt_proof(
            root_hash=proof.storage_root,
            key=keccak256(storage.key),
            proof_nodes=storage.proof_nodes,
        )
        if result.found:
            if result.value is None:
                raise RuntimeError("storage proof result lost its value")
            encoded_scalar = require_rlp_bytes(
                "storage scalar",
                rlp_decode(result.value),
            )
            authenticated_value = rlp_decode_uint(encoded_scalar, maximum_bits=256)
            if authenticated_value == 0:
                raise ValueError("Ethereum storage trie must not include a zero scalar")
            if authenticated_value != storage.value:
                raise ValueError("storage value disagrees with its authenticated leaf")
            included = True
        else:
            if storage.value != 0:
                raise ValueError("absent storage slot carries a non-zero value")
            authenticated_value = 0
            included = False
        verified_storage.append(
            VerifiedStorageValue(
                key=storage.key,
                value=authenticated_value,
                included=included,
                terminal=result.terminal,
                used_node_hashes=result.used_node_hashes,
            )
        )

    return _VerifiedProofData(
        proof=proof,
        account_exists=account_exists,
        account_terminal=account_result.terminal,
        account_used_node_hashes=account_result.used_node_hashes,
        storage_values=tuple(verified_storage),
    )


@dataclass(frozen=True, slots=True)
class EvmStateProofEvidence:
    """Proof-derived evidence that always recomputes from its exact bound inputs."""

    anchor: EvmBlockStateAnchor
    proof_observation: ObservationEnvelope
    schema: str = STATE_PROOF_EVIDENCE_SCHEMA
    _verified: _VerifiedProofData = field(init=False, repr=False, compare=True)

    def __post_init__(self) -> None:
        if self.schema != STATE_PROOF_EVIDENCE_SCHEMA:
            raise ValueError("unsupported state-proof evidence schema")
        verified = _verify_proof_data(self.anchor, self.proof_observation)
        object.__setattr__(self, "_verified", verified)
        canonical_json_bytes(self.to_json_value())

    @classmethod
    def verify(
        cls,
        anchor: EvmBlockStateAnchor,
        proof_observation: ObservationEnvelope,
    ) -> EvmStateProofEvidence:
        return cls(anchor=anchor, proof_observation=proof_observation)

    @property
    def chain(self) -> Chain:
        return self.anchor.chain

    @property
    def source_id(self) -> str:
        return self.anchor.source_id

    @property
    def finality(self) -> Finality:
        return self.anchor.finality

    @property
    def block_number(self) -> int:
        return self.anchor.block_number

    @property
    def block_hash(self) -> bytes:
        return self.anchor.block_hash

    @property
    def state_root(self) -> bytes:
        return self.anchor.state_root

    @property
    def address(self) -> bytes:
        return self._verified.proof.address

    @property
    def account_exists(self) -> bool:
        return self._verified.account_exists

    @property
    def nonce(self) -> int:
        return self._verified.proof.nonce

    @property
    def balance(self) -> int:
        return self._verified.proof.balance

    @property
    def storage_root(self) -> bytes:
        return self._verified.proof.storage_root

    @property
    def code_hash(self) -> bytes:
        return self._verified.proof.code_hash

    @property
    def account_terminal(self) -> MptTerminal:
        return self._verified.account_terminal

    @property
    def account_used_node_hashes(self) -> tuple[str, ...]:
        return self._verified.account_used_node_hashes

    @property
    def storage_values(self) -> tuple[VerifiedStorageValue, ...]:
        return self._verified.storage_values

    @property
    def anchor_sha256(self) -> str:
        return self.anchor.digest

    @property
    def proof_observation_sha256(self) -> str:
        return self.proof_observation.digest

    @property
    def proof_source_sequence(self) -> int:
        return self.proof_observation.source_sequence

    @property
    def proof_observed_at_unix_ms(self) -> int:
        return self.proof_observation.observed_at_unix_ms

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "chain": self.chain.value,
            "source_id": self.source_id,
            "finality": self.finality.value,
            "block_number": str(self.block_number),
            "block_hash": to_hex_data(self.block_hash),
            "state_root": to_hex_data(self.state_root),
            "address": to_hex_data(self.address),
            "account_exists": self.account_exists,
            "nonce": to_decimal(self.nonce),
            "balance": to_decimal(self.balance),
            "storage_root": to_hex_data(self.storage_root),
            "code_hash": to_hex_data(self.code_hash),
            "account_terminal": self.account_terminal.value,
            "account_used_node_hashes": list(self.account_used_node_hashes),
            "storage_values": [item.to_json_value() for item in self.storage_values],
            "anchor_sha256": self.anchor_sha256,
            "proof_observation_sha256": self.proof_observation_sha256,
            "proof_source_sequence": str(self.proof_source_sequence),
            "proof_observed_at_unix_ms": str(self.proof_observed_at_unix_ms),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class EvmStateSnapshot:
    anchor: EvmBlockStateAnchor
    accounts: tuple[EvmStateProofEvidence, ...]
    schema: str = STATE_SNAPSHOT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != STATE_SNAPSHOT_SCHEMA:
            raise ValueError("unsupported state snapshot schema")
        if type(self.anchor) is not EvmBlockStateAnchor:
            raise TypeError("anchor must be an exact EvmBlockStateAnchor")
        if type(self.accounts) is not tuple or not self.accounts:
            raise TypeError("accounts must be a non-empty exact tuple")
        if len(self.accounts) > MAX_SNAPSHOT_ACCOUNTS:
            raise ValueError("state snapshot account count exceeds the governed ceiling")
        if any(type(item) is not EvmStateProofEvidence for item in self.accounts):
            raise TypeError("accounts contains an ungoverned evidence value")
        addresses = [item.address for item in self.accounts]
        if addresses != sorted(addresses) or len(addresses) != len(set(addresses)):
            raise ValueError("snapshot accounts must be unique and sorted by address")
        proof_ids = [item.proof_observation_sha256 for item in self.accounts]
        if len(proof_ids) != len(set(proof_ids)):
            raise ValueError("snapshot accounts reuse a proof observation identity")
        for item in self.accounts:
            if item.anchor.digest != self.anchor.digest:
                raise ValueError("snapshot account evidence does not bind its exact anchor")
        canonical_json_bytes(self.to_json_value())

    @classmethod
    def create(
        cls,
        anchor: EvmBlockStateAnchor,
        accounts: tuple[EvmStateProofEvidence, ...],
    ) -> EvmStateSnapshot:
        return cls(anchor=anchor, accounts=accounts)

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "anchor": self.anchor.to_json_value(),
            "anchor_sha256": self.anchor.digest,
            "accounts": [item.to_json_value() for item in self.accounts],
            "account_evidence_sha256": [item.digest for item in self.accounts],
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())
