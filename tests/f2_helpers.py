from __future__ import annotations

from dataclasses import dataclass

from aladdin_mev_engine.evm_hex import to_hex_data
from aladdin_mev_engine.keccak import keccak256
from aladdin_mev_engine.mpt import EMPTY_TRIE_ROOT, bytes_to_nibbles, hex_prefix_encode
from aladdin_mev_engine.observation import ObservationEnvelope
from aladdin_mev_engine.rlp import rlp_encode
from aladdin_mev_engine.source_contracts import Finality, ObservationKind, Visibility
from aladdin_mev_engine.state_proof import (
    BLOCK_STATE_PAYLOAD_SCHEMA,
    EMPTY_CODE_HASH,
    STATE_PROOF_PAYLOAD_SCHEMA,
)


def uint_bytes(value: int) -> bytes:
    return b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")


def single_leaf_trie(key: bytes, value: bytes) -> tuple[bytes, bytes]:
    node = rlp_encode(
        (
            hex_prefix_encode(bytes_to_nibbles(key), is_leaf=True),
            value,
        )
    )
    return keccak256(node), node


@dataclass(frozen=True)
class ProofFixture:
    source_id: str
    finality: Finality
    block_number: int
    block_hash: bytes
    address: bytes
    storage_key: bytes
    storage_value: int
    nonce: int
    balance: int
    code_hash: bytes
    storage_root: bytes
    state_root: bytes
    account_node: bytes
    storage_node: bytes


def proof_fixture(
    *,
    source_id: str = "ethereum-json-rpc",
    finality: Finality = Finality.CONFIRMED,
    storage_value: int = 42,
) -> ProofFixture:
    block_hash = bytes.fromhex("ab" * 32)
    address = bytes.fromhex("12" * 20)
    storage_key = bytes.fromhex("00" * 31 + "01")
    nonce = 7
    balance = 10**21
    code_hash = keccak256(b"fixture-contract")
    storage_scalar = rlp_encode(uint_bytes(storage_value))
    storage_root, storage_node = single_leaf_trie(keccak256(storage_key), storage_scalar)
    account_value = rlp_encode(
        (
            uint_bytes(nonce),
            uint_bytes(balance),
            storage_root,
            code_hash,
        )
    )
    state_root, account_node = single_leaf_trie(keccak256(address), account_value)
    return ProofFixture(
        source_id=source_id,
        finality=finality,
        block_number=19_000_001,
        block_hash=block_hash,
        address=address,
        storage_key=storage_key,
        storage_value=storage_value,
        nonce=nonce,
        balance=balance,
        code_hash=code_hash,
        storage_root=storage_root,
        state_root=state_root,
        account_node=account_node,
        storage_node=storage_node,
    )


def head_observation(fixture: ProofFixture, *, sequence: int = 10) -> ObservationEnvelope:
    return ObservationEnvelope.create(
        source_id=fixture.source_id,
        source_sequence=sequence,
        source_event_id="head-19000001",
        observed_at_unix_ms=1_800_000_000_000,
        emitted_at_unix_ms=1_800_000_000_000,
        kind=ObservationKind.BLOCK_HEAD,
        finality=fixture.finality,
        visibility=Visibility.FULL,
        payload={
            "block_number": str(fixture.block_number),
            "block_hash": to_hex_data(fixture.block_hash),
            "parent_hash": "0x" + "cd" * 32,
            "block_timestamp_unix_s": "1800000000",
        },
    )


def state_observation(fixture: ProofFixture, *, sequence: int = 11) -> ObservationEnvelope:
    return ObservationEnvelope.create(
        source_id=fixture.source_id,
        source_sequence=sequence,
        source_event_id="state-19000001",
        observed_at_unix_ms=1_800_000_000_010,
        emitted_at_unix_ms=1_800_000_000_010,
        kind=ObservationKind.EVM_BLOCK_STATE,
        finality=fixture.finality,
        visibility=Visibility.FULL,
        payload={
            "schema": BLOCK_STATE_PAYLOAD_SCHEMA,
            "block_number": str(fixture.block_number),
            "block_hash": to_hex_data(fixture.block_hash),
            "state_root": to_hex_data(fixture.state_root),
        },
    )


def proof_payload(fixture: ProofFixture) -> dict[str, object]:
    return {
        "schema": STATE_PROOF_PAYLOAD_SCHEMA,
        "block_number": str(fixture.block_number),
        "block_hash": to_hex_data(fixture.block_hash),
        "state_root": to_hex_data(fixture.state_root),
        "address": to_hex_data(fixture.address),
        "nonce": str(fixture.nonce),
        "balance": str(fixture.balance),
        "storage_root": to_hex_data(fixture.storage_root),
        "code_hash": to_hex_data(fixture.code_hash),
        "account_proof": [to_hex_data(fixture.account_node)],
        "storage_proofs": [
            {
                "key": to_hex_data(fixture.storage_key),
                "value": str(fixture.storage_value),
                "proof": [to_hex_data(fixture.storage_node)],
            }
        ],
    }


def proof_observation(
    fixture: ProofFixture,
    *,
    sequence: int = 12,
    payload: dict[str, object] | None = None,
) -> ObservationEnvelope:
    return ObservationEnvelope.create(
        source_id=fixture.source_id,
        source_sequence=sequence,
        source_event_id="proof-19000001",
        observed_at_unix_ms=1_800_000_000_020,
        emitted_at_unix_ms=1_800_000_000_020,
        kind=ObservationKind.EVM_STATE_PROOF,
        finality=fixture.finality,
        visibility=Visibility.FULL,
        payload=proof_payload(fixture) if payload is None else payload,
    )


def empty_account_payload(
    *,
    block_number: int,
    block_hash: bytes,
    address: bytes,
    storage_key: bytes,
) -> dict[str, object]:
    return {
        "schema": STATE_PROOF_PAYLOAD_SCHEMA,
        "block_number": str(block_number),
        "block_hash": to_hex_data(block_hash),
        "state_root": to_hex_data(EMPTY_TRIE_ROOT),
        "address": to_hex_data(address),
        "nonce": "0",
        "balance": "0",
        "storage_root": to_hex_data(EMPTY_TRIE_ROOT),
        "code_hash": to_hex_data(EMPTY_CODE_HASH),
        "account_proof": [],
        "storage_proofs": [
            {
                "key": to_hex_data(storage_key),
                "value": "0",
                "proof": [],
            }
        ],
    }
