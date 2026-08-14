from __future__ import annotations

from dataclasses import dataclass

from aladdin_mev_engine.constant_product import (
    AuthenticatedConstantProductPool,
    ConstantProductImplementationSpec,
    ConstantProductModelRegistry,
    ConstantProductPoolSpec,
    PackedStorageField,
    PoolUniverse,
)
from aladdin_mev_engine.domain import Chain
from aladdin_mev_engine.evm_hex import to_hex_data
from aladdin_mev_engine.keccak import keccak256
from aladdin_mev_engine.mpt import bytes_to_nibbles, hex_prefix_encode
from aladdin_mev_engine.observation import ObservationEnvelope
from aladdin_mev_engine.rlp import rlp_encode
from aladdin_mev_engine.source_contracts import Finality, ObservationKind, Visibility
from aladdin_mev_engine.state_proof import (
    BLOCK_STATE_PAYLOAD_SCHEMA,
    STATE_PROOF_PAYLOAD_SCHEMA,
    EvmBlockStateAnchor,
    EvmStateProofEvidence,
    EvmStateSnapshot,
)

TOKEN0_SLOT = (1).to_bytes(32, "big")
TOKEN1_SLOT = (2).to_bytes(32, "big")
RESERVES_SLOT = (3).to_bytes(32, "big")
TOKEN_A = bytes.fromhex("11" * 20)
TOKEN_B = bytes.fromhex("22" * 20)
TOKEN_C = bytes.fromhex("33" * 20)
TOKEN_D = bytes.fromhex("44" * 20)
SYNTHETIC_CODE_HASH = keccak256(b"f3-synthetic-direct-cp-runtime-v1")


def uint_bytes(value: int) -> bytes:
    if type(value) is not int or isinstance(value, bool) or value < 0:
        raise ValueError("uint fixture value must be a non-negative exact integer")
    return b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")


@dataclass(frozen=True, slots=True)
class TrieMaterial:
    root_hash: bytes
    proofs: dict[bytes, tuple[bytes, ...]]


def branch_trie(entries: tuple[tuple[bytes, bytes], ...]) -> TrieMaterial:
    """Build a deterministic one-branch trie for keys with unique first nibbles."""

    if type(entries) is not tuple or not entries:
        raise TypeError("trie entries must be a non-empty exact tuple")
    branch: list[object] = [b""] * 17
    encoded_by_key: dict[bytes, bytes] = {}
    embedded_by_key: dict[bytes, bool] = {}
    first_nibbles: set[int] = set()
    for key, value in entries:
        if type(key) is not bytes or len(key) != 32 or type(value) is not bytes:
            raise ValueError("trie fixture entries require exact 32-byte keys and byte values")
        nibbles = bytes_to_nibbles(key)
        first = nibbles[0]
        if first in first_nibbles:
            raise ValueError("fixture trie keys collide in their first nibble")
        first_nibbles.add(first)
        leaf = (hex_prefix_encode(nibbles[1:], is_leaf=True), value)
        encoded = rlp_encode(leaf)
        embedded = len(encoded) < 32
        branch[first] = leaf if embedded else keccak256(encoded)
        encoded_by_key[key] = encoded
        embedded_by_key[key] = embedded
    root = rlp_encode(tuple(branch))
    proofs = {
        key: (root,) if embedded_by_key[key] else (root, encoded_by_key[key])
        for key in encoded_by_key
    }
    return TrieMaterial(root_hash=keccak256(root), proofs=proofs)


@dataclass(frozen=True, slots=True)
class PoolFixture:
    address: bytes
    token0: bytes
    token1: bytes
    reserve0: int
    reserve1: int
    storage_root: bytes
    storage_proofs: dict[bytes, tuple[bytes, ...]]
    account_value: bytes


def pool_fixture(
    *,
    address_byte: int,
    token0: bytes,
    token1: bytes,
    reserve0: int,
    reserve1: int,
) -> PoolFixture:
    if not 1 <= address_byte <= 6:
        raise ValueError("address_byte is outside the governed fixture range")
    address = bytes((address_byte,)) * 20
    packed_reserves = reserve0 | (reserve1 << 112)
    slot_values = {
        TOKEN0_SLOT: int.from_bytes(token0, "big"),
        TOKEN1_SLOT: int.from_bytes(token1, "big"),
        RESERVES_SLOT: packed_reserves,
    }
    storage_entries = tuple(
        (keccak256(slot), rlp_encode(uint_bytes(value)))
        for slot, value in sorted(slot_values.items())
    )
    material = branch_trie(storage_entries)
    proof_by_slot = {
        slot: material.proofs[keccak256(slot)]
        for slot in sorted(slot_values)
    }
    account_value = rlp_encode(
        (
            uint_bytes(1),
            uint_bytes(0),
            material.root_hash,
            SYNTHETIC_CODE_HASH,
        )
    )
    return PoolFixture(
        address=address,
        token0=token0,
        token1=token1,
        reserve0=reserve0,
        reserve1=reserve1,
        storage_root=material.root_hash,
        storage_proofs=proof_by_slot,
        account_value=account_value,
    )


def implementation_spec(
    *,
    fee_numerator: int = 997,
    fee_denominator: int = 1000,
) -> ConstantProductImplementationSpec:
    return ConstantProductImplementationSpec(
        implementation_id=f"synthetic-cp-{fee_numerator}-{fee_denominator}",
        code_hash=SYNTHETIC_CODE_HASH,
        token0_field=PackedStorageField(TOKEN0_SLOT, 0, 160),
        token1_field=PackedStorageField(TOKEN1_SLOT, 0, 160),
        reserve0_field=PackedStorageField(RESERVES_SLOT, 0, 112),
        reserve1_field=PackedStorageField(RESERVES_SLOT, 112, 112),
        fee_numerator=fee_numerator,
        fee_denominator=fee_denominator,
    )


def _head_observation(
    *,
    source_id: str,
    finality: Finality,
    block_number: int,
    block_hash: bytes,
) -> ObservationEnvelope:
    return ObservationEnvelope.create(
        source_id=source_id,
        source_sequence=10,
        source_event_id="f3-head",
        observed_at_unix_ms=1_800_000_000_000,
        emitted_at_unix_ms=1_800_000_000_000,
        kind=ObservationKind.BLOCK_HEAD,
        finality=finality,
        visibility=Visibility.FULL,
        payload={
            "block_number": str(block_number),
            "block_hash": to_hex_data(block_hash),
            "parent_hash": "0x" + "cd" * 32,
            "block_timestamp_unix_s": "1800000000",
        },
    )


def _state_observation(
    *,
    source_id: str,
    finality: Finality,
    block_number: int,
    block_hash: bytes,
    state_root: bytes,
) -> ObservationEnvelope:
    return ObservationEnvelope.create(
        source_id=source_id,
        source_sequence=11,
        source_event_id="f3-state",
        observed_at_unix_ms=1_800_000_000_010,
        emitted_at_unix_ms=1_800_000_000_010,
        kind=ObservationKind.EVM_BLOCK_STATE,
        finality=finality,
        visibility=Visibility.FULL,
        payload={
            "schema": BLOCK_STATE_PAYLOAD_SCHEMA,
            "block_number": str(block_number),
            "block_hash": to_hex_data(block_hash),
            "state_root": to_hex_data(state_root),
        },
    )


def _proof_observation(
    fixture: PoolFixture,
    *,
    state_root: bytes,
    account_proof: tuple[bytes, ...],
    source_id: str,
    finality: Finality,
    block_number: int,
    block_hash: bytes,
    source_sequence: int,
) -> ObservationEnvelope:
    slot_values = {
        TOKEN0_SLOT: int.from_bytes(fixture.token0, "big"),
        TOKEN1_SLOT: int.from_bytes(fixture.token1, "big"),
        RESERVES_SLOT: fixture.reserve0 | (fixture.reserve1 << 112),
    }
    return ObservationEnvelope.create(
        source_id=source_id,
        source_sequence=source_sequence,
        source_event_id=f"f3-proof-{fixture.address.hex()}",
        observed_at_unix_ms=1_800_000_000_020 + source_sequence,
        emitted_at_unix_ms=1_800_000_000_020 + source_sequence,
        kind=ObservationKind.EVM_STATE_PROOF,
        finality=finality,
        visibility=Visibility.FULL,
        payload={
            "schema": STATE_PROOF_PAYLOAD_SCHEMA,
            "block_number": str(block_number),
            "block_hash": to_hex_data(block_hash),
            "state_root": to_hex_data(state_root),
            "address": to_hex_data(fixture.address),
            "nonce": "1",
            "balance": "0",
            "storage_root": to_hex_data(fixture.storage_root),
            "code_hash": to_hex_data(SYNTHETIC_CODE_HASH),
            "account_proof": [to_hex_data(node) for node in account_proof],
            "storage_proofs": [
                {
                    "key": to_hex_data(slot),
                    "value": str(slot_values[slot]),
                    "proof": [
                        to_hex_data(node)
                        for node in fixture.storage_proofs[slot]
                    ],
                }
                for slot in sorted(slot_values)
            ],
        },
    )


def authenticated_universe(
    fixtures: tuple[PoolFixture, ...],
    *,
    implementation: ConstantProductImplementationSpec | None = None,
    source_id: str = "ethereum-json-rpc",
    finality: Finality = Finality.CONFIRMED,
) -> PoolUniverse:
    if type(fixtures) is not tuple or not fixtures:
        raise TypeError("pool fixtures must be a non-empty exact tuple")
    ordered = tuple(sorted(fixtures, key=lambda item: item.address))
    state_entries = tuple(
        (keccak256(item.address), item.account_value)
        for item in ordered
    )
    state_material = branch_trie(state_entries)
    block_number = 19_000_003
    block_hash = bytes.fromhex("ab" * 32)
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
    evidences = []
    for index, item in enumerate(ordered):
        observation = _proof_observation(
            item,
            state_root=state_material.root_hash,
            account_proof=state_material.proofs[keccak256(item.address)],
            source_id=source_id,
            finality=finality,
            block_number=block_number,
            block_hash=block_hash,
            source_sequence=12 + index,
        )
        evidences.append(EvmStateProofEvidence.verify(anchor, observation))
    snapshot = EvmStateSnapshot.create(anchor, tuple(evidences))
    model = implementation_spec() if implementation is None else implementation
    registry = ConstantProductModelRegistry(
        registry_id="f3-synthetic-model-registry",
        implementations=(model,),
    )
    pools = tuple(
        AuthenticatedConstantProductPool(
            ConstantProductPoolSpec(
                spec_id=f"synthetic-pool-{index + 1}",
                chain=anchor.chain,
                pool_address=item.address,
                token0=item.token0,
                token1=item.token1,
                implementation=model,
            ),
            evidence,
        )
        for index, (item, evidence) in enumerate(zip(ordered, evidences))
    )
    return PoolUniverse(
        snapshot=snapshot,
        model_registry=registry,
        pools=pools,
    )
