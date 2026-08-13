from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import re
from typing import Any

from .canonical import canonical_sha256
from .domain import Chain, require_sha256
from .observation import ObservationEnvelope, parse_decimal, require_u64
from .source_contracts import (
    Finality,
    ObservationKind,
    Visibility,
    get_source_contract,
)

_HEX_HASH = re.compile(r"^0x[0-9a-f]{64}$")
ZERO_BLOCK_HASH = "0x" + "0" * 64
MAX_TRACKED_HEADS = 100_000


class HeadTransitionKind(StrEnum):
    BOOTSTRAP = "bootstrap"
    EXTEND = "extend"
    REORG = "reorg"
    DUPLICATE = "duplicate"
    ORPHAN = "orphan"


def _require_hash_or_none(name: str, value: object, *, allow_zero: bool) -> None:
    if value is None:
        return
    if type(value) is not str or _HEX_HASH.fullmatch(value) is None:
        raise ValueError(f"{name} must be a canonical block hash or null")
    if not allow_zero and value == ZERO_BLOCK_HASH:
        raise ValueError(f"{name} cannot be the zero block hash")


def _require_exact_keys(name: str, value: dict[str, Any], expected: set[str]) -> None:
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"{name} keys mismatch; missing={sorted(expected - actual)}, unknown={sorted(actual - expected)}"
        )


@dataclass(frozen=True, slots=True)
class EvmHead:
    chain: Chain
    source_id: str
    source_sequence: int
    number: int
    block_hash: str
    parent_hash: str
    block_timestamp_unix_s: int

    def __post_init__(self) -> None:
        if type(self.chain) is not Chain or self.chain is Chain.SOLANA:
            raise ValueError("EvmHead requires a governed EVM chain")
        contract = get_source_contract(self.source_id)
        if contract.chain is not self.chain:
            raise ValueError("EvmHead source contract does not match its chain")
        require_u64("source_sequence", self.source_sequence)
        require_u64("number", self.number)
        require_u64("block_timestamp_unix_s", self.block_timestamp_unix_s)
        if type(self.block_hash) is not str or _HEX_HASH.fullmatch(self.block_hash) is None:
            raise ValueError("block_hash must be canonical lowercase 32-byte hex")
        if type(self.parent_hash) is not str or _HEX_HASH.fullmatch(self.parent_hash) is None:
            raise ValueError("parent_hash must be canonical lowercase 32-byte hex")
        if self.block_hash == ZERO_BLOCK_HASH:
            raise ValueError("block_hash cannot be zero")
        if self.number == 0:
            if self.parent_hash != ZERO_BLOCK_HASH:
                raise ValueError("genesis block must have the zero parent hash")
        elif self.parent_hash == ZERO_BLOCK_HASH:
            raise ValueError("non-genesis block cannot have the zero parent hash")

    @classmethod
    def from_observation(cls, envelope: ObservationEnvelope) -> EvmHead:
        if type(envelope) is not ObservationEnvelope:
            raise TypeError("envelope must be an exact ObservationEnvelope")
        if envelope.kind not in {
            ObservationKind.BLOCK_HEAD,
            ObservationKind.PRECONFIRMED_BLOCK,
        }:
            raise ValueError("observation is not a governed block-head event")
        if envelope.visibility is not Visibility.FULL:
            raise ValueError("head observations require full visibility")
        payload = envelope.payload
        expected = {
            "block_number",
            "block_hash",
            "parent_hash",
            "block_timestamp_unix_s",
        }
        if set(payload) != expected:
            raise ValueError("block-head payload fields do not match the governed contract")
        return cls(
            chain=envelope.chain,
            source_id=envelope.source_id,
            source_sequence=envelope.source_sequence,
            number=parse_decimal("block_number", payload["block_number"]),
            block_hash=payload["block_hash"],
            parent_hash=payload["parent_hash"],
            block_timestamp_unix_s=parse_decimal(
                "block_timestamp_unix_s", payload["block_timestamp_unix_s"]
            ),
        )

    def same_block_metadata(self, other: EvmHead) -> bool:
        if type(other) is not EvmHead:
            return False
        return (
            self.chain is other.chain
            and self.source_id == other.source_id
            and self.number == other.number
            and self.block_hash == other.block_hash
            and self.parent_hash == other.parent_hash
            and self.block_timestamp_unix_s == other.block_timestamp_unix_s
        )


@dataclass(frozen=True, slots=True)
class HeadTransition:
    chain: Chain
    source_id: str
    source_sequence: int
    observation_kind: ObservationKind
    finality: Finality
    observation_sha256: str
    kind: HeadTransitionKind
    old_head: str | None
    new_head: str | None
    common_ancestor: str | None
    removed: tuple[str, ...]
    added: tuple[str, ...]

    SCHEMA = "aladdin-mev-head-transition/v1"

    def __post_init__(self) -> None:
        if type(self.chain) is not Chain or self.chain is Chain.SOLANA:
            raise ValueError("head transition requires a governed EVM chain")
        contract = get_source_contract(self.source_id)
        if contract.chain is not self.chain:
            raise ValueError("head transition source contract does not match its chain")
        require_u64("source_sequence", self.source_sequence)
        if type(self.observation_kind) is not ObservationKind or self.observation_kind not in {
            ObservationKind.BLOCK_HEAD,
            ObservationKind.PRECONFIRMED_BLOCK,
        }:
            raise ValueError("head transition observation_kind is not a governed head kind")
        if type(self.finality) is not Finality:
            raise TypeError("head transition finality must be an exact Finality")
        if not contract.permits(
            kind=self.observation_kind,
            finality=self.finality,
            visibility=Visibility.FULL,
        ):
            raise ValueError("head transition stream is not permitted by its source contract")
        require_sha256("observation_sha256", self.observation_sha256)
        if type(self.kind) is not HeadTransitionKind:
            raise TypeError("kind must be an exact HeadTransitionKind")
        _require_hash_or_none("old_head", self.old_head, allow_zero=False)
        _require_hash_or_none("new_head", self.new_head, allow_zero=False)
        _require_hash_or_none("common_ancestor", self.common_ancestor, allow_zero=True)
        for name, values in (("removed", self.removed), ("added", self.added)):
            if type(values) is not tuple or any(
                type(value) is not str
                or _HEX_HASH.fullmatch(value) is None
                or value == ZERO_BLOCK_HASH
                for value in values
            ):
                raise TypeError(f"{name} must be an exact tuple of non-zero canonical block hashes")
            if len(values) != len(set(values)):
                raise ValueError(f"{name} contains a duplicate block hash")
        if set(self.removed) & set(self.added):
            raise ValueError("removed and added paths must be disjoint")
        if self.common_ancestor in set(self.removed) | set(self.added):
            raise ValueError("common ancestor cannot appear in a transition path")

        if self.kind is HeadTransitionKind.BOOTSTRAP:
            if not (
                self.old_head is None
                and self.new_head is not None
                and self.common_ancestor is None
                and not self.removed
                and self.added == (self.new_head,)
            ):
                raise ValueError("bootstrap transition shape is invalid")
        elif self.kind is HeadTransitionKind.EXTEND:
            if not (
                self.old_head is not None
                and self.new_head is not None
                and self.old_head != self.new_head
                and self.common_ancestor == self.old_head
                and not self.removed
                and self.added == (self.new_head,)
            ):
                raise ValueError("extension transition shape is invalid")
        elif self.kind is HeadTransitionKind.REORG:
            if not (
                self.old_head is not None
                and self.new_head is not None
                and self.old_head != self.new_head
                and self.common_ancestor is not None
                and self.removed
                and self.added
                and self.removed[0] == self.old_head
                and self.added[-1] == self.new_head
            ):
                raise ValueError("reorg transition shape is invalid")
        elif self.kind is HeadTransitionKind.DUPLICATE:
            if not (
                self.old_head == self.new_head == self.common_ancestor
                and self.old_head is not None
                and not self.removed
                and not self.added
            ):
                raise ValueError("duplicate transition shape is invalid")
        elif self.kind is HeadTransitionKind.ORPHAN:
            if not (
                self.old_head == self.new_head
                and self.old_head is not None
                and self.common_ancestor is None
                and not self.removed
                and not self.added
            ):
                raise ValueError("orphan transition shape is invalid")

    def to_json_value(self) -> dict[str, Any]:
        return {
            "schema": self.SCHEMA,
            "chain": self.chain.value,
            "source_id": self.source_id,
            "source_sequence": str(self.source_sequence),
            "observation_kind": self.observation_kind.value,
            "finality": self.finality.value,
            "observation_sha256": self.observation_sha256,
            "kind": self.kind.value,
            "old_head": self.old_head,
            "new_head": self.new_head,
            "common_ancestor": self.common_ancestor,
            "removed": list(self.removed),
            "added": list(self.added),
        }

    @classmethod
    def from_json_value(cls, value: object) -> HeadTransition:
        if type(value) is not dict:
            raise ValueError("head transition must be an exact JSON object")
        _require_exact_keys(
            "head transition",
            value,
            {
                "schema",
                "chain",
                "source_id",
                "source_sequence",
                "observation_kind",
                "finality",
                "observation_sha256",
                "kind",
                "old_head",
                "new_head",
                "common_ancestor",
                "removed",
                "added",
            },
        )
        if value["schema"] != cls.SCHEMA:
            raise ValueError("unknown head transition schema")
        enum_fields = ("chain", "observation_kind", "finality", "kind")
        if any(type(value[field]) is not str for field in enum_fields):
            raise ValueError("head transition governed enums must be exact JSON strings")
        try:
            chain = Chain(value["chain"])
            observation_kind = ObservationKind(value["observation_kind"])
            finality = Finality(value["finality"])
            kind = HeadTransitionKind(value["kind"])
        except ValueError as error:
            raise ValueError("head transition contains an unknown governed enum") from error
        if type(value["removed"]) is not list or type(value["added"]) is not list:
            raise ValueError("head transition paths must be JSON arrays")
        return cls(
            chain=chain,
            source_id=value["source_id"],
            source_sequence=parse_decimal("source_sequence", value["source_sequence"]),
            observation_kind=observation_kind,
            finality=finality,
            observation_sha256=value["observation_sha256"],
            kind=kind,
            old_head=value["old_head"],
            new_head=value["new_head"],
            common_ancestor=value["common_ancestor"],
            removed=tuple(value["removed"]),
            added=tuple(value["added"]),
        )

    def verify_observation(self, envelope: ObservationEnvelope) -> None:
        if type(envelope) is not ObservationEnvelope:
            raise TypeError("envelope must be an exact ObservationEnvelope")
        if (
            envelope.chain is not self.chain
            or envelope.source_id != self.source_id
            or envelope.source_sequence != self.source_sequence
            or envelope.kind is not self.observation_kind
            or envelope.finality is not self.finality
            or envelope.visibility is not Visibility.FULL
            or envelope.digest != self.observation_sha256
        ):
            raise ValueError("head transition does not match its triggering observation")

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


class HeadTracker:
    def __init__(
        self,
        *,
        chain: Chain,
        source_id: str,
        observation_kind: ObservationKind,
        finality: Finality,
    ) -> None:
        if type(chain) is not Chain or chain is Chain.SOLANA:
            raise ValueError("HeadTracker requires a governed EVM chain")
        if type(observation_kind) is not ObservationKind or observation_kind not in {
            ObservationKind.BLOCK_HEAD,
            ObservationKind.PRECONFIRMED_BLOCK,
        }:
            raise ValueError("HeadTracker requires a governed block-head observation kind")
        if type(finality) is not Finality:
            raise TypeError("HeadTracker finality must be an exact Finality")
        contract = get_source_contract(source_id)
        if contract.chain is not chain:
            raise ValueError("head tracker source contract does not match its chain")
        if not contract.permits(
            kind=observation_kind,
            finality=finality,
            visibility=Visibility.FULL,
        ):
            raise ValueError("source contract does not provide the governed full head stream")
        self._chain = chain
        self._source_id = source_id
        self._observation_kind = observation_kind
        self._finality = finality
        self._nodes: dict[str, EvmHead] = {}
        self._current_hash: str | None = None
        self._last_sequence: int | None = None

    @property
    def current_head(self) -> EvmHead | None:
        return None if self._current_hash is None else self._nodes[self._current_hash]

    @property
    def tracked_head_count(self) -> int:
        return len(self._nodes)

    def _transition(
        self,
        *,
        envelope: ObservationEnvelope,
        kind: HeadTransitionKind,
        old_head: str | None,
        new_head: str | None,
        common_ancestor: str | None,
        removed: tuple[str, ...],
        added: tuple[str, ...],
    ) -> HeadTransition:
        return HeadTransition(
            chain=self._chain,
            source_id=self._source_id,
            source_sequence=envelope.source_sequence,
            observation_kind=self._observation_kind,
            finality=self._finality,
            observation_sha256=envelope.digest,
            kind=kind,
            old_head=old_head,
            new_head=new_head,
            common_ancestor=common_ancestor,
            removed=removed,
            added=added,
        )

    def apply(self, envelope: ObservationEnvelope) -> HeadTransition:
        if type(envelope) is not ObservationEnvelope:
            raise TypeError("envelope must be an exact ObservationEnvelope")
        if (
            envelope.chain is not self._chain
            or envelope.source_id != self._source_id
            or envelope.kind is not self._observation_kind
            or envelope.finality is not self._finality
            or envelope.visibility is not Visibility.FULL
        ):
            raise ValueError("head observation does not belong to this exact tracker stream")
        head = EvmHead.from_observation(envelope)
        if self._last_sequence is not None and head.source_sequence <= self._last_sequence:
            raise ValueError("head observation source sequence did not advance")

        old_hash = self._current_hash
        existing = self._nodes.get(head.block_hash)
        if existing is not None and not existing.same_block_metadata(head):
            raise ValueError("duplicate block hash carries conflicting block metadata")

        if old_hash is None:
            if existing is not None or self._nodes:
                raise RuntimeError("head tracker authority is internally inconsistent")
            transition = self._transition(
                envelope=envelope,
                kind=HeadTransitionKind.BOOTSTRAP,
                old_head=None,
                new_head=head.block_hash,
                common_ancestor=None,
                removed=(),
                added=(head.block_hash,),
            )
            self._nodes[head.block_hash] = head
            self._current_hash = head.block_hash
            self._last_sequence = head.source_sequence
            return transition

        if existing is not None and head.block_hash == old_hash:
            transition = self._transition(
                envelope=envelope,
                kind=HeadTransitionKind.DUPLICATE,
                old_head=old_hash,
                new_head=old_hash,
                common_ancestor=old_hash,
                removed=(),
                added=(),
            )
            self._nodes[head.block_hash] = head
            self._last_sequence = head.source_sequence
            return transition

        if existing is None and len(self._nodes) >= MAX_TRACKED_HEADS:
            raise ValueError("head tracker node ceiling exceeded")

        parent = self._nodes.get(head.parent_hash) if head.number > 0 else None
        if parent is not None:
            if parent.number + 1 != head.number:
                raise ValueError("head number is inconsistent with its known parent")
            if head.block_timestamp_unix_s < parent.block_timestamp_unix_s:
                raise ValueError("head timestamp moved backwards from its known parent")

        if head.parent_hash == old_hash:
            current = self._nodes[old_hash]
            if head.number != current.number + 1:
                raise ValueError("head extension number is not contiguous")
            if head.block_timestamp_unix_s < current.block_timestamp_unix_s:
                raise ValueError("head extension timestamp moved backwards")
            transition = self._transition(
                envelope=envelope,
                kind=HeadTransitionKind.EXTEND,
                old_head=old_hash,
                new_head=head.block_hash,
                common_ancestor=old_hash,
                removed=(),
                added=(head.block_hash,),
            )
            self._nodes[head.block_hash] = head
            self._current_hash = head.block_hash
            self._last_sequence = head.source_sequence
            return transition

        paths = self._paths_to_common_ancestor(old_hash, head)
        if paths is None:
            transition = self._transition(
                envelope=envelope,
                kind=HeadTransitionKind.ORPHAN,
                old_head=old_hash,
                new_head=old_hash,
                common_ancestor=None,
                removed=(),
                added=(),
            )
            # The filtered stream advances, but an unauthenticated topology fragment is
            # not retained. A later observation may retry the same block after its parent
            # has become known.
            self._last_sequence = head.source_sequence
            return transition

        ancestor, removed, added = paths
        transition = self._transition(
            envelope=envelope,
            kind=HeadTransitionKind.REORG,
            old_head=old_hash,
            new_head=head.block_hash,
            common_ancestor=ancestor,
            removed=removed,
            added=added,
        )
        self._nodes[head.block_hash] = head
        self._current_hash = head.block_hash
        self._last_sequence = head.source_sequence
        return transition

    def _node_for_candidate(self, block_hash: str, candidate: EvmHead) -> EvmHead | None:
        if block_hash == candidate.block_hash:
            return candidate
        return self._nodes.get(block_hash)

    def _paths_to_common_ancestor(
        self, old_hash: str, candidate: EvmHead
    ) -> tuple[str, tuple[str, ...], tuple[str, ...]] | None:
        old_path: list[str] = []
        cursor = old_hash
        old_positions: dict[str, int] = {}
        while cursor in self._nodes and cursor not in old_positions:
            old_positions[cursor] = len(old_path)
            old_path.append(cursor)
            parent = self._nodes[cursor].parent_hash
            if parent == ZERO_BLOCK_HASH:
                old_positions[parent] = len(old_path)
                break
            cursor = parent

        new_path: list[str] = []
        cursor = candidate.block_hash
        visited: set[str] = set()
        while cursor not in visited:
            if cursor in old_positions:
                ancestor = cursor
                removed = tuple(old_path[: old_positions[cursor]])
                added = tuple(reversed(new_path))
                return ancestor, removed, added
            visited.add(cursor)
            node = self._node_for_candidate(cursor, candidate)
            if node is None:
                return None
            new_path.append(cursor)
            if node.parent_hash == ZERO_BLOCK_HASH:
                if ZERO_BLOCK_HASH in old_positions:
                    return ZERO_BLOCK_HASH, tuple(old_path), tuple(reversed(new_path))
                return None
            cursor = node.parent_hash
        return None
