from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import re
from types import MappingProxyType
from typing import Mapping

from .canonical import DEFAULT_MAX_JSON_BYTES, canonical_sha256
from .domain import Chain, require_bounded_text

_SOURCE_ID = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,78}[a-z0-9])?$")
MAX_SOURCE_CONTRACT_EVENTS = 16


class SourceKind(StrEnum):
    EVM_JSON_RPC = "evm-json-rpc"
    FLASHBOTS_MEV_SHARE = "flashbots-mev-share"
    BASE_FLASHBLOCKS = "base-flashblocks"
    ARBITRUM_SEQUENCER_FEED = "arbitrum-sequencer-feed"
    ARBITRUM_TIMEBOOST_AUCTION = "arbitrum-timeboost-auction"
    BSC_PBS_METADATA = "bsc-pbs-metadata"


class Transport(StrEnum):
    JSON_RPC_HTTP = "json-rpc-http"
    JSON_RPC_WEBSOCKET = "json-rpc-websocket"
    SERVER_SENT_EVENTS = "server-sent-events"
    SEQUENCER_FEED = "sequencer-feed"
    OFFCHAIN_AUCTION = "offchain-auction"
    BUILDER_METADATA = "builder-metadata"


class ObservationKind(StrEnum):
    BLOCK_HEAD = "block-head"
    EVM_BLOCK_STATE = "evm-block-state"
    EVM_STATE_PROOF = "evm-state-proof"
    PENDING_TRANSACTION = "pending-transaction"
    TRANSACTION_HINT = "transaction-hint"
    PRECONFIRMED_BLOCK = "preconfirmed-block"
    PRECONFIRMED_TRANSACTION = "preconfirmed-transaction"
    PENDING_LOG = "pending-log"
    SEQUENCER_BATCH = "sequencer-batch"
    TIMEBOOST_ROUND = "timeboost-round"
    PBS_BUILDER_STATUS = "pbs-builder-status"
    SOURCE_GAP = "source-gap"
    SOURCE_HEARTBEAT = "source-heartbeat"


class Finality(StrEnum):
    PENDING = "pending"
    PRECONFIRMED = "preconfirmed"
    CONFIRMED = "confirmed"
    FINALIZED = "finalized"
    METADATA = "metadata"


class Visibility(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    HASH_ONLY = "hash-only"
    METADATA = "metadata"


@dataclass(frozen=True, slots=True)
class EventShape:
    kind: ObservationKind
    finality: Finality
    visibility: Visibility

    def __post_init__(self) -> None:
        if type(self.kind) is not ObservationKind:
            raise TypeError("event shape kind must be an exact ObservationKind")
        if type(self.finality) is not Finality:
            raise TypeError("event shape finality must be an exact Finality")
        if type(self.visibility) is not Visibility:
            raise TypeError("event shape visibility must be an exact Visibility")
        metadata_pair = self.finality is Finality.METADATA and self.visibility is Visibility.METADATA
        if (self.finality is Finality.METADATA) != (self.visibility is Visibility.METADATA):
            raise ValueError("metadata finality and visibility must be paired")
        if self.kind in {ObservationKind.SOURCE_GAP, ObservationKind.SOURCE_HEARTBEAT}:
            if not metadata_pair:
                raise ValueError("source control event shapes must use metadata semantics")
        elif metadata_pair and self.kind not in {
            ObservationKind.TIMEBOOST_ROUND,
            ObservationKind.PBS_BUILDER_STATUS,
        }:
            raise ValueError("metadata semantics are restricted to governed metadata event kinds")

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return (self.kind.value, self.finality.value, self.visibility.value)

    def to_json_value(self) -> dict[str, str]:
        return {
            "kind": self.kind.value,
            "finality": self.finality.value,
            "visibility": self.visibility.value,
        }


@dataclass(frozen=True, slots=True)
class SourceContract:
    source_id: str
    chain: Chain
    source_kind: SourceKind
    transport: Transport
    allowed_events: tuple[EventShape, ...]
    max_payload_bytes: int
    max_future_clock_skew_ms: int
    partial_payload_expected: bool
    official_reference: str

    def __post_init__(self) -> None:
        if type(self.source_id) is not str or _SOURCE_ID.fullmatch(self.source_id) is None:
            raise ValueError("source_id must be a canonical lowercase source identifier")
        if type(self.chain) is not Chain:
            raise TypeError("chain must be an exact Chain")
        if self.chain is Chain.SOLANA:
            raise ValueError("Solana observation is not enabled by F2")
        if type(self.source_kind) is not SourceKind:
            raise TypeError("source_kind must be an exact SourceKind")
        if type(self.transport) is not Transport:
            raise TypeError("transport must be an exact Transport")
        if type(self.allowed_events) is not tuple or not self.allowed_events:
            raise TypeError("allowed_events must be a non-empty exact tuple")
        if len(self.allowed_events) > MAX_SOURCE_CONTRACT_EVENTS:
            raise ValueError("allowed_events exceeds the governed schema ceiling")
        if any(type(shape) is not EventShape for shape in self.allowed_events):
            raise TypeError("allowed_events contains an ungoverned value")
        if len(self.allowed_events) != len(set(self.allowed_events)):
            raise ValueError("allowed_events contains a duplicate")
        if tuple(sorted(self.allowed_events, key=lambda shape: shape.sort_key)) != self.allowed_events:
            raise ValueError("allowed_events must be sorted canonically")
        if type(self.max_payload_bytes) is not int or not 1 <= self.max_payload_bytes <= DEFAULT_MAX_JSON_BYTES:
            raise ValueError("max_payload_bytes is outside the governed range")
        if type(self.max_future_clock_skew_ms) is not int or not 0 <= self.max_future_clock_skew_ms <= 60_000:
            raise ValueError("max_future_clock_skew_ms is outside the governed range")
        if type(self.partial_payload_expected) is not bool:
            raise TypeError("partial_payload_expected must be an exact bool")
        allows_partial = any(shape.visibility is Visibility.PARTIAL for shape in self.allowed_events)
        if self.partial_payload_expected is not allows_partial:
            raise ValueError("partial_payload_expected must exactly match the allowed event shapes")
        require_bounded_text("official_reference", self.official_reference, maximum=512)
        if not self.official_reference.startswith("https://"):
            raise ValueError("official_reference must use HTTPS")
        control_kinds = {
            shape.kind
            for shape in self.allowed_events
            if shape.kind in {ObservationKind.SOURCE_GAP, ObservationKind.SOURCE_HEARTBEAT}
        }
        if control_kinds != {ObservationKind.SOURCE_GAP, ObservationKind.SOURCE_HEARTBEAT}:
            raise ValueError("every source contract must support both governed control events")

    @property
    def event_kinds(self) -> tuple[ObservationKind, ...]:
        return tuple(sorted({shape.kind for shape in self.allowed_events}, key=lambda item: item.value))

    def permits(self, *, kind: ObservationKind, finality: Finality, visibility: Visibility) -> bool:
        if type(kind) is not ObservationKind:
            raise TypeError("kind must be an exact ObservationKind")
        if type(finality) is not Finality:
            raise TypeError("finality must be an exact Finality")
        if type(visibility) is not Visibility:
            raise TypeError("visibility must be an exact Visibility")
        return EventShape(kind, finality, visibility) in self.allowed_events

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": "aladdin-mev-source-contract/v1",
            "source_id": self.source_id,
            "chain": self.chain.value,
            "source_kind": self.source_kind.value,
            "transport": self.transport.value,
            "allowed_events": [shape.to_json_value() for shape in self.allowed_events],
            "max_payload_bytes": str(self.max_payload_bytes),
            "max_future_clock_skew_ms": str(self.max_future_clock_skew_ms),
            "partial_payload_expected": self.partial_payload_expected,
            "official_reference": self.official_reference,
            "network_authority": "none-recorded-input-only",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


def _shape(kind: ObservationKind, finality: Finality, visibility: Visibility) -> EventShape:
    return EventShape(kind=kind, finality=finality, visibility=visibility)


def _events(*values: EventShape) -> tuple[EventShape, ...]:
    controls = (
        _shape(ObservationKind.SOURCE_GAP, Finality.METADATA, Visibility.METADATA),
        _shape(ObservationKind.SOURCE_HEARTBEAT, Finality.METADATA, Visibility.METADATA),
    )
    return tuple(sorted((*values, *controls), key=lambda shape: shape.sort_key))


def _evm_rpc_events(
    *,
    pending_transactions: bool,
    authenticated_state_proofs: bool,
) -> tuple[EventShape, ...]:
    values = [
        _shape(ObservationKind.BLOCK_HEAD, Finality.CONFIRMED, Visibility.FULL),
        _shape(ObservationKind.BLOCK_HEAD, Finality.FINALIZED, Visibility.FULL),
        _shape(ObservationKind.EVM_BLOCK_STATE, Finality.CONFIRMED, Visibility.FULL),
        _shape(ObservationKind.EVM_BLOCK_STATE, Finality.FINALIZED, Visibility.FULL),
    ]
    if authenticated_state_proofs:
        values.extend(
            [
                _shape(ObservationKind.EVM_STATE_PROOF, Finality.CONFIRMED, Visibility.FULL),
                _shape(ObservationKind.EVM_STATE_PROOF, Finality.FINALIZED, Visibility.FULL),
            ]
        )
    if pending_transactions:
        values.extend(
            [
                _shape(ObservationKind.PENDING_TRANSACTION, Finality.PENDING, Visibility.FULL),
                _shape(ObservationKind.PENDING_TRANSACTION, Finality.PENDING, Visibility.HASH_ONLY),
            ]
        )
    return _events(*values)


_CONTRACTS = (
    SourceContract(
        source_id="ethereum-json-rpc",
        chain=Chain.ETHEREUM,
        source_kind=SourceKind.EVM_JSON_RPC,
        transport=Transport.JSON_RPC_WEBSOCKET,
        allowed_events=_evm_rpc_events(
            pending_transactions=True,
            authenticated_state_proofs=True,
        ),
        max_payload_bytes=524_288,
        max_future_clock_skew_ms=5_000,
        partial_payload_expected=False,
        official_reference="https://ethereum.org/en/developers/apis/json-rpc/",
    ),
    SourceContract(
        source_id="ethereum-mev-share",
        chain=Chain.ETHEREUM,
        source_kind=SourceKind.FLASHBOTS_MEV_SHARE,
        transport=Transport.SERVER_SENT_EVENTS,
        allowed_events=_events(
            _shape(ObservationKind.TRANSACTION_HINT, Finality.PENDING, Visibility.FULL),
            _shape(ObservationKind.TRANSACTION_HINT, Finality.PENDING, Visibility.HASH_ONLY),
            _shape(ObservationKind.TRANSACTION_HINT, Finality.PENDING, Visibility.PARTIAL),
        ),
        max_payload_bytes=300_000,
        max_future_clock_skew_ms=5_000,
        partial_payload_expected=True,
        official_reference="https://docs.flashbots.net/flashbots-mev-share/searchers/getting-started",
    ),
    SourceContract(
        source_id="base-json-rpc",
        chain=Chain.BASE,
        source_kind=SourceKind.EVM_JSON_RPC,
        transport=Transport.JSON_RPC_WEBSOCKET,
        allowed_events=_evm_rpc_events(
            pending_transactions=True,
            authenticated_state_proofs=True,
        ),
        max_payload_bytes=524_288,
        max_future_clock_skew_ms=5_000,
        partial_payload_expected=False,
        official_reference="https://docs.base.org/base-chain/api-reference/ethereum-json-rpc-api/eth_subscribe",
    ),
    SourceContract(
        source_id="base-flashblocks",
        chain=Chain.BASE,
        source_kind=SourceKind.BASE_FLASHBLOCKS,
        transport=Transport.JSON_RPC_WEBSOCKET,
        allowed_events=_events(
            _shape(ObservationKind.PENDING_LOG, Finality.PRECONFIRMED, Visibility.FULL),
            _shape(ObservationKind.PRECONFIRMED_BLOCK, Finality.PRECONFIRMED, Visibility.FULL),
            _shape(ObservationKind.PRECONFIRMED_TRANSACTION, Finality.PRECONFIRMED, Visibility.FULL),
            _shape(ObservationKind.PRECONFIRMED_TRANSACTION, Finality.PRECONFIRMED, Visibility.HASH_ONLY),
        ),
        max_payload_bytes=786_432,
        max_future_clock_skew_ms=2_000,
        partial_payload_expected=False,
        official_reference="https://docs.base.org/base-chain/api-reference/flashblocks-api/flashblocks-api-overview",
    ),
    SourceContract(
        source_id="arbitrum-json-rpc",
        chain=Chain.ARBITRUM,
        source_kind=SourceKind.EVM_JSON_RPC,
        transport=Transport.JSON_RPC_HTTP,
        allowed_events=_evm_rpc_events(
            pending_transactions=False,
            authenticated_state_proofs=False,
        ),
        max_payload_bytes=524_288,
        max_future_clock_skew_ms=5_000,
        partial_payload_expected=False,
        official_reference="https://docs.arbitrum.io/for-devs/dev-tools-and-resources/chain-info",
    ),
    SourceContract(
        source_id="arbitrum-sequencer-feed",
        chain=Chain.ARBITRUM,
        source_kind=SourceKind.ARBITRUM_SEQUENCER_FEED,
        transport=Transport.SEQUENCER_FEED,
        allowed_events=_events(
            _shape(ObservationKind.SEQUENCER_BATCH, Finality.PRECONFIRMED, Visibility.FULL),
        ),
        max_payload_bytes=786_432,
        max_future_clock_skew_ms=2_000,
        partial_payload_expected=False,
        official_reference="https://docs.arbitrum.io/run-arbitrum-node/run-feed-relay",
    ),
    SourceContract(
        source_id="arbitrum-timeboost-auction",
        chain=Chain.ARBITRUM,
        source_kind=SourceKind.ARBITRUM_TIMEBOOST_AUCTION,
        transport=Transport.OFFCHAIN_AUCTION,
        allowed_events=_events(
            _shape(ObservationKind.TIMEBOOST_ROUND, Finality.METADATA, Visibility.METADATA),
        ),
        max_payload_bytes=131_072,
        max_future_clock_skew_ms=5_000,
        partial_payload_expected=False,
        official_reference="https://docs.arbitrum.io/how-arbitrum-works/timeboost/gentle-introduction",
    ),
    SourceContract(
        source_id="bnb-json-rpc",
        chain=Chain.BNB_SMART_CHAIN,
        source_kind=SourceKind.EVM_JSON_RPC,
        transport=Transport.JSON_RPC_WEBSOCKET,
        allowed_events=_evm_rpc_events(
            pending_transactions=True,
            authenticated_state_proofs=False,
        ),
        max_payload_bytes=524_288,
        max_future_clock_skew_ms=3_000,
        partial_payload_expected=False,
        official_reference="https://docs.bnbchain.org/bnb-smart-chain/developers/json_rpc/json-rpc-endpoint/",
    ),
    SourceContract(
        source_id="bnb-pbs-metadata",
        chain=Chain.BNB_SMART_CHAIN,
        source_kind=SourceKind.BSC_PBS_METADATA,
        transport=Transport.BUILDER_METADATA,
        allowed_events=_events(
            _shape(ObservationKind.PBS_BUILDER_STATUS, Finality.METADATA, Visibility.METADATA),
        ),
        max_payload_bytes=131_072,
        max_future_clock_skew_ms=5_000,
        partial_payload_expected=False,
        official_reference="https://docs.bnbchain.org/bnb-smart-chain/validator/mev/builder-integration/",
    ),
)

SOURCE_CONTRACTS: Mapping[str, SourceContract] = MappingProxyType(
    {contract.source_id: contract for contract in _CONTRACTS}
)
if len(SOURCE_CONTRACTS) != len(_CONTRACTS):
    raise RuntimeError("duplicate source contract identifier")


def get_source_contract(source_id: str) -> SourceContract:
    if type(source_id) is not str:
        raise TypeError("source_id must be an exact string")
    try:
        return SOURCE_CONTRACTS[source_id]
    except KeyError as error:
        raise ValueError(f"unknown source contract: {source_id}") from error


def source_contract_set_digest() -> str:
    return canonical_sha256(
        [SOURCE_CONTRACTS[source_id].to_json_value() for source_id in sorted(SOURCE_CONTRACTS)]
    )
