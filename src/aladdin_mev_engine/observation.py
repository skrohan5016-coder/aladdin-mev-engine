from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Any

from .canonical import CanonicalJsonError, canonical_json_bytes, canonical_sha256, strict_json_loads
from .domain import Chain, require_bounded_text, require_sha256
from .source_contracts import (
    Finality,
    ObservationKind,
    SourceKind,
    Visibility,
    get_source_contract,
)

_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)$")
MAX_U64 = (1 << 64) - 1


def require_u64(name: str, value: object) -> None:
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise ValueError(f"{name} must be an unsigned 64-bit integer")


def parse_decimal(name: str, value: object, *, maximum: int = MAX_U64) -> int:
    if type(maximum) is not int or not 0 <= maximum <= MAX_U64:
        raise ValueError("maximum must be a governed unsigned 64-bit integer")
    if type(value) is not str or _DECIMAL.fullmatch(value) is None:
        raise ValueError(f"{name} must be a canonical non-negative decimal string")
    if len(value) > 20:
        raise ValueError(f"{name} exceeds the governed integer width")
    parsed = int(value)
    if parsed > maximum:
        raise ValueError(f"{name} exceeds the governed maximum")
    return parsed


def _require_exact_keys(name: str, value: dict[str, Any], expected: set[str]) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise ValueError(f"{name} keys mismatch; missing={missing}, unknown={unknown}")


@dataclass(frozen=True, slots=True)
class ObservationEnvelope:
    source_id: str
    chain: Chain
    source_kind: SourceKind
    source_sequence: int
    source_event_id: str
    observed_at_unix_ms: int
    emitted_at_unix_ms: int | None
    kind: ObservationKind
    finality: Finality
    visibility: Visibility
    payload_bytes: bytes

    SCHEMA = "aladdin-mev-observation-envelope/v1"

    def __post_init__(self) -> None:
        contract = get_source_contract(self.source_id)
        if type(self.chain) is not Chain or self.chain is not contract.chain:
            raise ValueError("observation chain does not match its source contract")
        if type(self.source_kind) is not SourceKind or self.source_kind is not contract.source_kind:
            raise ValueError("observation source kind does not match its source contract")
        if type(self.kind) is not ObservationKind:
            raise TypeError("kind must be an exact ObservationKind")
        if type(self.finality) is not Finality:
            raise TypeError("finality must be an exact Finality")
        if type(self.visibility) is not Visibility:
            raise TypeError("visibility must be an exact Visibility")
        if not contract.permits(kind=self.kind, finality=self.finality, visibility=self.visibility):
            raise ValueError("observation kind/finality/visibility is not permitted by its source contract")
        require_u64("source_sequence", self.source_sequence)
        require_bounded_text("source_event_id", self.source_event_id, maximum=256)
        require_u64("observed_at_unix_ms", self.observed_at_unix_ms)
        if self.emitted_at_unix_ms is not None:
            require_u64("emitted_at_unix_ms", self.emitted_at_unix_ms)
            if self.emitted_at_unix_ms > self.observed_at_unix_ms + contract.max_future_clock_skew_ms:
                raise ValueError("source emission time exceeds the governed future-clock allowance")
        if type(self.payload_bytes) is not bytes:
            raise TypeError("payload_bytes must be exact immutable bytes")
        if len(self.payload_bytes) > contract.max_payload_bytes:
            raise ValueError("observation payload exceeds its source contract ceiling")
        payload = strict_json_loads(self.payload_bytes, max_bytes=contract.max_payload_bytes)
        if type(payload) is not dict:
            raise ValueError("observation payload must be a JSON object")
        if canonical_json_bytes(payload) != self.payload_bytes:
            raise ValueError("observation payload is not canonical JSON")
        self._validate_control_event(payload)

    def _validate_control_event(self, payload: dict[str, Any]) -> None:
        if self.kind in {ObservationKind.SOURCE_GAP, ObservationKind.SOURCE_HEARTBEAT}:
            if self.finality is not Finality.METADATA or self.visibility is not Visibility.METADATA:
                raise ValueError("source control observations must use metadata finality and visibility")
        if self.kind is ObservationKind.SOURCE_GAP:
            _require_exact_keys(
                "source-gap payload",
                payload,
                {"first_missing_cursor", "last_missing_cursor", "reason"},
            )
            for field in ("first_missing_cursor", "last_missing_cursor", "reason"):
                require_bounded_text(field, payload[field], maximum=256)
        elif self.kind is ObservationKind.SOURCE_HEARTBEAT:
            _require_exact_keys("source-heartbeat payload", payload, {"upstream_cursor"})
            require_bounded_text("upstream_cursor", payload["upstream_cursor"], maximum=256)
        elif self.finality is Finality.METADATA and self.visibility is not Visibility.METADATA:
            raise ValueError("metadata finality requires metadata visibility")
        elif self.visibility is Visibility.METADATA and self.finality is not Finality.METADATA:
            raise ValueError("metadata visibility requires metadata finality")

    @classmethod
    def create(
        cls,
        *,
        source_id: str,
        source_sequence: int,
        source_event_id: str,
        observed_at_unix_ms: int,
        emitted_at_unix_ms: int | None,
        kind: ObservationKind,
        finality: Finality,
        visibility: Visibility,
        payload: object,
    ) -> ObservationEnvelope:
        contract = get_source_contract(source_id)
        payload_bytes = canonical_json_bytes(payload)
        if len(payload_bytes) > contract.max_payload_bytes:
            raise ValueError("observation payload exceeds its source contract ceiling")
        return cls(
            source_id=source_id,
            chain=contract.chain,
            source_kind=contract.source_kind,
            source_sequence=source_sequence,
            source_event_id=source_event_id,
            observed_at_unix_ms=observed_at_unix_ms,
            emitted_at_unix_ms=emitted_at_unix_ms,
            kind=kind,
            finality=finality,
            visibility=visibility,
            payload_bytes=payload_bytes,
        )

    @property
    def payload(self) -> dict[str, Any]:
        value = strict_json_loads(self.payload_bytes)
        if type(value) is not dict:  # defensive; constructor already proves this
            raise RuntimeError("payload authority corrupted")
        return value

    @property
    def payload_sha256(self) -> str:
        return hashlib.sha256(self.payload_bytes).hexdigest()

    @property
    def source_contract_sha256(self) -> str:
        return get_source_contract(self.source_id).digest

    def to_json_value(self) -> dict[str, Any]:
        return {
            "schema": self.SCHEMA,
            "source_id": self.source_id,
            "chain": self.chain.value,
            "source_kind": self.source_kind.value,
            "source_sequence": str(self.source_sequence),
            "source_event_id": self.source_event_id,
            "observed_at_unix_ms": str(self.observed_at_unix_ms),
            "emitted_at_unix_ms": None if self.emitted_at_unix_ms is None else str(self.emitted_at_unix_ms),
            "kind": self.kind.value,
            "finality": self.finality.value,
            "visibility": self.visibility.value,
            "payload": self.payload,
            "payload_sha256": self.payload_sha256,
            "source_contract_sha256": self.source_contract_sha256,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())

    @classmethod
    def from_json_value(cls, value: object) -> ObservationEnvelope:
        if type(value) is not dict:
            raise ValueError("observation envelope must be an exact JSON object")
        _require_exact_keys(
            "observation envelope",
            value,
            {
                "schema",
                "source_id",
                "chain",
                "source_kind",
                "source_sequence",
                "source_event_id",
                "observed_at_unix_ms",
                "emitted_at_unix_ms",
                "kind",
                "finality",
                "visibility",
                "payload",
                "payload_sha256",
                "source_contract_sha256",
            },
        )
        if value["schema"] != cls.SCHEMA:
            raise ValueError("unknown observation envelope schema")
        enum_fields = ("chain", "source_kind", "kind", "finality", "visibility")
        if any(type(value[field]) is not str for field in enum_fields):
            raise ValueError("observation governed enums must be exact JSON strings")
        try:
            chain = Chain(value["chain"])
            source_kind = SourceKind(value["source_kind"])
            kind = ObservationKind(value["kind"])
            finality = Finality(value["finality"])
            visibility = Visibility(value["visibility"])
        except ValueError as error:
            raise ValueError("observation contains an unknown governed enum") from error
        emitted_raw = value["emitted_at_unix_ms"]
        emitted = None if emitted_raw is None else parse_decimal("emitted_at_unix_ms", emitted_raw)
        payload_bytes = canonical_json_bytes(value["payload"])
        envelope = cls(
            source_id=value["source_id"],
            chain=chain,
            source_kind=source_kind,
            source_sequence=parse_decimal("source_sequence", value["source_sequence"]),
            source_event_id=value["source_event_id"],
            observed_at_unix_ms=parse_decimal("observed_at_unix_ms", value["observed_at_unix_ms"]),
            emitted_at_unix_ms=emitted,
            kind=kind,
            finality=finality,
            visibility=visibility,
            payload_bytes=payload_bytes,
        )
        require_sha256("payload_sha256", value["payload_sha256"])
        require_sha256("source_contract_sha256", value["source_contract_sha256"])
        if value["payload_sha256"] != envelope.payload_sha256:
            raise ValueError("observation payload digest mismatch")
        if value["source_contract_sha256"] != envelope.source_contract_sha256:
            raise ValueError("observation source-contract digest mismatch")
        return envelope
