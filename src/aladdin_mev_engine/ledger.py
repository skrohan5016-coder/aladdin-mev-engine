from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from .canonical import DEFAULT_MAX_JSON_BYTES, canonical_json_bytes, canonical_sha256, strict_json_loads
from .domain import require_bounded_text, require_sha256
from .observation import ObservationEnvelope, parse_decimal, require_u64
from .source_contracts import get_source_contract, source_contract_set_digest

ZERO_SHA256 = "0" * 64
MAX_SEGMENT_RECORDS = 10_000
MAX_SEGMENT_BYTES = 16 * 1_048_576
_SEGMENT_ID = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")


def _require_segment_id(value: str) -> None:
    if type(value) is not str or _SEGMENT_ID.fullmatch(value) is None:
        raise ValueError("segment_id must be a canonical lowercase identifier")


def _require_exact_keys(name: str, value: dict[str, Any], expected: set[str]) -> None:
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"{name} keys mismatch; missing={sorted(expected - actual)}, unknown={sorted(actual - expected)}"
        )


@dataclass(frozen=True, slots=True)
class SourceCheckpoint:
    source_id: str
    source_sequence: int
    observed_at_unix_ms: int

    def __post_init__(self) -> None:
        get_source_contract(self.source_id)
        require_u64("source_sequence", self.source_sequence)
        require_u64("observed_at_unix_ms", self.observed_at_unix_ms)

    def to_json_value(self) -> dict[str, str]:
        return {
            "source_sequence": str(self.source_sequence),
            "observed_at_unix_ms": str(self.observed_at_unix_ms),
        }

    @classmethod
    def from_json_value(cls, source_id: object, value: object) -> SourceCheckpoint:
        if type(source_id) is not str:
            raise ValueError("checkpoint source_id must be an exact JSON string")
        if type(value) is not dict:
            raise ValueError("source checkpoint must be an exact JSON object")
        _require_exact_keys(
            "source checkpoint",
            value,
            {"source_sequence", "observed_at_unix_ms"},
        )
        return cls(
            source_id=source_id,
            source_sequence=parse_decimal("source_sequence", value["source_sequence"]),
            observed_at_unix_ms=parse_decimal(
                "observed_at_unix_ms", value["observed_at_unix_ms"]
            ),
        )


def _require_checkpoints(
    name: str,
    value: object,
    *,
    allow_empty: bool,
) -> tuple[SourceCheckpoint, ...]:
    if type(value) is not tuple:
        raise TypeError(f"{name} must be an exact tuple")
    if not value and not allow_empty:
        raise ValueError(f"{name} must not be empty")
    if any(type(checkpoint) is not SourceCheckpoint for checkpoint in value):
        raise TypeError(f"{name} contains an ungoverned checkpoint")
    source_ids = [checkpoint.source_id for checkpoint in value]
    if source_ids != sorted(source_ids) or len(source_ids) != len(set(source_ids)):
        raise ValueError(f"{name} must be unique and sorted by source_id")
    return value


def _checkpoint_map(checkpoints: tuple[SourceCheckpoint, ...]) -> dict[str, SourceCheckpoint]:
    return {checkpoint.source_id: checkpoint for checkpoint in checkpoints}


def _checkpoints_from_maps(
    sequences: dict[str, int], observed_times: dict[str, int]
) -> tuple[SourceCheckpoint, ...]:
    if set(sequences) != set(observed_times):
        raise RuntimeError("checkpoint authority maps disagree")
    return tuple(
        SourceCheckpoint(
            source_id=source_id,
            source_sequence=sequences[source_id],
            observed_at_unix_ms=observed_times[source_id],
        )
        for source_id in sorted(sequences)
    )


@dataclass(frozen=True, slots=True)
class LedgerRecord:
    segment_id: str
    ordinal: int
    previous_record_sha256: str
    envelope: ObservationEnvelope

    SCHEMA = "aladdin-mev-observation-ledger-record/v1"

    def __post_init__(self) -> None:
        _require_segment_id(self.segment_id)
        if type(self.ordinal) is not int or not 0 <= self.ordinal < MAX_SEGMENT_RECORDS:
            raise ValueError("ordinal is outside the governed range")
        require_sha256("previous_record_sha256", self.previous_record_sha256)
        if type(self.envelope) is not ObservationEnvelope:
            raise TypeError("envelope must be an exact ObservationEnvelope")

    def unsigned_json_value(self) -> dict[str, Any]:
        return {
            "schema": self.SCHEMA,
            "segment_id": self.segment_id,
            "ordinal": str(self.ordinal),
            "previous_record_sha256": self.previous_record_sha256,
            "envelope_sha256": self.envelope.digest,
            "envelope": self.envelope.to_json_value(),
        }

    @property
    def record_sha256(self) -> str:
        return canonical_sha256(self.unsigned_json_value())

    def to_json_value(self) -> dict[str, Any]:
        value = self.unsigned_json_value()
        value["record_sha256"] = self.record_sha256
        return value

    @classmethod
    def from_json_value(cls, value: object) -> LedgerRecord:
        if type(value) is not dict:
            raise ValueError("ledger record must be an exact JSON object")
        _require_exact_keys(
            "ledger record",
            value,
            {
                "schema",
                "segment_id",
                "ordinal",
                "previous_record_sha256",
                "envelope_sha256",
                "envelope",
                "record_sha256",
            },
        )
        if value["schema"] != cls.SCHEMA:
            raise ValueError("unknown ledger record schema")
        envelope = ObservationEnvelope.from_json_value(value["envelope"])
        require_sha256("previous_record_sha256", value["previous_record_sha256"])
        require_sha256("envelope_sha256", value["envelope_sha256"])
        require_sha256("record_sha256", value["record_sha256"])
        record = cls(
            segment_id=value["segment_id"],
            ordinal=parse_decimal(
                "ordinal", value["ordinal"], maximum=MAX_SEGMENT_RECORDS - 1
            ),
            previous_record_sha256=value["previous_record_sha256"],
            envelope=envelope,
        )
        if value["envelope_sha256"] != envelope.digest:
            raise ValueError("ledger envelope digest mismatch")
        if value["record_sha256"] != record.record_sha256:
            raise ValueError("ledger record digest mismatch")
        return record


@dataclass(frozen=True, slots=True)
class SegmentManifest:
    segment_id: str
    created_at_unix_ms: int
    previous_segment_sha256: str
    record_count: int
    first_record_sha256: str
    last_record_sha256: str
    records_root_sha256: str
    source_contract_set_sha256: str
    starting_source_checkpoints: tuple[SourceCheckpoint, ...]
    ending_source_checkpoints: tuple[SourceCheckpoint, ...]

    SCHEMA = "aladdin-mev-observation-segment-manifest/v1"

    def __post_init__(self) -> None:
        _require_segment_id(self.segment_id)
        require_u64("created_at_unix_ms", self.created_at_unix_ms)
        require_sha256("previous_segment_sha256", self.previous_segment_sha256)
        if type(self.record_count) is not int or not 1 <= self.record_count <= MAX_SEGMENT_RECORDS:
            raise ValueError("record_count is outside the governed range")
        for name, digest in (
            ("first_record_sha256", self.first_record_sha256),
            ("last_record_sha256", self.last_record_sha256),
            ("records_root_sha256", self.records_root_sha256),
            ("source_contract_set_sha256", self.source_contract_set_sha256),
        ):
            require_sha256(name, digest)
        _require_checkpoints(
            "starting_source_checkpoints",
            self.starting_source_checkpoints,
            allow_empty=True,
        )
        _require_checkpoints(
            "ending_source_checkpoints",
            self.ending_source_checkpoints,
            allow_empty=False,
        )
        if (self.previous_segment_sha256 == ZERO_SHA256) != (
            not self.starting_source_checkpoints
        ):
            raise ValueError(
                "genesis segment identity and starting checkpoints are inconsistent"
            )
        starting = _checkpoint_map(self.starting_source_checkpoints)
        ending = _checkpoint_map(self.ending_source_checkpoints)
        if not set(starting).issubset(ending):
            raise ValueError("ending checkpoints cannot drop a previously observed source")
        for source_id, checkpoint in starting.items():
            final = ending[source_id]
            if final.source_sequence < checkpoint.source_sequence:
                raise ValueError("ending source sequence moved backwards")
            if final.observed_at_unix_ms < checkpoint.observed_at_unix_ms:
                raise ValueError("ending source observation time moved backwards")
        if self.created_at_unix_ms < max(
            checkpoint.observed_at_unix_ms for checkpoint in self.ending_source_checkpoints
        ):
            raise ValueError("segment creation time precedes its ending source checkpoint")

    @staticmethod
    def _checkpoints_json(
        checkpoints: tuple[SourceCheckpoint, ...]
    ) -> dict[str, dict[str, str]]:
        return {
            checkpoint.source_id: checkpoint.to_json_value() for checkpoint in checkpoints
        }

    @staticmethod
    def _parse_checkpoints(name: str, value: object) -> tuple[SourceCheckpoint, ...]:
        if type(value) is not dict:
            raise ValueError(f"{name} must be an exact JSON object")
        return tuple(
            SourceCheckpoint.from_json_value(source_id, checkpoint)
            for source_id, checkpoint in sorted(value.items())
        )

    def unsigned_json_value(self) -> dict[str, Any]:
        return {
            "schema": self.SCHEMA,
            "segment_id": self.segment_id,
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "previous_segment_sha256": self.previous_segment_sha256,
            "record_count": str(self.record_count),
            "first_record_sha256": self.first_record_sha256,
            "last_record_sha256": self.last_record_sha256,
            "records_root_sha256": self.records_root_sha256,
            "source_contract_set_sha256": self.source_contract_set_sha256,
            "starting_source_checkpoints": self._checkpoints_json(
                self.starting_source_checkpoints
            ),
            "ending_source_checkpoints": self._checkpoints_json(
                self.ending_source_checkpoints
            ),
        }

    @property
    def segment_sha256(self) -> str:
        return canonical_sha256(self.unsigned_json_value())

    def to_json_value(self) -> dict[str, Any]:
        value = self.unsigned_json_value()
        value["segment_sha256"] = self.segment_sha256
        return value

    @classmethod
    def from_json_value(cls, value: object) -> SegmentManifest:
        if type(value) is not dict:
            raise ValueError("segment manifest must be an exact JSON object")
        _require_exact_keys(
            "segment manifest",
            value,
            {
                "schema",
                "segment_id",
                "created_at_unix_ms",
                "previous_segment_sha256",
                "record_count",
                "first_record_sha256",
                "last_record_sha256",
                "records_root_sha256",
                "source_contract_set_sha256",
                "starting_source_checkpoints",
                "ending_source_checkpoints",
                "segment_sha256",
            },
        )
        if value["schema"] != cls.SCHEMA:
            raise ValueError("unknown segment manifest schema")
        for name in (
            "previous_segment_sha256",
            "first_record_sha256",
            "last_record_sha256",
            "records_root_sha256",
            "source_contract_set_sha256",
            "segment_sha256",
        ):
            require_sha256(name, value[name])
        manifest = cls(
            segment_id=value["segment_id"],
            created_at_unix_ms=parse_decimal(
                "created_at_unix_ms", value["created_at_unix_ms"]
            ),
            previous_segment_sha256=value["previous_segment_sha256"],
            record_count=parse_decimal(
                "record_count", value["record_count"], maximum=MAX_SEGMENT_RECORDS
            ),
            first_record_sha256=value["first_record_sha256"],
            last_record_sha256=value["last_record_sha256"],
            records_root_sha256=value["records_root_sha256"],
            source_contract_set_sha256=value["source_contract_set_sha256"],
            starting_source_checkpoints=cls._parse_checkpoints(
                "starting_source_checkpoints", value["starting_source_checkpoints"]
            ),
            ending_source_checkpoints=cls._parse_checkpoints(
                "ending_source_checkpoints", value["ending_source_checkpoints"]
            ),
        )
        if value["segment_sha256"] != manifest.segment_sha256:
            raise ValueError("segment manifest digest mismatch")
        return manifest


@dataclass(frozen=True, slots=True)
class ObservationSegment:
    records: tuple[LedgerRecord, ...]
    manifest: SegmentManifest

    def __post_init__(self) -> None:
        if type(self.records) is not tuple or not self.records:
            raise TypeError("records must be a non-empty exact tuple")
        if any(type(record) is not LedgerRecord for record in self.records):
            raise TypeError("records contains an ungoverned record")
        if type(self.manifest) is not SegmentManifest:
            raise TypeError("manifest must be an exact SegmentManifest")
        validate_segment(self.records, self.manifest)


class ObservationLedgerBuilder:
    def __init__(
        self,
        *,
        segment_id: str,
        created_at_unix_ms: int,
        previous_manifest: SegmentManifest | None = None,
    ) -> None:
        _require_segment_id(segment_id)
        require_u64("created_at_unix_ms", created_at_unix_ms)
        if previous_manifest is not None and type(previous_manifest) is not SegmentManifest:
            raise TypeError("previous_manifest must be an exact SegmentManifest or null")
        if previous_manifest is not None:
            if previous_manifest.source_contract_set_sha256 != source_contract_set_digest():
                raise ValueError("previous segment uses a different source-contract authority")
            if created_at_unix_ms < previous_manifest.created_at_unix_ms:
                raise ValueError("segment creation time moved backwards")
            starting = previous_manifest.ending_source_checkpoints
            previous_segment_sha256 = previous_manifest.segment_sha256
        else:
            starting = ()
            previous_segment_sha256 = ZERO_SHA256
        self._segment_id = segment_id
        self._created_at_unix_ms = created_at_unix_ms
        self._previous_segment_sha256 = previous_segment_sha256
        self._starting_checkpoints = starting
        self._records: list[LedgerRecord] = []
        self._last_sequence = {
            checkpoint.source_id: checkpoint.source_sequence for checkpoint in starting
        }
        self._last_observed_at = {
            checkpoint.source_id: checkpoint.observed_at_unix_ms for checkpoint in starting
        }
        self._event_ids: set[tuple[str, str]] = set()
        self._sealed = False

    @property
    def record_count(self) -> int:
        return len(self._records)

    def append(self, envelope: ObservationEnvelope) -> LedgerRecord:
        if self._sealed:
            raise RuntimeError("ledger builder is already sealed")
        if type(envelope) is not ObservationEnvelope:
            raise TypeError("envelope must be an exact ObservationEnvelope")
        if len(self._records) >= MAX_SEGMENT_RECORDS:
            raise ValueError("segment record ceiling exceeded")
        previous_sequence = self._last_sequence.get(envelope.source_id)
        expected_sequence = 0 if previous_sequence is None else previous_sequence + 1
        if envelope.source_sequence != expected_sequence:
            raise ValueError(
                f"non-contiguous source sequence for {envelope.source_id}: expected {expected_sequence}"
            )
        previous_time = self._last_observed_at.get(envelope.source_id)
        if previous_time is not None and envelope.observed_at_unix_ms < previous_time:
            raise ValueError("source observation time moved backwards")
        identity = (envelope.source_id, envelope.source_event_id)
        if identity in self._event_ids:
            raise ValueError("duplicate source event identity within segment")
        previous_digest = ZERO_SHA256 if not self._records else self._records[-1].record_sha256
        record = LedgerRecord(
            segment_id=self._segment_id,
            ordinal=len(self._records),
            previous_record_sha256=previous_digest,
            envelope=envelope,
        )
        self._records.append(record)
        self._last_sequence[envelope.source_id] = envelope.source_sequence
        self._last_observed_at[envelope.source_id] = envelope.observed_at_unix_ms
        self._event_ids.add(identity)
        return record

    def seal(self) -> ObservationSegment:
        if self._sealed:
            raise RuntimeError("ledger builder is already sealed")
        if not self._records:
            raise ValueError("cannot seal an empty observation segment")
        ending = _checkpoints_from_maps(self._last_sequence, self._last_observed_at)
        if self._created_at_unix_ms < max(
            checkpoint.observed_at_unix_ms for checkpoint in ending
        ):
            raise ValueError("segment creation time precedes an observation")
        records = tuple(self._records)
        digests = [record.record_sha256 for record in records]
        manifest = SegmentManifest(
            segment_id=self._segment_id,
            created_at_unix_ms=self._created_at_unix_ms,
            previous_segment_sha256=self._previous_segment_sha256,
            record_count=len(records),
            first_record_sha256=digests[0],
            last_record_sha256=digests[-1],
            records_root_sha256=canonical_sha256(digests),
            source_contract_set_sha256=source_contract_set_digest(),
            starting_source_checkpoints=self._starting_checkpoints,
            ending_source_checkpoints=ending,
        )
        segment = ObservationSegment(records=records, manifest=manifest)
        self._sealed = True
        return segment


def validate_segment(records: tuple[LedgerRecord, ...], manifest: SegmentManifest) -> None:
    if len(records) != manifest.record_count:
        raise ValueError("segment record count mismatch")
    if len(records) > MAX_SEGMENT_RECORDS:
        raise ValueError("segment record ceiling exceeded")
    expected_previous = ZERO_SHA256
    starting = _checkpoint_map(manifest.starting_source_checkpoints)
    last_sequence = {
        source_id: checkpoint.source_sequence for source_id, checkpoint in starting.items()
    }
    last_observed = {
        source_id: checkpoint.observed_at_unix_ms for source_id, checkpoint in starting.items()
    }
    event_ids: set[tuple[str, str]] = set()
    digests: list[str] = []
    for ordinal, record in enumerate(records):
        if record.segment_id != manifest.segment_id:
            raise ValueError("record segment identity mismatch")
        if record.ordinal != ordinal:
            raise ValueError("record ordinal mismatch")
        if record.previous_record_sha256 != expected_previous:
            raise ValueError("record hash-chain mismatch")
        envelope = record.envelope
        previous_sequence = last_sequence.get(envelope.source_id)
        expected_sequence = 0 if previous_sequence is None else previous_sequence + 1
        if envelope.source_sequence != expected_sequence:
            raise ValueError("source sequence continuity mismatch")
        previous_time = last_observed.get(envelope.source_id)
        if previous_time is not None and envelope.observed_at_unix_ms < previous_time:
            raise ValueError("source observation time moved backwards")
        identity = (envelope.source_id, envelope.source_event_id)
        if identity in event_ids:
            raise ValueError("duplicate source event identity within segment")
        event_ids.add(identity)
        last_sequence[envelope.source_id] = envelope.source_sequence
        last_observed[envelope.source_id] = envelope.observed_at_unix_ms
        digest = record.record_sha256
        digests.append(digest)
        expected_previous = digest
    ending = _checkpoints_from_maps(last_sequence, last_observed)
    if manifest.created_at_unix_ms < max(
        checkpoint.observed_at_unix_ms for checkpoint in ending
    ):
        raise ValueError("segment creation time precedes an observation")
    if manifest.first_record_sha256 != digests[0]:
        raise ValueError("first record digest mismatch")
    if manifest.last_record_sha256 != digests[-1]:
        raise ValueError("last record digest mismatch")
    if manifest.records_root_sha256 != canonical_sha256(digests):
        raise ValueError("records root digest mismatch")
    if manifest.source_contract_set_sha256 != source_contract_set_digest():
        raise ValueError("source-contract set digest mismatch")
    if manifest.ending_source_checkpoints != ending:
        raise ValueError("ending source checkpoint manifest mismatch")


def validate_segment_chain(segments: tuple[ObservationSegment, ...]) -> None:
    if type(segments) is not tuple or not segments:
        raise TypeError("segments must be a non-empty exact tuple")
    if any(type(segment) is not ObservationSegment for segment in segments):
        raise TypeError("segments contains an ungoverned segment")
    seen_ids: set[str] = set()
    previous: ObservationSegment | None = None
    for segment in segments:
        if segment.manifest.segment_id in seen_ids:
            raise ValueError("segment chain contains a duplicate segment_id")
        seen_ids.add(segment.manifest.segment_id)
        expected_previous = ZERO_SHA256 if previous is None else previous.manifest.segment_sha256
        expected_starting = () if previous is None else previous.manifest.ending_source_checkpoints
        if segment.manifest.previous_segment_sha256 != expected_previous:
            raise ValueError("segment chain previous-segment digest mismatch")
        if segment.manifest.starting_source_checkpoints != expected_starting:
            raise ValueError("segment chain starting checkpoint mismatch")
        if previous is not None:
            if segment.manifest.created_at_unix_ms < previous.manifest.created_at_unix_ms:
                raise ValueError("segment chain creation time moved backwards")
            if (
                segment.manifest.source_contract_set_sha256
                != previous.manifest.source_contract_set_sha256
            ):
                raise ValueError("segment chain source-contract authority changed")
        previous = segment


def serialize_segment(segment: ObservationSegment) -> bytes:
    if type(segment) is not ObservationSegment:
        raise TypeError("segment must be an exact ObservationSegment")
    lines = [canonical_json_bytes(record.to_json_value()) for record in segment.records]
    lines.append(canonical_json_bytes(segment.manifest.to_json_value()))
    payload = b"\n".join(lines) + b"\n"
    if len(payload) > MAX_SEGMENT_BYTES:
        raise ValueError("serialized segment exceeds the governed byte ceiling")
    return payload


def parse_segment(payload: bytes) -> ObservationSegment:
    if type(payload) is not bytes:
        raise TypeError("segment payload must be exact bytes")
    if not payload:
        raise ValueError("segment payload is empty")
    if len(payload) > MAX_SEGMENT_BYTES:
        raise ValueError("segment payload exceeds the governed byte ceiling")
    if payload.startswith(b"\xef\xbb\xbf"):
        raise ValueError("segment UTF-8 BOM is forbidden")
    if b"\r" in payload:
        raise ValueError("segment must use canonical LF line endings")
    if not payload.endswith(b"\n"):
        raise ValueError("segment must end with a newline")
    raw_lines = payload[:-1].split(b"\n")
    if len(raw_lines) < 2 or any(not line for line in raw_lines):
        raise ValueError("segment requires records followed by exactly one manifest")
    if len(raw_lines) > MAX_SEGMENT_RECORDS + 1:
        raise ValueError("segment contains more than the governed record ceiling")
    if any(len(line) > DEFAULT_MAX_JSON_BYTES for line in raw_lines):
        raise ValueError("segment line exceeds the governed JSON byte ceiling")
    values = [strict_json_loads(line) for line in raw_lines]
    manifest = SegmentManifest.from_json_value(values[-1])
    records = tuple(LedgerRecord.from_json_value(value) for value in values[:-1])
    return ObservationSegment(records=records, manifest=manifest)
