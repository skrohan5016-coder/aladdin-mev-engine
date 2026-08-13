from __future__ import annotations

import unittest

from aladdin_mev_engine.canonical import canonical_json_bytes, canonical_sha256, strict_json_loads
from aladdin_mev_engine.ledger import (
    LedgerRecord,
    MAX_SEGMENT_RECORDS,
    ObservationLedgerBuilder,
    ObservationSegment,
    SegmentManifest,
    SourceCheckpoint,
    ZERO_SHA256,
    parse_segment,
    serialize_segment,
    validate_segment_chain,
)
from aladdin_mev_engine.source_contracts import Finality, ObservationKind, Visibility
from f1_helpers import make_observation


def build_segment() -> ObservationSegment:
    builder = ObservationLedgerBuilder(segment_id="segment-0001", created_at_unix_ms=10_000)
    builder.append(make_observation(sequence=0, observed_at=1_000))
    builder.append(
        make_observation(
            source_id="ethereum-mev-share",
            sequence=0,
            event_id="hint-0",
            observed_at=1_001,
            kind=ObservationKind.TRANSACTION_HINT,
            finality=Finality.PENDING,
            visibility=Visibility.PARTIAL,
            payload={"hash": "0x" + "a" * 64},
        )
    )
    builder.append(make_observation(sequence=1, observed_at=1_002))
    builder.append(
        make_observation(
            source_id="ethereum-mev-share",
            sequence=1,
            event_id="gap-1",
            observed_at=1_003,
            kind=ObservationKind.SOURCE_GAP,
            finality=Finality.METADATA,
            visibility=Visibility.METADATA,
            payload={
                "first_missing_cursor": "abc",
                "last_missing_cursor": "def",
                "reason": "upstream disconnect",
            },
        )
    )
    return builder.seal()


def build_second_segment(previous: SegmentManifest | None = None) -> ObservationSegment:
    prior = build_segment().manifest if previous is None else previous
    builder = ObservationLedgerBuilder(
        segment_id="segment-0002",
        created_at_unix_ms=20_000,
        previous_manifest=prior,
    )
    builder.append(make_observation(sequence=2, observed_at=2_000, event_id="head-2"))
    builder.append(
        make_observation(
            source_id="base-json-rpc",
            sequence=0,
            event_id="base-head-0",
            observed_at=2_001,
            kind=ObservationKind.BLOCK_HEAD,
            finality=Finality.CONFIRMED,
            visibility=Visibility.FULL,
        )
    )
    return builder.seal()


class LedgerTests(unittest.TestCase):
    def test_segment_round_trip_is_exact_and_deterministic(self) -> None:
        segment = build_segment()
        payload = serialize_segment(segment)
        restored = parse_segment(payload)
        self.assertEqual(restored, segment)
        self.assertEqual(serialize_segment(restored), payload)
        self.assertTrue(payload.endswith(b"\n"))

    def test_global_record_hash_chain_and_source_checkpoints_are_bound(self) -> None:
        segment = build_segment()
        self.assertEqual(segment.records[0].previous_record_sha256, ZERO_SHA256)
        for previous, current in zip(segment.records, segment.records[1:]):
            self.assertEqual(current.previous_record_sha256, previous.record_sha256)
        self.assertEqual(segment.manifest.previous_segment_sha256, ZERO_SHA256)
        self.assertEqual(segment.manifest.starting_source_checkpoints, ())
        self.assertEqual(
            segment.manifest.ending_source_checkpoints,
            (
                SourceCheckpoint("ethereum-json-rpc", 1, 1_002),
                SourceCheckpoint("ethereum-mev-share", 1, 1_003),
            ),
        )

    def test_source_sequence_must_start_at_zero_and_remain_contiguous(self) -> None:
        builder = ObservationLedgerBuilder(segment_id="segment-a", created_at_unix_ms=10_000)
        with self.assertRaises(ValueError):
            builder.append(make_observation(sequence=1))
        builder.append(make_observation(sequence=0))
        with self.assertRaises(ValueError):
            builder.append(make_observation(sequence=2))

    def test_segment_chain_continues_source_sequences_and_adds_new_sources_at_zero(self) -> None:
        first = build_segment()
        second = build_second_segment(first.manifest)
        self.assertEqual(second.manifest.previous_segment_sha256, first.manifest.segment_sha256)
        self.assertEqual(
            second.manifest.starting_source_checkpoints,
            first.manifest.ending_source_checkpoints,
        )
        endings = {item.source_id: item for item in second.manifest.ending_source_checkpoints}
        self.assertEqual(endings["ethereum-json-rpc"].source_sequence, 2)
        self.assertEqual(endings["ethereum-mev-share"].source_sequence, 1)
        self.assertEqual(endings["base-json-rpc"].source_sequence, 0)
        validate_segment_chain((first, second))

    def test_cross_segment_restart_gap_and_time_regression_fail_closed(self) -> None:
        first = build_segment()
        restart = ObservationLedgerBuilder(
            segment_id="restart",
            created_at_unix_ms=20_000,
            previous_manifest=first.manifest,
        )
        with self.assertRaises(ValueError):
            restart.append(make_observation(sequence=0, observed_at=2_000))
        with self.assertRaises(ValueError):
            restart.append(make_observation(sequence=3, observed_at=2_000))
        with self.assertRaises(ValueError):
            restart.append(make_observation(sequence=2, observed_at=999))
        accepted = restart.append(make_observation(sequence=2, observed_at=1_002))
        self.assertEqual(accepted.envelope.source_sequence, 2)

    def test_chain_validation_rejects_truncation_wrong_parent_and_duplicate_ids(self) -> None:
        first = build_segment()
        second = build_second_segment(first.manifest)
        with self.assertRaises(ValueError):
            validate_segment_chain((second,))
        wrong_first = ObservationLedgerBuilder(
            segment_id="other-first",
            created_at_unix_ms=10_000,
        )
        wrong_first.append(make_observation(sequence=0))
        wrong = wrong_first.seal()
        with self.assertRaises(ValueError):
            validate_segment_chain((wrong, second))
        with self.assertRaises(ValueError):
            validate_segment_chain((first, first))

    def test_event_identity_is_unique_within_a_segment_per_source(self) -> None:
        builder = ObservationLedgerBuilder(segment_id="segment-a", created_at_unix_ms=10_000)
        builder.append(make_observation(sequence=0, event_id="same"))
        with self.assertRaises(ValueError):
            builder.append(make_observation(sequence=1, event_id="same"))
        other_source = make_observation(
            source_id="base-json-rpc",
            sequence=0,
            event_id="same",
            kind=ObservationKind.BLOCK_HEAD,
            finality=Finality.CONFIRMED,
            visibility=Visibility.FULL,
        )
        builder.append(other_source)

    def test_source_time_cannot_move_backwards(self) -> None:
        builder = ObservationLedgerBuilder(segment_id="segment-a", created_at_unix_ms=10_000)
        builder.append(make_observation(sequence=0, observed_at=2_000))
        with self.assertRaises(ValueError):
            builder.append(make_observation(sequence=1, observed_at=1_999))

    def test_empty_or_early_segment_cannot_be_sealed(self) -> None:
        with self.assertRaises(ValueError):
            ObservationLedgerBuilder(segment_id="segment-a", created_at_unix_ms=1).seal()
        builder = ObservationLedgerBuilder(segment_id="segment-a", created_at_unix_ms=999)
        builder.append(make_observation(sequence=0, observed_at=1_000))
        with self.assertRaises(ValueError):
            builder.seal()

    def test_previous_manifest_authority_and_creation_time_are_checked(self) -> None:
        first = build_segment()
        with self.assertRaises(ValueError):
            ObservationLedgerBuilder(
                segment_id="segment-2",
                created_at_unix_ms=9_999,
                previous_manifest=first.manifest,
            )
        with self.assertRaises(TypeError):
            ObservationLedgerBuilder(
                segment_id="segment-2",
                created_at_unix_ms=20_000,
                previous_manifest=object(),  # type: ignore[arg-type]
            )

    def test_builder_is_single_use_after_seal(self) -> None:
        builder = ObservationLedgerBuilder(segment_id="segment-a", created_at_unix_ms=10_000)
        builder.append(make_observation(sequence=0))
        builder.seal()
        with self.assertRaises(RuntimeError):
            builder.append(make_observation(sequence=1))
        with self.assertRaises(RuntimeError):
            builder.seal()

    def test_tampered_envelope_is_rejected(self) -> None:
        lines = serialize_segment(build_segment()).splitlines()
        record = strict_json_loads(lines[0])
        record["envelope"]["payload"]["block_number"] = "99"
        lines[0] = canonical_json_bytes(record)
        with self.assertRaises(ValueError):
            parse_segment(b"\n".join(lines) + b"\n")

    def test_tampered_record_digest_or_previous_link_is_rejected(self) -> None:
        lines = serialize_segment(build_segment()).splitlines()
        record = strict_json_loads(lines[1])
        record["record_sha256"] = "0" * 64
        lines[1] = canonical_json_bytes(record)
        with self.assertRaises(ValueError):
            parse_segment(b"\n".join(lines) + b"\n")

        lines = serialize_segment(build_segment()).splitlines()
        record = strict_json_loads(lines[1])
        record["previous_record_sha256"] = "0" * 64
        unsigned = dict(record)
        unsigned.pop("record_sha256")
        record["record_sha256"] = canonical_sha256(unsigned)
        lines[1] = canonical_json_bytes(record)
        with self.assertRaises(ValueError):
            parse_segment(b"\n".join(lines) + b"\n")

    def test_reordering_or_truncation_is_rejected(self) -> None:
        lines = serialize_segment(build_segment()).splitlines()
        lines[0], lines[1] = lines[1], lines[0]
        with self.assertRaises(ValueError):
            parse_segment(b"\n".join(lines) + b"\n")
        lines = serialize_segment(build_segment()).splitlines()
        del lines[1]
        with self.assertRaises(ValueError):
            parse_segment(b"\n".join(lines) + b"\n")

    def test_manifest_tampering_is_rejected(self) -> None:
        lines = serialize_segment(build_segment()).splitlines()
        manifest = strict_json_loads(lines[-1])
        manifest["record_count"] = "3"
        lines[-1] = canonical_json_bytes(manifest)
        with self.assertRaises(ValueError):
            parse_segment(b"\n".join(lines) + b"\n")

        lines = serialize_segment(build_second_segment()).splitlines()
        manifest = strict_json_loads(lines[-1])
        manifest["previous_segment_sha256"] = "1" * 64
        unsigned = dict(manifest)
        unsigned.pop("segment_sha256")
        manifest["segment_sha256"] = canonical_sha256(unsigned)
        lines[-1] = canonical_json_bytes(manifest)
        tampered = parse_segment(b"\n".join(lines) + b"\n")
        with self.assertRaises(ValueError):
            validate_segment_chain((build_segment(), tampered))

    def test_excessive_line_count_is_rejected_before_record_parsing(self) -> None:
        payload = b"{}\n" * (MAX_SEGMENT_RECORDS + 2)
        with self.assertRaisesRegex(ValueError, "record ceiling"):
            parse_segment(payload)

    def test_noncanonical_container_framing_is_rejected(self) -> None:
        payload = serialize_segment(build_segment())
        with self.assertRaises(ValueError):
            parse_segment(payload[:-1])
        with self.assertRaises(ValueError):
            parse_segment(payload.replace(b"\n", b"\r\n"))
        with self.assertRaises(ValueError):
            parse_segment(b"\xef\xbb\xbf" + payload)
        with self.assertRaises(ValueError):
            parse_segment(payload.split(b"\n", 1)[0] + b"\n\n" + payload.split(b"\n", 1)[1])

    def test_record_manifest_and_checkpoint_objects_are_closed(self) -> None:
        record = build_segment().records[0].to_json_value()
        record["unknown"] = 1
        with self.assertRaises(ValueError):
            LedgerRecord.from_json_value(record)
        manifest = build_segment().manifest.to_json_value()
        manifest["unknown"] = 1
        with self.assertRaises(ValueError):
            SegmentManifest.from_json_value(manifest)
        checkpoint = {"source_sequence": "0", "observed_at_unix_ms": "1", "extra": "x"}
        with self.assertRaises(ValueError):
            SourceCheckpoint.from_json_value("ethereum-json-rpc", checkpoint)

    def test_segment_constructor_revalidates_manifest_authority(self) -> None:
        segment = build_segment()
        manifest = SegmentManifest(
            segment_id=segment.manifest.segment_id,
            created_at_unix_ms=segment.manifest.created_at_unix_ms,
            previous_segment_sha256=segment.manifest.previous_segment_sha256,
            record_count=segment.manifest.record_count,
            first_record_sha256=segment.manifest.first_record_sha256,
            last_record_sha256=segment.manifest.last_record_sha256,
            records_root_sha256="0" * 64,
            source_contract_set_sha256=segment.manifest.source_contract_set_sha256,
            starting_source_checkpoints=segment.manifest.starting_source_checkpoints,
            ending_source_checkpoints=segment.manifest.ending_source_checkpoints,
        )
        with self.assertRaises(ValueError):
            ObservationSegment(records=segment.records, manifest=manifest)

    def test_schema_values_use_canonical_decimal_strings(self) -> None:
        segment = build_segment()
        first = segment.records[0].to_json_value()
        manifest = segment.manifest.to_json_value()
        self.assertEqual(first["ordinal"], "0")
        self.assertIsInstance(first["envelope"]["source_sequence"], str)
        self.assertIsInstance(manifest["record_count"], str)
        checkpoint = next(iter(manifest["ending_source_checkpoints"].values()))
        self.assertIsInstance(checkpoint["source_sequence"], str)


if __name__ == "__main__":
    unittest.main()
