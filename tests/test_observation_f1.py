from __future__ import annotations

import hashlib
import unittest

from aladdin_mev_engine.canonical import CanonicalJsonError, canonical_json_bytes
from aladdin_mev_engine.domain import Chain
from aladdin_mev_engine.observation import MAX_U64, ObservationEnvelope
from aladdin_mev_engine.source_contracts import Finality, ObservationKind, SourceKind, Visibility
from f1_helpers import make_observation


class ObservationEnvelopeTests(unittest.TestCase):
    def test_round_trip_and_digest_are_deterministic(self) -> None:
        first = make_observation(payload={"b": 2, "a": 1})
        second = make_observation(payload={"a": 1, "b": 2})
        self.assertEqual(first.digest, second.digest)
        restored = ObservationEnvelope.from_json_value(first.to_json_value())
        self.assertEqual(restored, first)
        self.assertEqual(restored.digest, first.digest)

    def test_payload_is_detached_from_mutable_input(self) -> None:
        payload = {"nested": {"value": 1}}
        envelope = make_observation(payload=payload)
        payload["nested"]["value"] = 2
        self.assertEqual(envelope.payload, {"nested": {"value": 1}})
        returned = envelope.payload
        returned["nested"]["value"] = 3
        self.assertEqual(envelope.payload, {"nested": {"value": 1}})

    def test_direct_chain_or_source_kind_mismatch_is_rejected(self) -> None:
        valid = make_observation()
        with self.assertRaises(ValueError):
            ObservationEnvelope(
                source_id=valid.source_id,
                chain=Chain.BASE,
                source_kind=valid.source_kind,
                source_sequence=valid.source_sequence,
                source_event_id=valid.source_event_id,
                observed_at_unix_ms=valid.observed_at_unix_ms,
                emitted_at_unix_ms=valid.emitted_at_unix_ms,
                kind=valid.kind,
                finality=valid.finality,
                visibility=valid.visibility,
                payload_bytes=valid.payload_bytes,
            )
        with self.assertRaises(ValueError):
            ObservationEnvelope(
                source_id=valid.source_id,
                chain=valid.chain,
                source_kind=SourceKind.BASE_FLASHBLOCKS,
                source_sequence=valid.source_sequence,
                source_event_id=valid.source_event_id,
                observed_at_unix_ms=valid.observed_at_unix_ms,
                emitted_at_unix_ms=valid.emitted_at_unix_ms,
                kind=valid.kind,
                finality=valid.finality,
                visibility=valid.visibility,
                payload_bytes=valid.payload_bytes,
            )

    def test_source_contract_rejects_unpermitted_event_or_cross_product(self) -> None:
        with self.assertRaises(ValueError):
            make_observation(
                source_id="ethereum-mev-share",
                kind=ObservationKind.BLOCK_HEAD,
                finality=Finality.CONFIRMED,
                visibility=Visibility.FULL,
            )
        with self.assertRaises(ValueError):
            make_observation(
                kind=ObservationKind.BLOCK_HEAD,
                finality=Finality.CONFIRMED,
                visibility=Visibility.HASH_ONLY,
                payload={"hash": "0x" + "1" * 64},
            )
        with self.assertRaises(ValueError):
            make_observation(
                kind=ObservationKind.PENDING_TRANSACTION,
                finality=Finality.FINALIZED,
                visibility=Visibility.FULL,
                payload={"hash": "0x" + "1" * 64},
            )

    def test_floats_and_oversized_payloads_fail_closed(self) -> None:
        with self.assertRaises(CanonicalJsonError):
            make_observation(payload={"price": 1.2})
        with self.assertRaises((CanonicalJsonError, ValueError)):
            make_observation(
                source_id="arbitrum-timeboost-auction",
                payload={"x": "z" * 140_000},
                kind=ObservationKind.TIMEBOOST_ROUND,
                finality=Finality.METADATA,
                visibility=Visibility.METADATA,
            )

    def test_future_clock_skew_is_bounded(self) -> None:
        with self.assertRaises(ValueError):
            make_observation(observed_at=1_000, emitted_at=7_001)
        old = make_observation(observed_at=100_000, emitted_at=1)
        self.assertEqual(old.emitted_at_unix_ms, 1)

    def test_unsigned_64_bit_sequence_and_time_bounds_are_enforced(self) -> None:
        with self.assertRaises(ValueError):
            make_observation(sequence=MAX_U64 + 1)
        value = make_observation().to_json_value()
        value["source_sequence"] = str(MAX_U64 + 1)
        with self.assertRaises(ValueError):
            ObservationEnvelope.from_json_value(value)
        value = make_observation().to_json_value()
        value["observed_at_unix_ms"] = "1" * 100_000
        with self.assertRaises(ValueError):
            ObservationEnvelope.from_json_value(value)

    def test_gap_and_heartbeat_payloads_are_closed(self) -> None:
        gap = make_observation(
            kind=ObservationKind.SOURCE_GAP,
            finality=Finality.METADATA,
            visibility=Visibility.METADATA,
            payload={
                "first_missing_cursor": "10",
                "last_missing_cursor": "12",
                "reason": "disconnect",
            },
        )
        self.assertEqual(gap.kind, ObservationKind.SOURCE_GAP)
        with self.assertRaises(ValueError):
            make_observation(
                kind=ObservationKind.SOURCE_GAP,
                finality=Finality.METADATA,
                visibility=Visibility.METADATA,
                payload={"first_missing_cursor": "10", "last_missing_cursor": "12"},
            )
        heartbeat = make_observation(
            kind=ObservationKind.SOURCE_HEARTBEAT,
            finality=Finality.METADATA,
            visibility=Visibility.METADATA,
            payload={"upstream_cursor": "abc"},
        )
        self.assertEqual(heartbeat.payload["upstream_cursor"], "abc")

    def test_control_events_require_metadata_semantics(self) -> None:
        with self.assertRaises(ValueError):
            make_observation(
                kind=ObservationKind.SOURCE_HEARTBEAT,
                finality=Finality.CONFIRMED,
                visibility=Visibility.FULL,
                payload={"upstream_cursor": "abc"},
            )

    def test_mev_share_partial_hint_is_accepted(self) -> None:
        envelope = make_observation(
            source_id="ethereum-mev-share",
            kind=ObservationKind.TRANSACTION_HINT,
            finality=Finality.PENDING,
            visibility=Visibility.PARTIAL,
            payload={"hash": "0x" + "1" * 64, "function_selector": "0x12345678"},
        )
        self.assertEqual(envelope.chain, Chain.ETHEREUM)

    def test_tampered_payload_or_contract_digest_is_rejected(self) -> None:
        value = make_observation().to_json_value()
        value["payload"]["block_number"] = "9"
        with self.assertRaises(ValueError):
            ObservationEnvelope.from_json_value(value)
        value = make_observation().to_json_value()
        value["source_contract_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            ObservationEnvelope.from_json_value(value)

    def test_unknown_fields_and_noncanonical_decimal_are_rejected(self) -> None:
        value = make_observation().to_json_value()
        value["unknown"] = True
        with self.assertRaises(ValueError):
            ObservationEnvelope.from_json_value(value)
        value = make_observation().to_json_value()
        value["source_sequence"] = "00"
        with self.assertRaises(ValueError):
            ObservationEnvelope.from_json_value(value)

    def test_noncanonical_payload_bytes_are_rejected(self) -> None:
        valid = make_observation(payload={"a": 1, "b": 2})
        with self.assertRaises(ValueError):
            ObservationEnvelope(
                source_id=valid.source_id,
                chain=valid.chain,
                source_kind=valid.source_kind,
                source_sequence=valid.source_sequence,
                source_event_id=valid.source_event_id,
                observed_at_unix_ms=valid.observed_at_unix_ms,
                emitted_at_unix_ms=valid.emitted_at_unix_ms,
                kind=valid.kind,
                finality=valid.finality,
                visibility=valid.visibility,
                payload_bytes=b'{"b":2,"a":1}',
            )

    def test_payload_digest_matches_exact_canonical_bytes(self) -> None:
        envelope = make_observation(payload={"a": [1, 2, 3]})
        self.assertEqual(
            envelope.payload_sha256,
            hashlib.sha256(canonical_json_bytes({"a": [1, 2, 3]})).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
