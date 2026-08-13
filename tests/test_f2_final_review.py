from __future__ import annotations

import unittest

from aladdin_mev_engine.domain import Chain
from aladdin_mev_engine.observation import ObservationEnvelope
from aladdin_mev_engine.source_contracts import (
    MAX_SOURCE_CONTRACT_EVENTS,
    EventShape,
    Finality,
    ObservationKind,
    SourceContract,
    SourceKind,
    Transport,
    Visibility,
)
from aladdin_mev_engine.state_proof import EvmBlockStateAnchor

from f2_helpers import proof_fixture, state_observation


class F2FinalReviewTests(unittest.TestCase):
    def test_state_anchor_reuses_canonical_f1_head_validation(self) -> None:
        fixture = proof_fixture()
        malformed_head = ObservationEnvelope.create(
            source_id=fixture.source_id,
            source_sequence=10,
            source_event_id="malformed-head",
            observed_at_unix_ms=1_800_000_000_000,
            emitted_at_unix_ms=1_800_000_000_000,
            kind=ObservationKind.BLOCK_HEAD,
            finality=fixture.finality,
            visibility=Visibility.FULL,
            payload={
                "block_number": str(fixture.block_number),
                "block_hash": "0x" + fixture.block_hash.hex(),
                "parent_hash": "0x" + "00" * 32,
                "block_timestamp_unix_s": "1800000000",
            },
        )
        with self.assertRaisesRegex(ValueError, "non-genesis block"):
            EvmBlockStateAnchor.from_observations(
                malformed_head,
                state_observation(fixture),
            )

    def test_source_contract_runtime_matches_schema_event_ceiling(self) -> None:
        ordinary_kinds = tuple(
            kind
            for kind in ObservationKind
            if kind
            not in {
                ObservationKind.SOURCE_GAP,
                ObservationKind.SOURCE_HEARTBEAT,
            }
        )
        shapes = [
            EventShape(kind, Finality.PENDING, Visibility.FULL)
            for kind in ordinary_kinds
        ]
        shapes.extend(
            EventShape(kind, Finality.CONFIRMED, Visibility.FULL)
            for kind in ordinary_kinds[:4]
        )
        shapes.extend(
            (
                EventShape(
                    ObservationKind.SOURCE_GAP,
                    Finality.METADATA,
                    Visibility.METADATA,
                ),
                EventShape(
                    ObservationKind.SOURCE_HEARTBEAT,
                    Finality.METADATA,
                    Visibility.METADATA,
                ),
            )
        )
        events = tuple(sorted(shapes, key=lambda shape: shape.sort_key))
        self.assertEqual(len(events), MAX_SOURCE_CONTRACT_EVENTS + 1)
        with self.assertRaisesRegex(ValueError, "schema ceiling"):
            SourceContract(
                source_id="review-source",
                chain=Chain.ETHEREUM,
                source_kind=SourceKind.EVM_JSON_RPC,
                transport=Transport.JSON_RPC_HTTP,
                allowed_events=events,
                max_payload_bytes=1,
                max_future_clock_skew_ms=0,
                partial_payload_expected=False,
                official_reference="https://example.invalid/source-contract",
            )


if __name__ == "__main__":
    unittest.main()
