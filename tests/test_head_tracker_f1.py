from __future__ import annotations

import unittest

from aladdin_mev_engine.domain import Chain
from aladdin_mev_engine.head_tracker import (
    HeadTracker,
    HeadTransition,
    HeadTransitionKind,
    ZERO_BLOCK_HASH,
)
from aladdin_mev_engine.source_contracts import Finality, ObservationKind, Visibility
from f1_helpers import make_observation


def tracker(
    *,
    chain: Chain = Chain.ETHEREUM,
    source_id: str = "ethereum-json-rpc",
    observation_kind: ObservationKind = ObservationKind.BLOCK_HEAD,
    finality: Finality = Finality.CONFIRMED,
) -> HeadTracker:
    return HeadTracker(
        chain=chain,
        source_id=source_id,
        observation_kind=observation_kind,
        finality=finality,
    )


def head(
    sequence: int,
    number: int,
    block_hash_number: int,
    parent_hash_number: int | None,
    *,
    source_id: str = "ethereum-json-rpc",
    observed_at: int | None = None,
    block_timestamp: int | None = None,
    kind: ObservationKind = ObservationKind.BLOCK_HEAD,
    finality: Finality = Finality.CONFIRMED,
):
    return make_observation(
        source_id=source_id,
        sequence=sequence,
        event_id=f"head-{source_id}-{sequence}-{block_hash_number}",
        observed_at=1_000 + sequence if observed_at is None else observed_at,
        kind=kind,
        finality=finality,
        visibility=Visibility.FULL,
        payload={
            "block_number": str(number),
            "block_hash": "0x" + f"{block_hash_number:064x}",
            "parent_hash": ZERO_BLOCK_HASH
            if parent_hash_number is None
            else "0x" + f"{parent_hash_number:064x}",
            "block_timestamp_unix_s": str(
                100 + number if block_timestamp is None else block_timestamp
            ),
        },
    )


class HeadTrackerTests(unittest.TestCase):
    def test_bootstrap_and_extension(self) -> None:
        subject = tracker()
        bootstrap_envelope = head(0, 0, 1, None)
        bootstrap = subject.apply(bootstrap_envelope)
        self.assertEqual(bootstrap.kind, HeadTransitionKind.BOOTSTRAP)
        self.assertEqual(bootstrap.observation_sha256, bootstrap_envelope.digest)
        extension = subject.apply(head(1, 1, 2, 1))
        self.assertEqual(extension.kind, HeadTransitionKind.EXTEND)
        self.assertEqual(subject.current_head.block_hash, "0x" + f"{2:064x}")

    def test_tracker_can_bootstrap_from_a_non_genesis_head(self) -> None:
        subject = tracker()
        transition = subject.apply(head(50, 20_000_000, 100, 99))
        self.assertEqual(transition.kind, HeadTransitionKind.BOOTSTRAP)
        self.assertIsNone(transition.old_head)

    def test_single_branch_reorg_reports_removed_and_added_paths(self) -> None:
        subject = tracker()
        subject.apply(head(0, 0, 1, None))
        subject.apply(head(1, 1, 2, 1))
        subject.apply(head(2, 2, 3, 2))
        transition = subject.apply(head(3, 1, 20, 1))
        self.assertEqual(transition.kind, HeadTransitionKind.REORG)
        self.assertEqual(transition.common_ancestor, "0x" + f"{1:064x}")
        self.assertEqual(
            transition.removed,
            ("0x" + f"{3:064x}", "0x" + f"{2:064x}"),
        )
        self.assertEqual(transition.added, ("0x" + f"{20:064x}",))
        self.assertEqual(subject.current_head.block_hash, "0x" + f"{20:064x}")

    def test_unknown_parent_is_orphaned_without_retaining_untrusted_topology(self) -> None:
        subject = tracker()
        subject.apply(head(0, 0, 1, None))
        transition = subject.apply(head(1, 10, 100, 99))
        self.assertEqual(transition.kind, HeadTransitionKind.ORPHAN)
        self.assertEqual(transition.old_head, transition.new_head)
        self.assertEqual(subject.current_head.block_hash, "0x" + f"{1:064x}")
        self.assertEqual(subject.tracked_head_count, 1)

    def test_orphan_can_be_retried_after_parent_becomes_known(self) -> None:
        subject = tracker()
        subject.apply(head(0, 0, 1, None))
        subject.apply(head(1, 2, 3, 2))
        parent = subject.apply(head(2, 1, 2, 1))
        self.assertEqual(parent.kind, HeadTransitionKind.EXTEND)
        child = subject.apply(head(3, 2, 3, 2))
        self.assertEqual(child.kind, HeadTransitionKind.EXTEND)
        self.assertEqual(subject.current_head.block_hash, "0x" + f"{3:064x}")

    def test_duplicate_current_hash_does_not_change_head(self) -> None:
        subject = tracker()
        subject.apply(head(0, 0, 1, None))
        duplicate = subject.apply(head(1, 0, 1, None))
        self.assertEqual(duplicate.kind, HeadTransitionKind.DUPLICATE)
        self.assertEqual(duplicate.old_head, duplicate.new_head)
        self.assertEqual(duplicate.common_ancestor, duplicate.old_head)

    def test_known_noncurrent_block_can_be_reobserved_and_reorg_back(self) -> None:
        subject = tracker()
        subject.apply(head(0, 0, 1, None))
        subject.apply(head(1, 1, 2, 1))
        subject.apply(head(2, 1, 20, 1))
        transition = subject.apply(head(3, 1, 2, 1))
        self.assertEqual(transition.kind, HeadTransitionKind.REORG)
        self.assertEqual(transition.new_head, "0x" + f"{2:064x}")

    def test_duplicate_hash_with_conflicting_metadata_is_rejected_transactionally(self) -> None:
        subject = tracker()
        subject.apply(head(10, 0, 1, None, block_timestamp=100))
        with self.assertRaises(ValueError):
            subject.apply(head(11, 0, 1, None, block_timestamp=101))
        duplicate = subject.apply(head(11, 0, 1, None, block_timestamp=100))
        self.assertEqual(duplicate.kind, HeadTransitionKind.DUPLICATE)

    def test_filtered_head_sequences_must_increase_but_need_not_be_contiguous(self) -> None:
        subject = tracker()
        subject.apply(head(5, 0, 1, None))
        subject.apply(head(9, 1, 2, 1))
        with self.assertRaises(ValueError):
            subject.apply(head(9, 2, 3, 2))
        with self.assertRaises(ValueError):
            subject.apply(head(8, 2, 3, 2))

    def test_rejected_head_does_not_consume_sequence_or_insert_node(self) -> None:
        subject = tracker()
        subject.apply(head(0, 0, 1, None))
        with self.assertRaises(ValueError):
            subject.apply(head(1, 2, 2, 1))
        self.assertEqual(subject.tracked_head_count, 1)
        accepted = subject.apply(head(1, 1, 2, 1))
        self.assertEqual(accepted.kind, HeadTransitionKind.EXTEND)
        self.assertEqual(subject.tracked_head_count, 2)

    def test_cross_source_chain_kind_or_finality_is_rejected(self) -> None:
        subject = tracker()
        with self.assertRaises(ValueError):
            subject.apply(head(0, 0, 1, None, source_id="base-json-rpc"))
        with self.assertRaises(ValueError):
            tracker(chain=Chain.ETHEREUM, source_id="base-json-rpc")
        with self.assertRaises(ValueError):
            subject.apply(head(0, 0, 1, None, finality=Finality.FINALIZED))
        with self.assertRaises(ValueError):
            subject.apply(
                make_observation(
                    sequence=0,
                    kind=ObservationKind.PENDING_TRANSACTION,
                    finality=Finality.PENDING,
                    visibility=Visibility.FULL,
                    payload={"hash": "0x" + "1" * 64},
                )
            )

    def test_source_without_exact_full_block_stream_cannot_back_a_tracker(self) -> None:
        with self.assertRaises(ValueError):
            tracker(source_id="ethereum-mev-share")
        with self.assertRaises(ValueError):
            tracker(chain=Chain.ARBITRUM, source_id="arbitrum-sequencer-feed")
        base = tracker(
            chain=Chain.BASE,
            source_id="base-flashblocks",
            observation_kind=ObservationKind.PRECONFIRMED_BLOCK,
            finality=Finality.PRECONFIRMED,
        )
        transition = base.apply(
            head(
                0,
                1,
                2,
                1,
                source_id="base-flashblocks",
                kind=ObservationKind.PRECONFIRMED_BLOCK,
                finality=Finality.PRECONFIRMED,
            )
        )
        self.assertEqual(transition.kind, HeadTransitionKind.BOOTSTRAP)

    def test_known_parent_number_and_timestamp_must_be_monotonic(self) -> None:
        subject = tracker()
        subject.apply(head(0, 0, 1, None, block_timestamp=100))
        with self.assertRaises(ValueError):
            subject.apply(head(1, 2, 2, 1, block_timestamp=101))
        with self.assertRaises(ValueError):
            subject.apply(head(1, 1, 2, 1, block_timestamp=99))
        accepted = subject.apply(head(1, 1, 2, 1, block_timestamp=100))
        self.assertEqual(accepted.kind, HeadTransitionKind.EXTEND)

    def test_partial_or_malformed_head_payload_is_rejected(self) -> None:
        subject = tracker()
        with self.assertRaises(ValueError):
            make_observation(
                sequence=0,
                kind=ObservationKind.BLOCK_HEAD,
                finality=Finality.CONFIRMED,
                visibility=Visibility.HASH_ONLY,
                payload={"hash": "0x" + "1" * 64},
            )
        malformed = make_observation(
            sequence=0,
            kind=ObservationKind.BLOCK_HEAD,
            finality=Finality.CONFIRMED,
            visibility=Visibility.FULL,
            payload={
                "block_number": "0",
                "block_hash": "0xABC",
                "parent_hash": ZERO_BLOCK_HASH,
                "block_timestamp_unix_s": "1",
            },
        )
        with self.assertRaises(ValueError):
            subject.apply(malformed)

    def test_transition_round_trip_binds_trigger_and_stream(self) -> None:
        subject = tracker()
        envelope = head(0, 0, 1, None)
        transition = subject.apply(envelope)
        restored = HeadTransition.from_json_value(transition.to_json_value())
        self.assertEqual(restored, transition)
        self.assertEqual(transition.chain, Chain.ETHEREUM)
        self.assertEqual(transition.source_id, "ethereum-json-rpc")
        self.assertEqual(transition.source_sequence, 0)
        self.assertEqual(transition.observation_sha256, envelope.digest)
        transition.verify_observation(envelope)
        value = transition.to_json_value()
        value["observation_sha256"] = "0" * 64
        tampered = HeadTransition.from_json_value(value)
        with self.assertRaises(ValueError):
            tampered.verify_observation(envelope)
        value = transition.to_json_value()
        value["old_head"] = value["new_head"]
        with self.assertRaises(ValueError):
            HeadTransition.from_json_value(value)

    def test_transition_rejects_overlapping_paths_and_zero_heads(self) -> None:
        subject = tracker()
        subject.apply(head(0, 0, 1, None))
        subject.apply(head(1, 1, 2, 1))
        subject.apply(head(2, 2, 3, 2))
        transition = subject.apply(head(3, 1, 20, 1))
        value = transition.to_json_value()
        value["added"] = [value["removed"][0], value["new_head"]]
        with self.assertRaises(ValueError):
            HeadTransition.from_json_value(value)
        value = transition.to_json_value()
        value["new_head"] = ZERO_BLOCK_HASH
        with self.assertRaises(ValueError):
            HeadTransition.from_json_value(value)

    def test_solana_tracker_is_not_accidentally_enabled(self) -> None:
        with self.assertRaises(ValueError):
            tracker(chain=Chain.SOLANA)


if __name__ == "__main__":
    unittest.main()
