from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.head_tracker import (
    HeadTracker,
    HeadTransition,
    HeadTransitionKind,
    ZERO_BLOCK_HASH,
)
from aladdin_mev_engine.ledger import (
    ObservationLedgerBuilder,
    parse_segment,
    serialize_segment,
)
from aladdin_mev_engine.source_contracts import (
    Finality,
    ObservationKind,
    Visibility,
)
from f1_helpers import make_observation
from scripts.check_repo_policy import workflow_policy_errors

ROOT = Path(__file__).resolve().parents[1]


def head_observation(
    *,
    sequence: int,
    number: int,
    block_hash_number: int,
    parent_hash_number: int | None,
):
    return make_observation(
        sequence=sequence,
        event_id=f"fresh-review-head-{sequence}-{block_hash_number}",
        observed_at=10_000 + sequence,
        emitted_at=10_000 + sequence,
        kind=ObservationKind.BLOCK_HEAD,
        finality=Finality.CONFIRMED,
        visibility=Visibility.FULL,
        payload={
            "block_number": str(number),
            "block_hash": "0x" + f"{block_hash_number:064x}",
            "parent_hash": ZERO_BLOCK_HASH
            if parent_hash_number is None
            else "0x" + f"{parent_hash_number:064x}",
            "block_timestamp_unix_s": str(100 + number),
        },
    )


class F1FreshReviewRemediationTests(unittest.TestCase):
    def test_semantically_equal_noncanonical_jsonl_line_is_rejected(self) -> None:
        builder = ObservationLedgerBuilder(
            segment_id="fresh-review-segment",
            created_at_unix_ms=20_000,
        )
        builder.append(make_observation(sequence=0, observed_at=10_000))
        payload = serialize_segment(builder.seal())
        lines = payload.splitlines()
        value = json.loads(lines[0])
        lines[0] = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=False,
            separators=(", ", ": "),
        ).encode("utf-8")
        with self.assertRaisesRegex(ValueError, "canonical JSON"):
            parse_segment(b"\n".join(lines) + b"\n")

    def test_known_ancestor_can_become_head_as_a_pure_rollback(self) -> None:
        tracker = HeadTracker(
            chain=make_observation().chain,
            source_id="ethereum-json-rpc",
            observation_kind=ObservationKind.BLOCK_HEAD,
            finality=Finality.CONFIRMED,
        )
        tracker.apply(
            head_observation(
                sequence=0,
                number=0,
                block_hash_number=1,
                parent_hash_number=None,
            )
        )
        tracker.apply(
            head_observation(
                sequence=1,
                number=1,
                block_hash_number=2,
                parent_hash_number=1,
            )
        )
        tracker.apply(
            head_observation(
                sequence=2,
                number=2,
                block_hash_number=3,
                parent_hash_number=2,
            )
        )
        rollback = tracker.apply(
            head_observation(
                sequence=3,
                number=1,
                block_hash_number=2,
                parent_hash_number=1,
            )
        )
        block_two = "0x" + f"{2:064x}"
        block_three = "0x" + f"{3:064x}"
        self.assertEqual(rollback.kind, HeadTransitionKind.REORG)
        self.assertEqual(rollback.new_head, block_two)
        self.assertEqual(rollback.common_ancestor, block_two)
        self.assertEqual(rollback.removed, (block_three,))
        self.assertEqual(rollback.added, ())
        self.assertEqual(
            HeadTransition.from_json_value(rollback.to_json_value()),
            rollback,
        )
        self.assertEqual(tracker.current_head.block_hash, block_two)

    def test_alternate_python_network_command_is_not_workflow_allowlisted(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "ci.yml"
        ).read_text(encoding="utf-8")
        mutated = workflow.replace(
            "python -m compileall -q src tests scripts",
            "python -c \"__import__('socket').socket()\"",
            1,
        )
        errors = workflow_policy_errors(mutated)
        self.assertTrue(
            any("run command is not allowlisted" in error for error in errors)
        )


if __name__ == "__main__":
    unittest.main()
