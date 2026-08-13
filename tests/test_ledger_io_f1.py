from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aladdin_mev_engine.ledger import ObservationLedgerBuilder, serialize_segment
from aladdin_mev_engine.ledger_io import SegmentStorageError, read_segment_stable, write_segment_once
from f1_helpers import make_observation


def segment():
    builder = ObservationLedgerBuilder(segment_id="disk-segment", created_at_unix_ms=10_000)
    builder.append(make_observation(sequence=0))
    return builder.seal()


class SegmentStorageTests(unittest.TestCase):
    def test_write_once_and_stable_read_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "segment.jsonl"
            expected = segment()
            digest = write_segment_once(path, expected)
            self.assertEqual(digest, hashlib.sha256(serialize_segment(expected)).hexdigest())
            self.assertEqual(
                read_segment_stable(path, expected_payload_sha256=digest),
                expected,
            )
            info = path.stat()
            self.assertEqual(info.st_nlink, 1)
            self.assertEqual(info.st_mode & 0o222, 0)

    def test_external_payload_anchor_is_exact_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "segment.jsonl"
            digest = write_segment_once(path, segment())
            self.assertEqual(read_segment_stable(path, expected_payload_sha256=digest), segment())
            with self.assertRaises(SegmentStorageError):
                read_segment_stable(path, expected_payload_sha256="0" * 64)
            with self.assertRaises(SegmentStorageError):
                read_segment_stable(path, expected_payload_sha256="not-a-digest")

    def test_overwrite_is_forbidden(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "segment.jsonl"
            write_segment_once(path, segment())
            with self.assertRaises(SegmentStorageError):
                write_segment_once(path, segment())

    def test_symlink_target_is_rejected_for_read_and_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.write_bytes(serialize_segment(segment()))
            real.chmod(0o400)
            link = root / "link"
            link.symlink_to(real)
            with self.assertRaises(SegmentStorageError):
                read_segment_stable(link)
            with self.assertRaises(SegmentStorageError):
                write_segment_once(link, segment())

    def test_symlink_parent_and_parent_traversal_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_parent = root / "real-parent"
            real_parent.mkdir()
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaises(SegmentStorageError):
                write_segment_once(linked_parent / "segment.jsonl", segment())
            with self.assertRaises(SegmentStorageError):
                write_segment_once(root / "real-parent" / ".." / "escape.jsonl", segment())

    def test_tampered_file_fails_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "segment.jsonl"
            write_segment_once(path, segment())
            path.chmod(0o600)
            payload = bytearray(path.read_bytes())
            payload[payload.index(b"block_number") + 20] ^= 1
            path.write_bytes(payload)
            path.chmod(0o400)
            with self.assertRaises((SegmentStorageError, ValueError)):
                read_segment_stable(path)

    def test_writable_or_hardlinked_segment_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            writable = root / "writable.jsonl"
            writable.write_bytes(serialize_segment(segment()))
            with self.assertRaises(SegmentStorageError):
                read_segment_stable(writable)
            writable.chmod(0o400)
            alias = root / "alias.jsonl"
            os.link(writable, alias)
            with self.assertRaises(SegmentStorageError):
                read_segment_stable(writable)
            with self.assertRaises(SegmentStorageError):
                read_segment_stable(alias)

    def test_path_replacement_during_read_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "segment.jsonl"
            replacement = root / "replacement.jsonl"
            write_segment_once(path, segment())
            replacement.write_bytes(serialize_segment(segment()))
            replacement.chmod(0o400)
            real_read = os.read
            mutated = False

            def read_and_replace(descriptor: int, size: int) -> bytes:
                nonlocal mutated
                chunk = real_read(descriptor, size)
                if not mutated:
                    mutated = True
                    path.unlink()
                    replacement.rename(path)
                return chunk

            with patch("aladdin_mev_engine.ledger_io.os.read", side_effect=read_and_replace):
                with self.assertRaises(SegmentStorageError):
                    read_segment_stable(path)

    def test_missing_and_empty_files_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(SegmentStorageError):
                read_segment_stable(root / "missing")
            empty = root / "empty"
            empty.write_bytes(b"")
            empty.chmod(0o400)
            with self.assertRaises(SegmentStorageError):
                read_segment_stable(empty)


if __name__ == "__main__":
    unittest.main()
