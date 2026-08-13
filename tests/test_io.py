from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from aladdin_mev_engine.io import StableReadError, read_stable_json


class StableReadTests(unittest.TestCase):
    def test_regular_bounded_json_is_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_text('{"ok":true}', encoding="utf-8")
            self.assertEqual(read_stable_json(path), {"ok": True})

    def test_symbolic_link_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            link = root / "link.json"
            target.write_text('{"ok":true}', encoding="utf-8")
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symbolic links are unavailable")
            with self.assertRaisesRegex(StableReadError, "symbolic-link"):
                read_stable_json(link)

    def test_byte_limit_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.json"
            path.write_text('{"value":"123456"}', encoding="utf-8")
            with self.assertRaisesRegex(StableReadError, "byte limit"):
                read_stable_json(path, max_bytes=5)


if __name__ == "__main__":
    unittest.main()
