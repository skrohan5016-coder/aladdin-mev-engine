from __future__ import annotations

import unittest

from aladdin_mev_engine.canonical import CanonicalJsonError, canonical_json_bytes, canonical_sha256, strict_json_loads


class CanonicalJsonTests(unittest.TestCase):
    def test_key_order_does_not_change_digest(self) -> None:
        left = {"b": [2, 3], "a": 1}
        right = {"a": 1, "b": [2, 3]}
        self.assertEqual(canonical_json_bytes(left), canonical_json_bytes(right))
        self.assertEqual(canonical_sha256(left), canonical_sha256(right))

    def test_duplicate_keys_fail_closed(self) -> None:
        with self.assertRaisesRegex(CanonicalJsonError, "duplicate object key"):
            strict_json_loads('{"a":1,"a":2}')

    def test_floats_and_non_finite_values_are_forbidden(self) -> None:
        for payload in ('{"value":1.5}', '{"value":NaN}', '{"value":Infinity}'):
            with self.subTest(payload=payload), self.assertRaises(CanonicalJsonError):
                strict_json_loads(payload)

    def test_depth_limit_is_enforced(self) -> None:
        payload = "[" * 34 + "0" + "]" * 34
        with self.assertRaisesRegex(CanonicalJsonError, "nesting depth"):
            strict_json_loads(payload)

    def test_invalid_utf8_fails(self) -> None:
        with self.assertRaisesRegex(CanonicalJsonError, "valid UTF-8"):
            strict_json_loads(b"\xff")


if __name__ == "__main__":
    unittest.main()
