from __future__ import annotations

import unittest

from aladdin_mev_engine.canonical import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_ITEMS,
    DEFAULT_MAX_JSON_BYTES,
    CanonicalJsonError,
    canonical_json_bytes,
    canonical_sha256,
    strict_json_loads,
)


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

    def test_invalid_limits_fail_closed(self) -> None:
        for name, value in (("max_bytes", -1), ("max_depth", True), ("max_items", -1)):
            with self.subTest(name=name), self.assertRaisesRegex(CanonicalJsonError, name):
                strict_json_loads("0", **{name: value})

    def test_configured_limits_cannot_exceed_governed_ceilings(self) -> None:
        cases = (
            ("max_bytes", DEFAULT_MAX_JSON_BYTES + 1),
            ("max_depth", DEFAULT_MAX_DEPTH + 1),
            ("max_items", DEFAULT_MAX_ITEMS + 1),
        )
        for name, value in cases:
            with self.subTest(name=name), self.assertRaisesRegex(CanonicalJsonError, "governed maximum"):
                strict_json_loads("0", **{name: value})

    def test_canonical_output_is_also_byte_bounded(self) -> None:
        with self.assertRaisesRegex(CanonicalJsonError, "canonical JSON byte limit"):
            canonical_json_bytes("x" * DEFAULT_MAX_JSON_BYTES)

    def test_parser_integer_limit_is_normalized(self) -> None:
        with self.assertRaisesRegex(CanonicalJsonError, "parser safety limits"):
            strict_json_loads("9" * 5_000)

    def test_unpaired_surrogate_cannot_enter_canonical_evidence(self) -> None:
        with self.assertRaises(CanonicalJsonError):
            strict_json_loads('"\ud800"')
        with self.assertRaises(CanonicalJsonError):
            canonical_json_bytes("\ud800")


if __name__ == "__main__":
    unittest.main()
