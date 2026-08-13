from __future__ import annotations

import unittest

from aladdin_mev_engine.rlp import (
    MAX_RLP_BYTES,
    MAX_RLP_DEPTH,
    RlpError,
    rlp_decode,
    rlp_decode_uint,
    rlp_encode,
    rlp_encode_uint,
)


class RlpTests(unittest.TestCase):
    def test_documented_examples(self) -> None:
        self.assertEqual(rlp_encode(b"dog"), bytes.fromhex("83646f67"))
        self.assertEqual(
            rlp_encode((b"cat", b"dog")),
            bytes.fromhex("c88363617483646f67"),
        )
        self.assertEqual(rlp_encode(b""), b"\x80")
        self.assertEqual(rlp_encode(()), b"\xc0")
        self.assertEqual(rlp_encode_uint(0), b"\x80")
        self.assertEqual(rlp_encode_uint(15), b"\x0f")
        self.assertEqual(rlp_encode(b"\x04\x00"), b"\x82\x04\x00")

    def test_round_trip_nested_values(self) -> None:
        value = (b"cat", (b"puppy", b"cow"), b"horse", ((),), b"")
        self.assertEqual(rlp_decode(rlp_encode(value)), value)

    def test_rejects_non_minimal_single_byte(self) -> None:
        with self.assertRaisesRegex(RlpError, "single-byte"):
            rlp_decode(b"\x81\x00")
        with self.assertRaisesRegex(RlpError, "single-byte"):
            rlp_decode(b"\x81\x7f")

    def test_rejects_long_form_for_short_values(self) -> None:
        with self.assertRaisesRegex(RlpError, "long form"):
            rlp_decode(b"\xb8\x01a")
        with self.assertRaisesRegex(RlpError, "long form"):
            rlp_decode(b"\xf8\x01\xc0")

    def test_rejects_leading_zero_length_and_truncation(self) -> None:
        for payload in (
            b"\xb9\x00\x38" + b"a" * 56,
            b"\xb8\x38" + b"a" * 55,
            b"\xc2\x80",
            b"\x83ab",
        ):
            with self.assertRaises(RlpError):
                rlp_decode(payload)

    def test_rejects_trailing_bytes(self) -> None:
        with self.assertRaisesRegex(RlpError, "trailing"):
            rlp_decode(b"\x80\x80")

    def test_integer_semantics_reject_leading_zero(self) -> None:
        self.assertEqual(rlp_decode_uint(b""), 0)
        self.assertEqual(rlp_decode_uint(b"\x01"), 1)
        with self.assertRaisesRegex(RlpError, "leading zero"):
            rlp_decode_uint(b"\x00")
        with self.assertRaisesRegex(RlpError, "leading zero"):
            rlp_decode_uint(b"\x00\x01")

    def test_encoder_and_declared_lengths_obey_governed_limits(self) -> None:
        with self.assertRaisesRegex(RlpError, "byte string"):
            rlp_encode(b"x" * (MAX_RLP_BYTES + 1))

        nested: object = b""
        for _ in range(MAX_RLP_DEPTH + 2):
            nested = (nested,)
        with self.assertRaisesRegex(RlpError, "nesting depth"):
            rlp_encode(nested)

        declared_too_large = b"\xba\x10\x00\x01"
        with self.assertRaisesRegex(RlpError, "declared payload"):
            rlp_decode(declared_too_large)

    def test_type_and_width_limits_fail_closed(self) -> None:
        with self.assertRaises(TypeError):
            rlp_decode(bytearray(b"\x80"))  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            rlp_encode("cat")
        with self.assertRaises(ValueError):
            rlp_encode_uint(True)
        with self.assertRaises(RlpError):
            rlp_decode_uint(b"\x01\x00", maximum_bits=8)


if __name__ == "__main__":
    unittest.main()
