from __future__ import annotations

import unittest

from aladdin_mev_engine.evm_hex import (
    parse_decimal_integer,
    parse_hex_data,
    parse_hex_quantity,
    to_decimal,
    to_hex_data,
    to_hex_quantity,
)


class EvmHexTests(unittest.TestCase):
    def test_canonical_data_quantity_and_decimal_round_trip(self) -> None:
        self.assertEqual(parse_hex_data("data", "0x00ff", exact_bytes=2), b"\x00\xff")
        self.assertEqual(parse_hex_quantity("quantity", "0xff"), 255)
        self.assertEqual(parse_decimal_integer("decimal", "255"), 255)
        self.assertEqual(to_hex_data(b"\x00\xff"), "0x00ff")
        self.assertEqual(to_hex_quantity(255), "0xff")
        self.assertEqual(to_decimal(255), "255")

    def test_noncanonical_forms_fail_closed(self) -> None:
        for value in ("00", "0x0", "0xGG", "0xAB"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_hex_data("data", value)
        for value in ("0x00", "0x01", "0xA", "1"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_hex_quantity("quantity", value)
        for value in ("01", "+1", "-1", "1.0"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_decimal_integer("decimal", value)

    def test_encoded_width_is_rejected_before_materialization(self) -> None:
        with self.assertRaisesRegex(ValueError, "byte ceiling"):
            parse_hex_data("data", "0x" + "00" * 33, maximum_bytes=32)
        with self.assertRaisesRegex(ValueError, "exactly 20"):
            parse_hex_data("address", "0x" + "00" * 19, exact_bytes=20, maximum_bytes=20)
        with self.assertRaisesRegex(ValueError, "integer width"):
            parse_hex_quantity("quantity", "0x1" + "0" * 64, maximum_bits=256)
        with self.assertRaisesRegex(ValueError, "integer width"):
            parse_decimal_integer("decimal", "1" + "0" * 78, maximum_bits=256)

    def test_boolean_and_invalid_limits_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            parse_hex_data("data", "0x", maximum_bytes=True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            parse_hex_quantity("quantity", "0x0", maximum_bits=0)
        with self.assertRaises(ValueError):
            parse_decimal_integer("decimal", "0", maximum_bits=4097)


if __name__ == "__main__":
    unittest.main()
