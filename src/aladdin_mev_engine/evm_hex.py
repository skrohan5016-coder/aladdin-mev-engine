from __future__ import annotations

import re

_HEX_DATA = re.compile(r"^0x(?:[0-9a-f]{2})*$")
_HEX_QUANTITY = re.compile(r"^0x(?:0|[1-9a-f][0-9a-f]*)$")
_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)$")


def parse_hex_data(
    name: str,
    value: object,
    *,
    exact_bytes: int | None = None,
    maximum_bytes: int = 1_048_576,
) -> bytes:
    if type(maximum_bytes) is not int or not 0 <= maximum_bytes <= 1_048_576:
        raise ValueError("maximum_bytes is outside the governed range")
    if exact_bytes is not None and (
        type(exact_bytes) is not int or not 0 <= exact_bytes <= maximum_bytes
    ):
        raise ValueError("exact_bytes is outside the governed range")
    if type(value) is not str or _HEX_DATA.fullmatch(value) is None:
        raise ValueError(f"{name} must be canonical lowercase even-length 0x data")
    encoded_bytes = (len(value) - 2) // 2
    if encoded_bytes > maximum_bytes:
        raise ValueError(f"{name} exceeds the governed byte ceiling")
    if exact_bytes is not None and encoded_bytes != exact_bytes:
        raise ValueError(f"{name} must contain exactly {exact_bytes} bytes")
    raw = bytes.fromhex(value[2:])
    return raw


def parse_hex_quantity(name: str, value: object, *, maximum_bits: int = 256) -> int:
    if type(maximum_bits) is not int or not 1 <= maximum_bits <= 4096:
        raise ValueError("maximum_bits is outside the governed range")
    if type(value) is not str or _HEX_QUANTITY.fullmatch(value) is None:
        raise ValueError(f"{name} must be a canonical lowercase Ethereum quantity")
    maximum_digits = (maximum_bits + 3) // 4
    if len(value) - 2 > maximum_digits:
        raise ValueError(f"{name} exceeds the governed integer width")
    parsed = int(value[2:], 16)
    if parsed.bit_length() > maximum_bits:
        raise ValueError(f"{name} exceeds the governed integer width")
    return parsed


def parse_decimal_integer(name: str, value: object, *, maximum_bits: int = 256) -> int:
    if type(maximum_bits) is not int or not 1 <= maximum_bits <= 4096:
        raise ValueError("maximum_bits is outside the governed range")
    if type(value) is not str or _DECIMAL.fullmatch(value) is None:
        raise ValueError(f"{name} must be a canonical non-negative decimal string")
    maximum_digits = (maximum_bits * 30_103 + 99_999) // 100_000
    if len(value) > maximum_digits:
        raise ValueError(f"{name} exceeds the governed integer width")
    parsed = int(value)
    if parsed.bit_length() > maximum_bits:
        raise ValueError(f"{name} exceeds the governed integer width")
    return parsed


def to_hex_data(value: bytes) -> str:
    if type(value) is not bytes:
        raise TypeError("hex data value must be exact immutable bytes")
    return "0x" + value.hex()


def to_hex_quantity(value: int) -> str:
    if type(value) is not int or value < 0:
        raise ValueError("hex quantity value must be a non-negative integer")
    return hex(value)


def to_decimal(value: int) -> str:
    if type(value) is not int or value < 0:
        raise ValueError("decimal value must be a non-negative integer")
    return str(value)
