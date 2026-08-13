from __future__ import annotations

from typing import TypeAlias

RlpItem: TypeAlias = bytes | tuple["RlpItem", ...]
MAX_RLP_BYTES = 1_048_576
MAX_RLP_DEPTH = 64
MAX_RLP_ITEMS = 100_000


class RlpError(ValueError):
    """Raised when RLP is malformed, non-canonical, or outside governed limits."""


def _length_bytes(length: int) -> bytes:
    if length <= 0:
        raise RlpError("long-form RLP length must be positive")
    return length.to_bytes((length.bit_length() + 7) // 8, "big")


def _encode(
    value: object,
    *,
    depth: int,
    item_counter: list[int],
) -> bytes:
    if depth > MAX_RLP_DEPTH:
        raise RlpError("RLP maximum nesting depth exceeded")
    item_counter[0] += 1
    if item_counter[0] > MAX_RLP_ITEMS:
        raise RlpError("RLP maximum item count exceeded")

    if type(value) is bytes:
        length = len(value)
        if length > MAX_RLP_BYTES:
            raise RlpError("RLP byte string exceeds the governed byte ceiling")
        if length == 1 and value[0] < 0x80:
            return value
        if length <= 55:
            return bytes((0x80 + length,)) + value
        encoded_length = _length_bytes(length)
        return bytes((0xB7 + len(encoded_length),)) + encoded_length + value

    if type(value) not in {tuple, list}:
        raise TypeError("RLP value must be exact bytes, tuple, or list")
    pieces: list[bytes] = []
    payload_length = 0
    for item in value:
        encoded = _encode(item, depth=depth + 1, item_counter=item_counter)
        payload_length += len(encoded)
        if payload_length > MAX_RLP_BYTES:
            raise RlpError("RLP list payload exceeds the governed byte ceiling")
        pieces.append(encoded)
    payload = b"".join(pieces)
    if len(payload) <= 55:
        return bytes((0xC0 + len(payload),)) + payload
    encoded_length = _length_bytes(len(payload))
    return bytes((0xF7 + len(encoded_length),)) + encoded_length + payload


def rlp_encode(value: object) -> bytes:
    encoded = _encode(value, depth=0, item_counter=[0])
    if len(encoded) > MAX_RLP_BYTES:
        raise RlpError("RLP output exceeds the governed byte ceiling")
    return encoded


def rlp_encode_uint(value: int) -> bytes:
    if type(value) is not int or value < 0:
        raise ValueError("RLP integer must be a non-negative exact integer")
    raw = b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")
    return rlp_encode(raw)


def _read_long_length(payload: bytes, offset: int, length_of_length: int) -> tuple[int, int]:
    end = offset + length_of_length
    if end > len(payload):
        raise RlpError("RLP length prefix exceeds input")
    encoded = payload[offset:end]
    if not encoded or encoded[0] == 0:
        raise RlpError("RLP long length is not minimally encoded")
    length = int.from_bytes(encoded, "big")
    if length < 56:
        raise RlpError("RLP long form used for a short payload")
    if length > MAX_RLP_BYTES:
        raise RlpError("RLP declared payload exceeds the governed byte ceiling")
    return length, end


def _decode_at(
    payload: bytes,
    offset: int,
    *,
    depth: int,
    item_counter: list[int],
) -> tuple[RlpItem, int]:
    if depth > MAX_RLP_DEPTH:
        raise RlpError("RLP maximum nesting depth exceeded")
    item_counter[0] += 1
    if item_counter[0] > MAX_RLP_ITEMS:
        raise RlpError("RLP maximum item count exceeded")
    if offset >= len(payload):
        raise RlpError("RLP item is truncated")

    prefix = payload[offset]
    if prefix <= 0x7F:
        return bytes((prefix,)), offset + 1

    if prefix <= 0xB7:
        length = prefix - 0x80
        start = offset + 1
        end = start + length
        if end > len(payload):
            raise RlpError("RLP short string is truncated")
        value = payload[start:end]
        if length == 1 and value[0] <= 0x7F:
            raise RlpError("RLP single-byte string is not minimally encoded")
        return value, end

    if prefix <= 0xBF:
        length, start = _read_long_length(payload, offset + 1, prefix - 0xB7)
        end = start + length
        if end > len(payload):
            raise RlpError("RLP long string is truncated")
        return payload[start:end], end

    if prefix <= 0xF7:
        payload_length = prefix - 0xC0
        start = offset + 1
        end = start + payload_length
        if end > len(payload):
            raise RlpError("RLP short list is truncated")
        items: list[RlpItem] = []
        cursor = start
        while cursor < end:
            item, cursor = _decode_at(
                payload,
                cursor,
                depth=depth + 1,
                item_counter=item_counter,
            )
            if cursor > end:
                raise RlpError("RLP list child exceeds its container")
            items.append(item)
        if cursor != end:
            raise RlpError("RLP list framing is inconsistent")
        return tuple(items), end

    payload_length, start = _read_long_length(payload, offset + 1, prefix - 0xF7)
    end = start + payload_length
    if end > len(payload):
        raise RlpError("RLP long list is truncated")
    items = []
    cursor = start
    while cursor < end:
        item, cursor = _decode_at(
            payload,
            cursor,
            depth=depth + 1,
            item_counter=item_counter,
        )
        if cursor > end:
            raise RlpError("RLP list child exceeds its container")
        items.append(item)
    if cursor != end:
        raise RlpError("RLP list framing is inconsistent")
    return tuple(items), end


def rlp_decode(payload: bytes) -> RlpItem:
    if type(payload) is not bytes:
        raise TypeError("RLP payload must be exact immutable bytes")
    if not payload:
        raise RlpError("RLP payload must not be empty")
    if len(payload) > MAX_RLP_BYTES:
        raise RlpError("RLP payload exceeds the governed byte ceiling")
    value, end = _decode_at(payload, 0, depth=0, item_counter=[0])
    if end != len(payload):
        raise RlpError("RLP payload contains trailing bytes")
    if rlp_encode(value) != payload:
        raise RlpError("RLP payload is not canonical")
    return value


def rlp_decode_uint(value: bytes, *, maximum_bits: int = 256) -> int:
    if type(value) is not bytes:
        raise TypeError("RLP integer payload must be exact bytes")
    if type(maximum_bits) is not int or not 1 <= maximum_bits <= 4096:
        raise ValueError("maximum_bits is outside the governed range")
    if value and value[0] == 0:
        raise RlpError("RLP integer has a leading zero")
    parsed = int.from_bytes(value, "big") if value else 0
    if parsed.bit_length() > maximum_bits:
        raise RlpError("RLP integer exceeds the governed width")
    return parsed


def require_rlp_bytes(name: str, value: RlpItem) -> bytes:
    if type(value) is not bytes:
        raise RlpError(f"{name} must be an RLP byte string")
    return value


def require_rlp_list(
    name: str,
    value: RlpItem,
    *,
    length: int | None = None,
) -> tuple[RlpItem, ...]:
    if type(value) is not tuple:
        raise RlpError(f"{name} must be an RLP list")
    if length is not None and len(value) != length:
        raise RlpError(f"{name} must contain exactly {length} items")
    return value
