from __future__ import annotations

MASK_64 = (1 << 64) - 1
KECCAK_256_RATE_BYTES = 136

_ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)

_ROTATION_OFFSETS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def _rotate_left_64(value: int, shift: int) -> int:
    if shift == 0:
        return value & MASK_64
    return ((value << shift) | (value >> (64 - shift))) & MASK_64


def _keccak_f1600(state: list[int]) -> None:
    if len(state) != 25:
        raise ValueError("Keccak state must contain exactly 25 lanes")

    for round_constant in _ROUND_CONSTANTS:
        column_parity = [
            state[x]
            ^ state[x + 5]
            ^ state[x + 10]
            ^ state[x + 15]
            ^ state[x + 20]
            for x in range(5)
        ]
        theta = [
            column_parity[(x - 1) % 5]
            ^ _rotate_left_64(column_parity[(x + 1) % 5], 1)
            for x in range(5)
        ]
        for y in range(5):
            for x in range(5):
                index = x + 5 * y
                state[index] = (state[index] ^ theta[x]) & MASK_64

        rotated = [0] * 25
        for y in range(5):
            for x in range(5):
                new_x = y
                new_y = (2 * x + 3 * y) % 5
                rotated[new_x + 5 * new_y] = _rotate_left_64(
                    state[x + 5 * y],
                    _ROTATION_OFFSETS[x][y],
                )

        for y in range(5):
            row = [rotated[x + 5 * y] for x in range(5)]
            for x in range(5):
                state[x + 5 * y] = (
                    row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
                ) & MASK_64

        state[0] = (state[0] ^ round_constant) & MASK_64


def keccak256(payload: bytes) -> bytes:
    """Return legacy Ethereum Keccak-256, not NIST SHA3-256."""

    if type(payload) is not bytes:
        raise TypeError("Keccak payload must be exact immutable bytes")

    state = [0] * 25
    offset = 0
    while offset + KECCAK_256_RATE_BYTES <= len(payload):
        block = payload[offset : offset + KECCAK_256_RATE_BYTES]
        for lane_index in range(KECCAK_256_RATE_BYTES // 8):
            lane = int.from_bytes(
                block[lane_index * 8 : (lane_index + 1) * 8],
                "little",
            )
            state[lane_index] ^= lane
        _keccak_f1600(state)
        offset += KECCAK_256_RATE_BYTES

    final_block = bytearray(KECCAK_256_RATE_BYTES)
    remainder = payload[offset:]
    final_block[: len(remainder)] = remainder
    final_block[len(remainder)] ^= 0x01
    final_block[-1] ^= 0x80
    for lane_index in range(KECCAK_256_RATE_BYTES // 8):
        lane = int.from_bytes(
            final_block[lane_index * 8 : (lane_index + 1) * 8],
            "little",
        )
        state[lane_index] ^= lane
    _keccak_f1600(state)

    output = bytearray()
    while len(output) < 32:
        for lane_index in range(KECCAK_256_RATE_BYTES // 8):
            output.extend(state[lane_index].to_bytes(8, "little"))
            if len(output) >= 32:
                return bytes(output[:32])
        _keccak_f1600(state)
    raise AssertionError("unreachable")


def keccak256_hex(payload: bytes) -> str:
    return keccak256(payload).hex()
