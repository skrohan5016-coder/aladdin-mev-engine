from __future__ import annotations

from dataclasses import dataclass

from .keccak import keccak256

FIELD_MODULUS = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
GROUP_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GENERATOR_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GENERATOR_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
HALF_GROUP_ORDER = GROUP_ORDER // 2


@dataclass(frozen=True, slots=True)
class Secp256k1Point:
    x: int
    y: int

    def __post_init__(self) -> None:
        if type(self.x) is not int or type(self.y) is not int:
            raise TypeError("secp256k1 coordinates must be exact integers")
        if not 0 <= self.x < FIELD_MODULUS or not 0 <= self.y < FIELD_MODULUS:
            raise ValueError("secp256k1 point is outside the field")
        if (self.y * self.y - (self.x * self.x * self.x + 7)) % FIELD_MODULUS:
            raise ValueError("secp256k1 point is not on the curve")

    def to_uncompressed_bytes(self) -> bytes:
        return b"\x04" + self.x.to_bytes(32, "big") + self.y.to_bytes(32, "big")


GENERATOR = Secp256k1Point(GENERATOR_X, GENERATOR_Y)
PointOrInfinity = Secp256k1Point | None


def _require_scalar(name: str, value: object, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if type(value) is not int or not minimum <= value < GROUP_ORDER:
        boundary = "non-negative" if allow_zero else "positive"
        raise ValueError(f"{name} must be a {boundary} secp256k1 scalar")
    return value


def point_negate(point: PointOrInfinity) -> PointOrInfinity:
    if point is None:
        return None
    if type(point) is not Secp256k1Point:
        raise TypeError("point must be an exact Secp256k1Point or infinity")
    return Secp256k1Point(point.x, (-point.y) % FIELD_MODULUS)


def point_add(left: PointOrInfinity, right: PointOrInfinity) -> PointOrInfinity:
    if left is None:
        if right is not None and type(right) is not Secp256k1Point:
            raise TypeError("right point is ungoverned")
        return right
    if right is None:
        if type(left) is not Secp256k1Point:
            raise TypeError("left point is ungoverned")
        return left
    if type(left) is not Secp256k1Point or type(right) is not Secp256k1Point:
        raise TypeError("secp256k1 addition requires exact points")
    if left.x == right.x:
        if (left.y + right.y) % FIELD_MODULUS == 0 or left.y == 0:
            return None
        slope = (3 * left.x * left.x) * pow(2 * left.y, -1, FIELD_MODULUS)
    else:
        slope = (right.y - left.y) * pow(right.x - left.x, -1, FIELD_MODULUS)
    slope %= FIELD_MODULUS
    x = (slope * slope - left.x - right.x) % FIELD_MODULUS
    y = (slope * (left.x - x) - left.y) % FIELD_MODULUS
    return Secp256k1Point(x, y)


def scalar_multiply(scalar: int, point: PointOrInfinity = GENERATOR) -> PointOrInfinity:
    if type(scalar) is not int or not 0 <= scalar <= GROUP_ORDER:
        raise ValueError(
            "scalar must be an exact integer from zero through the secp256k1 group order"
        )
    if point is not None and type(point) is not Secp256k1Point:
        raise TypeError("point must be an exact Secp256k1Point or infinity")
    if point is None or scalar == 0:
        return None
    result: PointOrInfinity = None
    addend: PointOrInfinity = point
    remaining = scalar
    while remaining:
        if remaining & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        remaining >>= 1
    return result


def lift_x(x: int, y_parity: int) -> Secp256k1Point:
    if type(x) is not int or not 0 <= x < FIELD_MODULUS:
        raise ValueError("x must be an exact secp256k1 field element")
    if type(y_parity) is not int or y_parity not in (0, 1):
        raise ValueError("y_parity must be 0 or 1")
    y_squared = (x * x * x + 7) % FIELD_MODULUS
    y = pow(y_squared, (FIELD_MODULUS + 1) // 4, FIELD_MODULUS)
    if (y * y) % FIELD_MODULUS != y_squared:
        raise ValueError("x does not lift to a secp256k1 point")
    if (y & 1) != y_parity:
        y = FIELD_MODULUS - y
    return Secp256k1Point(x, y)


def public_key_to_address(public_key: Secp256k1Point) -> bytes:
    if type(public_key) is not Secp256k1Point:
        raise TypeError("public_key must be an exact Secp256k1Point")
    encoded = public_key.x.to_bytes(32, "big") + public_key.y.to_bytes(32, "big")
    return keccak256(encoded)[-20:]


def verify_signature(
    message_hash: bytes,
    r: int,
    s: int,
    public_key: Secp256k1Point,
) -> bool:
    if type(message_hash) is not bytes or len(message_hash) != 32:
        raise ValueError("message_hash must be exact 32-byte data")
    _require_scalar("r", r)
    _require_scalar("s", s)
    if type(public_key) is not Secp256k1Point:
        raise TypeError("public_key must be an exact Secp256k1Point")
    z = int.from_bytes(message_hash, "big") % GROUP_ORDER
    inverse_s = pow(s, -1, GROUP_ORDER)
    left = scalar_multiply((z * inverse_s) % GROUP_ORDER, GENERATOR)
    right = scalar_multiply((r * inverse_s) % GROUP_ORDER, public_key)
    result = point_add(left, right)
    return result is not None and result.x % GROUP_ORDER == r


def recover_public_keys(
    message_hash: bytes,
    r: int,
    s: int,
    y_parity: int,
) -> tuple[Secp256k1Point, ...]:
    if type(message_hash) is not bytes or len(message_hash) != 32:
        raise ValueError("message_hash must be exact 32-byte data")
    _require_scalar("r", r)
    _require_scalar("s", s)
    if type(y_parity) is not int or y_parity not in (0, 1):
        raise ValueError("y_parity must be 0 or 1")
    z = int.from_bytes(message_hash, "big") % GROUP_ORDER
    inverse_r = pow(r, -1, GROUP_ORDER)
    candidates: list[Secp256k1Point] = []
    for overflow_bit in (0, 1):
        x = r + overflow_bit * GROUP_ORDER
        if x >= FIELD_MODULUS:
            continue
        try:
            ephemeral = lift_x(x, y_parity)
        except ValueError:
            continue
        if scalar_multiply(GROUP_ORDER, ephemeral) is not None:
            continue
        s_times_r = scalar_multiply(s, ephemeral)
        minus_z_times_g = scalar_multiply((-z) % GROUP_ORDER, GENERATOR)
        recovered = scalar_multiply(inverse_r, point_add(s_times_r, minus_z_times_g))
        if recovered is None or not verify_signature(message_hash, r, s, recovered):
            continue
        if recovered not in candidates:
            candidates.append(recovered)
    return tuple(sorted(candidates, key=lambda item: (item.x, item.y)))


def recover_addresses(
    message_hash: bytes,
    r: int,
    s: int,
    y_parity: int,
) -> tuple[bytes, ...]:
    addresses = {
        public_key_to_address(item)
        for item in recover_public_keys(message_hash, r, s, y_parity)
    }
    return tuple(sorted(addresses))
