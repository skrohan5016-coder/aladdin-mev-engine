from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .canonical import canonical_json_bytes, canonical_sha256
from .constant_product import MAX_UINT256
from .domain import Chain, require_bounded_text, require_sha256
from .evm_hex import to_hex_data

ASSET_SCHEMA = "aladdin-mev-asset-id/v1"
RATE_SCHEMA = "aladdin-mev-conservative-valuation-rate/v1"
BOOK_SCHEMA = "aladdin-mev-valuation-book/v1"
MAX_UINT64 = (1 << 64) - 1
MAX_VALUATION_RATES = 64


class AssetKind(StrEnum):
    NATIVE = "native"
    ERC20 = "erc20"


def _uint(name: str, value: object, *, positive: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT256:
        raise ValueError(f"{name} must be an unsigned 256-bit exact integer")
    if positive and value == 0:
        raise ValueError(f"{name} must be positive")
    return value


def _time(name: str, value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT64:
        raise ValueError(f"{name} must be an unsigned 64-bit exact integer")
    return value


def _checked_mul(left: int, right: int, name: str) -> int:
    _uint(f"{name} left", left)
    _uint(f"{name} right", right)
    if left and right > MAX_UINT256 // left:
        raise ValueError(f"{name} multiplication exceeds uint256")
    return left * right


def _address(name: str, value: object, *, nonzero: bool = True) -> bytes:
    if type(value) is not bytes or len(value) != 20:
        raise ValueError(f"{name} must be exact immutable 20-byte data")
    if nonzero and value == bytes(20):
        raise ValueError(f"{name} cannot be zero")
    return value


def valuation_pair_sha256(asset_in: AssetId, asset_out: AssetId) -> str:
    if type(asset_in) is not AssetId or type(asset_out) is not AssetId:
        raise TypeError("valuation pair assets must be exact AssetId values")
    if asset_in.chain is not asset_out.chain:
        raise ValueError("valuation pair cannot cross chains")
    if asset_in == asset_out:
        raise ValueError("identity valuation pair is forbidden")
    return canonical_sha256(
        {
            "asset_in": asset_in.to_json_value(),
            "asset_out": asset_out.to_json_value(),
        }
    )


@dataclass(frozen=True, slots=True)
class AssetId:
    chain: Chain
    kind: AssetKind
    address: bytes | None
    schema: str = ASSET_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != ASSET_SCHEMA:
            raise ValueError("unsupported asset-id schema")
        if type(self.chain) is not Chain:
            raise TypeError("chain must be an exact Chain")
        if type(self.kind) is not AssetKind:
            raise TypeError("kind must be an exact AssetKind")
        if self.kind is AssetKind.NATIVE:
            if self.address is not None:
                raise ValueError("native asset cannot carry a token address")
        elif self.kind is AssetKind.ERC20:
            _address("address", self.address)
        else:  # pragma: no cover - exact enum check above is fail-closed.
            raise ValueError("unsupported asset kind")
        canonical_json_bytes(self.to_json_value())

    @classmethod
    def native(cls, chain: Chain) -> AssetId:
        return cls(chain=chain, kind=AssetKind.NATIVE, address=None)

    @classmethod
    def erc20(cls, chain: Chain, address: bytes) -> AssetId:
        return cls(chain=chain, kind=AssetKind.ERC20, address=address)

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "chain": self.chain.value,
            "kind": self.kind.value,
            "address": None if self.address is None else to_hex_data(self.address),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class AssetAmount:
    asset: AssetId
    amount: int

    def __post_init__(self) -> None:
        if type(self.asset) is not AssetId:
            raise TypeError("asset must be an exact AssetId")
        _uint("amount", self.amount)
        canonical_json_bytes(self.to_json_value())

    def to_json_value(self) -> dict[str, object]:
        return {"asset": self.asset.to_json_value(), "amount": str(self.amount)}

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class ConservativeValuationRate:
    rate_id: str
    asset_in: AssetId
    asset_out: AssetId
    numerator: int
    denominator: int
    observed_at_unix_ms: int
    valid_until_unix_ms: int
    source_sha256: str
    schema: str = RATE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != RATE_SCHEMA:
            raise ValueError("unsupported conservative valuation-rate schema")
        require_bounded_text("rate_id", self.rate_id, maximum=128)
        if type(self.asset_in) is not AssetId or type(self.asset_out) is not AssetId:
            raise TypeError("valuation assets must be exact AssetId values")
        if self.asset_in.chain is not self.asset_out.chain:
            raise ValueError("valuation cannot cross chains")
        if self.asset_in == self.asset_out:
            raise ValueError("identity valuation rates are forbidden")
        _uint("numerator", self.numerator, positive=True)
        _uint("denominator", self.denominator, positive=True)
        _time("observed_at_unix_ms", self.observed_at_unix_ms)
        _time("valid_until_unix_ms", self.valid_until_unix_ms)
        if self.valid_until_unix_ms < self.observed_at_unix_ms:
            raise ValueError("valuation validity cannot precede observation")
        require_sha256("source_sha256", self.source_sha256)
        canonical_json_bytes(self.to_json_value())

    def is_valid_at(self, at_unix_ms: int) -> bool:
        _time("at_unix_ms", at_unix_ms)
        return self.observed_at_unix_ms <= at_unix_ms <= self.valid_until_unix_ms

    def convert_upper_bound(self, amount: AssetAmount, *, at_unix_ms: int) -> AssetAmount:
        if type(amount) is not AssetAmount:
            raise TypeError("amount must be an exact AssetAmount")
        if amount.asset != self.asset_in:
            raise ValueError("valuation input asset mismatch")
        if not self.is_valid_at(at_unix_ms):
            raise ValueError("valuation rate is not valid at the evidence time")
        if amount.amount and self.numerator > MAX_UINT256 // amount.amount:
            raise ValueError("valuation multiplication exceeds uint256")
        product = _checked_mul(
            amount.amount,
            self.numerator,
            "valuation",
        )
        quotient, remainder = divmod(product, self.denominator)
        converted = quotient + (1 if remainder else 0)
        if converted > MAX_UINT256:
            raise ValueError("converted upper bound exceeds uint256")
        return AssetAmount(self.asset_out, converted)

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "rate_id": self.rate_id,
            "asset_in": self.asset_in.to_json_value(),
            "asset_out": self.asset_out.to_json_value(),
            "numerator": str(self.numerator),
            "denominator": str(self.denominator),
            "rounding": "ceiling",
            "observed_at_unix_ms": str(self.observed_at_unix_ms),
            "valid_until_unix_ms": str(self.valid_until_unix_ms),
            "source_sha256": self.source_sha256,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class ValuationBook:
    rates: tuple[ConservativeValuationRate, ...]
    schema: str = BOOK_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != BOOK_SCHEMA:
            raise ValueError("unsupported valuation-book schema")
        if type(self.rates) is not tuple:
            raise TypeError("rates must be an exact tuple")
        if len(self.rates) > MAX_VALUATION_RATES:
            raise ValueError("valuation book exceeds the governed rate ceiling")
        if any(type(item) is not ConservativeValuationRate for item in self.rates):
            raise TypeError("valuation book contains an ungoverned rate")
        ordered = tuple(
            sorted(
                self.rates,
                key=lambda item: (
                    item.asset_in.digest,
                    item.asset_out.digest,
                    item.rate_id,
                    item.digest,
                ),
            )
        )
        object.__setattr__(self, "rates", ordered)
        pairs = [(item.asset_in, item.asset_out) for item in ordered]
        if len(pairs) != len(set(pairs)):
            raise ValueError("valuation book contains an ambiguous asset pair")
        canonical_json_bytes(self.to_json_value())

    def rate_for(self, asset_in: AssetId, asset_out: AssetId) -> ConservativeValuationRate:
        if type(asset_in) is not AssetId or type(asset_out) is not AssetId:
            raise TypeError("valuation lookup assets must be exact AssetId values")
        for item in self.rates:
            if item.asset_in == asset_in and item.asset_out == asset_out:
                return item
        raise ValueError("required conservative valuation rate is absent")

    def convert_upper_bound(
        self,
        amount: AssetAmount,
        target_asset: AssetId,
        *,
        at_unix_ms: int,
    ) -> AssetAmount:
        if type(amount) is not AssetAmount:
            raise TypeError("amount must be an exact AssetAmount")
        if type(target_asset) is not AssetId:
            raise TypeError("target_asset must be an exact AssetId")
        _time("at_unix_ms", at_unix_ms)
        if amount.asset == target_asset:
            return AssetAmount(target_asset, amount.amount)
        return self.rate_for(amount.asset, target_asset).convert_upper_bound(
            amount,
            at_unix_ms=at_unix_ms,
        )

    @property
    def pairs(self) -> tuple[tuple[AssetId, AssetId], ...]:
        return tuple((item.asset_in, item.asset_out) for item in self.rates)

    @property
    def pair_sha256(self) -> tuple[str, ...]:
        return tuple(valuation_pair_sha256(asset_in, asset_out) for asset_in, asset_out in self.pairs)

    def require_exact_pairs(
        self,
        required_pairs: tuple[tuple[AssetId, AssetId], ...],
        *,
        at_unix_ms: int,
    ) -> tuple[ConservativeValuationRate, ...]:
        if type(required_pairs) is not tuple:
            raise TypeError("required_pairs must be an exact tuple")
        _time("at_unix_ms", at_unix_ms)
        normalized: list[tuple[AssetId, AssetId]] = []
        for pair in required_pairs:
            if type(pair) is not tuple or len(pair) != 2:
                raise TypeError("each required valuation pair must be an exact two-item tuple")
            asset_in, asset_out = pair
            _ = valuation_pair_sha256(asset_in, asset_out)
            normalized.append((asset_in, asset_out))
        if len(normalized) != len(set(normalized)):
            raise ValueError("required valuation pairs contain a duplicate")
        required = set(normalized)
        present = set(self.pairs)
        if present != required or len(self.rates) != len(required):
            raise ValueError("valuation book does not contain the exact required asset pairs")
        if any(not item.is_valid_at(at_unix_ms) for item in self.rates):
            raise ValueError("valuation rate is not valid at the evidence time")
        return self.rates

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "rates": [item.to_json_value() for item in self.rates],
            "rate_sha256": [item.digest for item in self.rates],
            "pair_sha256": list(self.pair_sha256),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())
