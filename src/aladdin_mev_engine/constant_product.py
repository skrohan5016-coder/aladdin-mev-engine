from __future__ import annotations

from dataclasses import dataclass, field

from .canonical import canonical_json_bytes, canonical_sha256
from .domain import Chain, StateReference, require_bounded_text, require_sha256
from .evm_hex import to_hex_data
from .state_proof import EMPTY_CODE_HASH, EvmStateProofEvidence, EvmStateSnapshot

MAX_UINT256 = (1 << 256) - 1
MAX_FEE_DENOMINATOR = 1_000_000_000
MAX_MODEL_REGISTRY_SIZE = 64
MAX_POOL_UNIVERSE_SIZE = 256
IMPLEMENTATION_SCHEMA = "aladdin-mev-constant-product-implementation/v1"
MODEL_REGISTRY_SCHEMA = "aladdin-mev-constant-product-model-registry/v1"
POOL_SPEC_SCHEMA = "aladdin-mev-constant-product-pool-spec/v1"
AUTHENTICATED_POOL_SCHEMA = "aladdin-mev-authenticated-constant-product-pool/v1"
POOL_UNIVERSE_SCHEMA = "aladdin-mev-constant-product-pool-universe/v1"


class ConstantProductArithmeticError(ValueError):
    pass


def _uint(name: str, value: object, *, positive: bool = False) -> int:
    if type(value) is not int or value < 0 or value > MAX_UINT256:
        raise ValueError(f"{name} must be an unsigned 256-bit exact integer")
    if positive and value == 0:
        raise ValueError(f"{name} must be positive")
    return value


def _bytes(name: str, value: object, length: int, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise ValueError(f"{name} must be exact immutable {length}-byte data")
    if nonzero and value == bytes(length):
        raise ValueError(f"{name} cannot be zero")
    return value


def _mul(a: int, b: int, name: str) -> int:
    _uint(f"{name} left", a)
    _uint(f"{name} right", b)
    if a and b > MAX_UINT256 // a:
        raise ConstantProductArithmeticError(f"{name} exceeds checked uint256")
    return a * b


def _add(a: int, b: int, name: str) -> int:
    _uint(f"{name} left", a)
    _uint(f"{name} right", b)
    if b > MAX_UINT256 - a:
        raise ConstantProductArithmeticError(f"{name} exceeds checked uint256")
    return a + b


@dataclass(frozen=True, slots=True)
class PackedStorageField:
    slot: bytes
    bit_offset: int
    bit_width: int

    def __post_init__(self) -> None:
        _bytes("slot", self.slot, 32)
        if type(self.bit_offset) is not int or not 0 <= self.bit_offset < 256:
            raise ValueError("bit_offset is outside the governed storage word")
        if type(self.bit_width) is not int or not 1 <= self.bit_width <= 256:
            raise ValueError("bit_width is outside the governed range")
        if self.bit_offset + self.bit_width > 256:
            raise ValueError("packed storage field exceeds one 256-bit word")

    @property
    def mask(self) -> int:
        return (1 << self.bit_width) - 1

    @property
    def capacity(self) -> int:
        return self.mask

    def extract(self, word: int) -> int:
        return (_uint("storage word", word) >> self.bit_offset) & self.mask

    def overlaps(self, other: PackedStorageField) -> bool:
        return type(other) is PackedStorageField and self.slot == other.slot and max(self.bit_offset, other.bit_offset) < min(self.bit_offset + self.bit_width, other.bit_offset + other.bit_width)

    def to_json_value(self) -> dict[str, str]:
        return {"slot": to_hex_data(self.slot), "bit_offset": str(self.bit_offset), "bit_width": str(self.bit_width)}

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class ConstantProductImplementationSpec:
    implementation_id: str
    code_hash: bytes
    token0_field: PackedStorageField
    token1_field: PackedStorageField
    reserve0_field: PackedStorageField
    reserve1_field: PackedStorageField
    fee_numerator: int
    fee_denominator: int
    schema: str = IMPLEMENTATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != IMPLEMENTATION_SCHEMA:
            raise ValueError("unsupported constant-product implementation schema")
        require_bounded_text("implementation_id", self.implementation_id, maximum=128)
        _bytes("code_hash", self.code_hash, 32, nonzero=True)
        if self.code_hash == EMPTY_CODE_HASH:
            raise ValueError("constant-product implementation code hash cannot be empty code")
        fields = (self.token0_field, self.token1_field, self.reserve0_field, self.reserve1_field)
        if any(type(item) is not PackedStorageField for item in fields):
            raise TypeError("implementation fields must be exact PackedStorageField values")
        if self.token0_field.bit_width != 160 or self.token1_field.bit_width != 160:
            raise ValueError("token storage fields must be exact 160-bit addresses")
        for index, left in enumerate(fields):
            for right in fields[index + 1:]:
                if left.overlaps(right):
                    raise ValueError("implementation storage fields overlap")
        _uint("fee_numerator", self.fee_numerator, positive=True)
        _uint("fee_denominator", self.fee_denominator, positive=True)
        if self.fee_denominator > MAX_FEE_DENOMINATOR:
            raise ValueError("fee_denominator exceeds the governed ceiling")
        if self.fee_numerator >= self.fee_denominator:
            raise ValueError("fee_numerator must be smaller than fee_denominator")
        canonical_json_bytes(self.to_json_value())

    @property
    def required_slots(self) -> tuple[bytes, ...]:
        return tuple(sorted({item.slot for item in (self.token0_field, self.token1_field, self.reserve0_field, self.reserve1_field)}))

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "implementation_id": self.implementation_id,
            "code_hash": to_hex_data(self.code_hash),
            "token0_field": self.token0_field.to_json_value(),
            "token1_field": self.token1_field.to_json_value(),
            "reserve0_field": self.reserve0_field.to_json_value(),
            "reserve1_field": self.reserve1_field.to_json_value(),
            "fee_numerator": str(self.fee_numerator),
            "fee_denominator": str(self.fee_denominator),
            "arithmetic_semantics": "checked-uint256",
            "code_identity_semantics": "direct-runtime-code-hash-model-bound",
            "fee_semantics": "static-exact-input-multiplier",
            "transfer_semantics": "standard-no-transfer-tax-no-rebase-assumption",
            "model_authority": "explicit-model-bound-shadow-only",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class ConstantProductModelRegistry:
    registry_id: str
    implementations: tuple[ConstantProductImplementationSpec, ...]
    schema: str = MODEL_REGISTRY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != MODEL_REGISTRY_SCHEMA:
            raise ValueError("unsupported model-registry schema")
        require_bounded_text("registry_id", self.registry_id, maximum=128)
        if type(self.implementations) is not tuple or not self.implementations:
            raise TypeError("implementations must be a non-empty exact tuple")
        if len(self.implementations) > MAX_MODEL_REGISTRY_SIZE:
            raise ValueError("model registry exceeds the governed size ceiling")
        if any(type(item) is not ConstantProductImplementationSpec for item in self.implementations):
            raise TypeError("model registry contains an ungoverned implementation")
        ordered = tuple(sorted(self.implementations, key=lambda item: (item.code_hash, item.implementation_id, item.digest)))
        object.__setattr__(self, "implementations", ordered)
        ids = [item.implementation_id for item in ordered]
        digests = [item.digest for item in ordered]
        codes = [item.code_hash for item in ordered]
        if len(ids) != len(set(ids)):
            raise ValueError("model registry contains a duplicate implementation_id")
        if len(digests) != len(set(digests)):
            raise ValueError("model registry contains a duplicate implementation")
        if len(codes) != len(set(codes)):
            raise ValueError("one runtime code hash cannot authorize conflicting constant-product models")
        canonical_json_bytes(self.to_json_value())

    def get_by_code_hash(self, code_hash: bytes) -> ConstantProductImplementationSpec:
        _bytes("code_hash", code_hash, 32)
        for item in self.implementations:
            if item.code_hash == code_hash:
                return item
        raise ValueError("runtime code hash is absent from the model registry")

    def to_json_value(self) -> dict[str, object]:
        return {"schema": self.schema, "registry_id": self.registry_id, "implementations": [item.to_json_value() for item in self.implementations], "implementation_sha256": [item.digest for item in self.implementations]}

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class ConstantProductPoolSpec:
    spec_id: str
    chain: Chain
    pool_address: bytes
    token0: bytes
    token1: bytes
    implementation: ConstantProductImplementationSpec
    schema: str = POOL_SPEC_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != POOL_SPEC_SCHEMA:
            raise ValueError("unsupported pool-spec schema")
        require_bounded_text("spec_id", self.spec_id, maximum=128)
        if type(self.chain) is not Chain or self.chain not in {Chain.ETHEREUM, Chain.BASE}:
            raise ValueError("F3 pool specs require an F2 proof-enabled EVM chain")
        _bytes("pool_address", self.pool_address, 20, nonzero=True)
        _bytes("token0", self.token0, 20, nonzero=True)
        _bytes("token1", self.token1, 20, nonzero=True)
        if self.token0 == self.token1:
            raise ValueError("pool tokens must be distinct")
        if type(self.implementation) is not ConstantProductImplementationSpec:
            raise TypeError("implementation must be an exact governed model")
        canonical_json_bytes(self.to_json_value())

    def to_json_value(self) -> dict[str, object]:
        return {"schema": self.schema, "spec_id": self.spec_id, "chain": self.chain.value, "pool_address": to_hex_data(self.pool_address), "token0": to_hex_data(self.token0), "token1": to_hex_data(self.token1), "implementation": self.implementation.to_json_value(), "implementation_sha256": self.implementation.digest}

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class PoolSwapQuote:
    pool_sha256: str
    implementation_sha256: str
    pool_address: bytes
    token_in: bytes
    token_out: bytes
    amount_in: int
    amount_out: int
    reserve_in: int
    reserve_out: int
    reserve_in_capacity: int
    post_reserve_in: int
    post_reserve_out: int
    fee_numerator: int
    fee_denominator: int

    def __post_init__(self) -> None:
        require_sha256("pool_sha256", self.pool_sha256)
        require_sha256("implementation_sha256", self.implementation_sha256)
        _bytes("pool_address", self.pool_address, 20, nonzero=True)
        _bytes("token_in", self.token_in, 20, nonzero=True)
        _bytes("token_out", self.token_out, 20, nonzero=True)
        if self.token_in == self.token_out:
            raise ValueError("quote tokens must be distinct")
        for name in ("amount_in", "amount_out", "reserve_in", "reserve_out", "reserve_in_capacity", "post_reserve_in", "post_reserve_out", "fee_numerator", "fee_denominator"):
            _uint(name, getattr(self, name))
        if not self.reserve_in or not self.reserve_out or not self.fee_numerator or not self.fee_denominator:
            raise ValueError("quote reserves and fee values must be positive")
        if self.post_reserve_in != self.reserve_in + self.amount_in or self.post_reserve_out != self.reserve_out - self.amount_out:
            raise ValueError("quote reserves do not reconcile")
        if self.post_reserve_in > self.reserve_in_capacity:
            raise ValueError("post reserve exceeds packed-field capacity")
        amount_with_fee = _mul(self.amount_in, self.fee_numerator, "quote amount_in_with_fee")
        expected = _mul(amount_with_fee, self.reserve_out, "quote numerator") // _add(_mul(self.reserve_in, self.fee_denominator, "quote reserve denominator"), amount_with_fee, "quote denominator")
        if self.amount_out != expected:
            raise ValueError("quote amount_out does not match exact integer mathematics")

    def to_json_value(self) -> dict[str, str]:
        return {
            "pool_sha256": self.pool_sha256,
            "implementation_sha256": self.implementation_sha256,
            "pool_address": to_hex_data(self.pool_address),
            "token_in": to_hex_data(self.token_in),
            "token_out": to_hex_data(self.token_out),
            "amount_in": str(self.amount_in),
            "amount_out": str(self.amount_out),
            "reserve_in": str(self.reserve_in),
            "reserve_out": str(self.reserve_out),
            "reserve_in_capacity": str(self.reserve_in_capacity),
            "post_reserve_in": str(self.post_reserve_in),
            "post_reserve_out": str(self.post_reserve_out),
            "fee_numerator": str(self.fee_numerator),
            "fee_denominator": str(self.fee_denominator),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class AuthenticatedConstantProductPool:
    spec: ConstantProductPoolSpec
    evidence: EvmStateProofEvidence
    schema: str = AUTHENTICATED_POOL_SCHEMA
    _reserve0: int = field(init=False, repr=False)
    _reserve1: int = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != AUTHENTICATED_POOL_SCHEMA:
            raise ValueError("unsupported authenticated-pool schema")
        if type(self.spec) is not ConstantProductPoolSpec:
            raise TypeError("spec must be exact ConstantProductPoolSpec")
        if type(self.evidence) is not EvmStateProofEvidence:
            raise TypeError("evidence must be exact F2 EvmStateProofEvidence")
        if not self.evidence.account_exists:
            raise ValueError("pool account must exist in authenticated state")
        if self.evidence.chain is not self.spec.chain:
            raise ValueError("pool evidence chain does not match its specification")
        if self.evidence.address != self.spec.pool_address:
            raise ValueError("pool evidence address does not match its specification")
        if self.evidence.code_hash != self.spec.implementation.code_hash:
            raise ValueError("pool runtime code hash does not match its model")
        storage = self.evidence.storage_values
        if type(storage) is not tuple:
            raise TypeError("pool storage evidence must be an exact tuple")
        keys = [item.key for item in storage]
        if len(keys) != len(set(keys)):
            raise ValueError("pool storage evidence contains duplicate slots")
        required = self.spec.implementation.required_slots
        if tuple(sorted(keys)) != required:
            raise ValueError("pool storage evidence does not contain the exact model slot set")
        if any(not item.included for item in storage):
            raise ValueError("all model storage slots require authenticated inclusion")
        words = {item.key: item.value for item in storage}
        model = self.spec.implementation
        token0 = model.token0_field.extract(words[model.token0_field.slot]).to_bytes(20, "big")
        token1 = model.token1_field.extract(words[model.token1_field.slot]).to_bytes(20, "big")
        if not any(token0) or not any(token1):
            raise ValueError("authenticated pool token identity cannot be zero")
        if token0 != self.spec.token0 or token1 != self.spec.token1:
            raise ValueError("authenticated pool token identity disagrees with its specification")
        reserve0 = model.reserve0_field.extract(words[model.reserve0_field.slot])
        reserve1 = model.reserve1_field.extract(words[model.reserve1_field.slot])
        if not reserve0 or not reserve1:
            raise ValueError("authenticated constant-product reserves must be positive")
        object.__setattr__(self, "_reserve0", reserve0)
        object.__setattr__(self, "_reserve1", reserve1)
        canonical_json_bytes(self.to_json_value())

    @property
    def chain(self) -> Chain:
        return self.spec.chain

    @property
    def pool_address(self) -> bytes:
        return self.spec.pool_address

    @property
    def token0(self) -> bytes:
        return self.spec.token0

    @property
    def token1(self) -> bytes:
        return self.spec.token1

    @property
    def reserve0(self) -> int:
        return self._reserve0

    @property
    def reserve1(self) -> int:
        return self._reserve1

    def supports_token(self, token: bytes) -> bool:
        return type(token) is bytes and token in {self.token0, self.token1}

    def other_token(self, token: bytes) -> bytes:
        _bytes("token", token, 20, nonzero=True)
        if token == self.token0:
            return self.token1
        if token == self.token1:
            return self.token0
        raise ValueError("token is not in the authenticated pool")

    def reserve_pair(self, token_in: bytes) -> tuple[int, int, int]:
        _bytes("token_in", token_in, 20, nonzero=True)
        model = self.spec.implementation
        if token_in == self.token0:
            return self.reserve0, self.reserve1, model.reserve0_field.capacity
        if token_in == self.token1:
            return self.reserve1, self.reserve0, model.reserve1_field.capacity
        raise ValueError("token_in is not in the authenticated pool")

    def maximum_safe_input(self, token_in: bytes) -> int:
        reserve_in, reserve_out, capacity = self.reserve_pair(token_in)
        model = self.spec.implementation
        reserve_term = _mul(reserve_in, model.fee_denominator, "reserve denominator")
        return min(capacity - reserve_in, MAX_UINT256 // model.fee_numerator, (MAX_UINT256 - reserve_term) // model.fee_numerator, (MAX_UINT256 // reserve_out) // model.fee_numerator)

    def quote_exact_in(self, token_in: bytes, amount_in: int) -> PoolSwapQuote:
        _uint("amount_in", amount_in)
        reserve_in, reserve_out, capacity = self.reserve_pair(token_in)
        if amount_in > self.maximum_safe_input(token_in):
            raise ConstantProductArithmeticError("input exceeds checked arithmetic or packed reserve capacity")
        model = self.spec.implementation
        amount_with_fee = _mul(amount_in, model.fee_numerator, "amount_in_with_fee")
        amount_out = _mul(amount_with_fee, reserve_out, "quote numerator") // _add(_mul(reserve_in, model.fee_denominator, "quote reserve denominator"), amount_with_fee, "quote denominator")
        return PoolSwapQuote(self.digest, model.digest, self.pool_address, token_in, self.other_token(token_in), amount_in, amount_out, reserve_in, reserve_out, capacity, reserve_in + amount_in, reserve_out - amount_out, model.fee_numerator, model.fee_denominator)

    def to_json_value(self) -> dict[str, object]:
        return {"schema": self.schema, "spec": self.spec.to_json_value(), "spec_sha256": self.spec.digest, "evidence_sha256": self.evidence.digest, "reserve0": str(self.reserve0), "reserve1": str(self.reserve1)}

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class PoolUniverse:
    snapshot: EvmStateSnapshot
    model_registry: ConstantProductModelRegistry
    pools: tuple[AuthenticatedConstantProductPool, ...]
    schema: str = POOL_UNIVERSE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != POOL_UNIVERSE_SCHEMA:
            raise ValueError("unsupported pool-universe schema")
        if type(self.snapshot) is not EvmStateSnapshot:
            raise TypeError("snapshot must be exact F2 EvmStateSnapshot")
        if type(self.model_registry) is not ConstantProductModelRegistry:
            raise TypeError("model_registry must be exact governed registry")
        if type(self.pools) is not tuple or not self.pools:
            raise TypeError("pools must be a non-empty exact tuple")
        if len(self.pools) > MAX_POOL_UNIVERSE_SIZE:
            raise ValueError("pool universe exceeds the governed size ceiling")
        if any(type(item) is not AuthenticatedConstantProductPool for item in self.pools):
            raise TypeError("pool universe contains an ungoverned pool")
        ordered = tuple(sorted(self.pools, key=lambda item: item.pool_address))
        object.__setattr__(self, "pools", ordered)
        addresses = [item.pool_address for item in ordered]
        if len(addresses) != len(set(addresses)):
            raise ValueError("pool universe contains a duplicate pool address")
        snapshot_by_address = {item.address: item for item in self.snapshot.accounts}
        if set(addresses) != set(snapshot_by_address):
            raise ValueError("pool universe does not consume the exact snapshot account set")
        if self.snapshot.anchor.chain not in {Chain.ETHEREUM, Chain.BASE}:
            raise ValueError("F3 universe requires an F2 proof-enabled chain")
        for pool in ordered:
            if pool.chain is not self.snapshot.anchor.chain:
                raise ValueError("pool universe contains a cross-chain pool")
            if snapshot_by_address[pool.pool_address].digest != pool.evidence.digest:
                raise ValueError("pool evidence is not the exact snapshot account evidence")
            if pool.evidence.anchor.digest != self.snapshot.anchor.digest:
                raise ValueError("pool evidence does not bind the exact snapshot anchor")
            registered = self.model_registry.get_by_code_hash(pool.evidence.code_hash)
            if registered.digest != pool.spec.implementation.digest:
                raise ValueError("pool implementation is absent from the model registry")
        canonical_json_bytes(self.to_json_value())

    @property
    def chain(self) -> Chain:
        return self.snapshot.anchor.chain

    @property
    def observed_at_unix_ms(self) -> int:
        return self.snapshot.anchor.state_observed_at_unix_ms

    @property
    def state_reference(self) -> StateReference:
        return StateReference(self.chain, self.snapshot.anchor.block_number, to_hex_data(self.snapshot.anchor.block_hash), self.observed_at_unix_ms, self.snapshot.digest)

    def get_pool(self, pool_address: bytes) -> AuthenticatedConstantProductPool:
        _bytes("pool_address", pool_address, 20, nonzero=True)
        for item in self.pools:
            if item.pool_address == pool_address:
                return item
        raise ValueError("unknown pool address in the authenticated universe")

    def to_json_value(self) -> dict[str, object]:
        return {"schema": self.schema, "state_snapshot_sha256": self.snapshot.digest, "model_registry": self.model_registry.to_json_value(), "model_registry_sha256": self.model_registry.digest, "pools": [item.to_json_value() for item in self.pools], "pool_sha256": [item.digest for item in self.pools], "opportunity_authority": "authenticated-state-explicit-model-gross-shadow-only"}

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())
