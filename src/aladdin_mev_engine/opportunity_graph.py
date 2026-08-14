from __future__ import annotations

from dataclasses import dataclass

from .canonical import canonical_json_bytes, canonical_sha256
from .constant_product import (
    AuthenticatedConstantProductPool,
    ConstantProductArithmeticError,
    MAX_UINT256,
    PoolSwapQuote,
    PoolUniverse,
)
from .domain import require_sha256
from .evm_hex import to_hex_data

MIN_ROUTE_HOPS = 2
MAX_ROUTE_HOPS = 4
MAX_ENUMERATED_ROUTES = 4096
MAX_ENUMERATION_STEPS = 100_000
ROUTE_SCHEMA = "aladdin-mev-constant-product-route/v1"


def _require_address(name: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 20 or value == bytes(20):
        raise ValueError(f"{name} must be a non-zero exact 20-byte address")
    return value


@dataclass(frozen=True, slots=True)
class RouteLeg:
    pool_address: bytes
    token_in: bytes
    token_out: bytes

    def __post_init__(self) -> None:
        _require_address("pool_address", self.pool_address)
        _require_address("token_in", self.token_in)
        _require_address("token_out", self.token_out)
        if self.token_in == self.token_out:
            raise ValueError("route leg tokens must be distinct")

    def to_json_value(self) -> dict[str, str]:
        return {
            "pool_address": to_hex_data(self.pool_address),
            "token_in": to_hex_data(self.token_in),
            "token_out": to_hex_data(self.token_out),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class RouteQuote:
    route_sha256: str
    amount_in: int
    amount_out: int
    gross_profit: int
    legs: tuple[PoolSwapQuote, ...]

    def __post_init__(self) -> None:
        require_sha256("route_sha256", self.route_sha256)
        if type(self.amount_in) is not int or self.amount_in <= 0:
            raise ValueError("route quote amount_in must be a positive exact integer")
        if type(self.amount_out) is not int or self.amount_out < 0:
            raise ValueError("route quote amount_out must be a non-negative exact integer")
        if type(self.gross_profit) is not int:
            raise ValueError("route quote gross_profit must be an exact integer")
        if self.gross_profit != self.amount_out - self.amount_in:
            raise ValueError("route quote gross profit does not reconcile")
        if type(self.legs) is not tuple:
            raise TypeError("route quote legs must be an exact tuple")
        if not MIN_ROUTE_HOPS <= len(self.legs) <= MAX_ROUTE_HOPS:
            raise ValueError("route quote hop count is outside the governed range")
        if any(type(leg) is not PoolSwapQuote for leg in self.legs):
            raise TypeError("route quote contains an ungoverned leg")
        if self.legs[0].amount_in != self.amount_in:
            raise ValueError("route quote first leg amount does not match route input")
        if self.legs[-1].amount_out != self.amount_out:
            raise ValueError("route quote final leg amount does not match route output")
        pool_addresses = [leg.pool_address for leg in self.legs]
        if len(pool_addresses) != len(set(pool_addresses)):
            raise ValueError("route quote cannot reuse a pool")
        for previous, current in zip(self.legs, self.legs[1:]):
            if previous.token_out != current.token_in:
                raise ValueError("route quote token path is disconnected")
            if previous.amount_out != current.amount_in:
                raise ValueError("route quote amount path is disconnected")
        if self.legs[-1].token_out != self.legs[0].token_in:
            raise ValueError("route quote must return to its input token")
        canonical_json_bytes(self.to_json_value())

    def to_json_value(self) -> dict[str, object]:
        return {
            "route_sha256": self.route_sha256,
            "amount_in": str(self.amount_in),
            "amount_out": str(self.amount_out),
            "gross_profit": str(self.gross_profit),
            "legs": [item.to_json_value() for item in self.legs],
            "leg_sha256": [item.digest for item in self.legs],
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class ConstantProductRoute:
    universe_sha256: str
    legs: tuple[RouteLeg, ...]
    schema: str = ROUTE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != ROUTE_SCHEMA:
            raise ValueError("unsupported constant-product route schema")
        require_sha256("universe_sha256", self.universe_sha256)
        if type(self.legs) is not tuple:
            raise TypeError("route legs must be an exact tuple")
        if not MIN_ROUTE_HOPS <= len(self.legs) <= MAX_ROUTE_HOPS:
            raise ValueError("route hop count is outside the governed range")
        if any(type(leg) is not RouteLeg for leg in self.legs):
            raise TypeError("route contains an ungoverned leg")
        pools = [leg.pool_address for leg in self.legs]
        if len(pools) != len(set(pools)):
            raise ValueError("route cannot reuse a pool")
        for previous, current in zip(self.legs, self.legs[1:]):
            if previous.token_out != current.token_in:
                raise ValueError("route token path is disconnected")
        base = self.legs[0].token_in
        if self.legs[-1].token_out != base:
            raise ValueError("route must return to its base token")
        intermediate = [leg.token_out for leg in self.legs[:-1]]
        if base in intermediate:
            raise ValueError("route returns to its base token before the final leg")
        if len(intermediate) != len(set(intermediate)):
            raise ValueError("route repeats an intermediate token")
        canonical_json_bytes(self.to_json_value())

    @property
    def base_token(self) -> bytes:
        return self.legs[0].token_in

    def validate_against(self, universe: PoolUniverse) -> None:
        if type(universe) is not PoolUniverse:
            raise TypeError("universe must be an exact PoolUniverse")
        if universe.digest != self.universe_sha256:
            raise ValueError("route does not bind the exact pool universe")
        for leg in self.legs:
            pool = universe.get_pool(leg.pool_address)
            if not pool.supports_token(leg.token_in):
                raise ValueError("route leg token_in is absent from its pool")
            if pool.other_token(leg.token_in) != leg.token_out:
                raise ValueError("route leg token direction disagrees with its pool")

    def quote_exact_in(self, universe: PoolUniverse, amount_in: int) -> RouteQuote:
        self.validate_against(universe)
        if type(amount_in) is not int or amount_in <= 0:
            raise ValueError("route amount_in must be a positive exact integer")
        current = amount_in
        quotes: list[PoolSwapQuote] = []
        for leg in self.legs:
            pool = universe.get_pool(leg.pool_address)
            quote = pool.quote_exact_in(leg.token_in, current)
            if quote.token_out != leg.token_out:
                raise RuntimeError("authenticated pool quote changed its governed direction")
            quotes.append(quote)
            current = quote.amount_out
        return RouteQuote(
            route_sha256=self.digest,
            amount_in=amount_in,
            amount_out=current,
            gross_profit=current - amount_in,
            legs=tuple(quotes),
        )

    def _try_amount_out_bound(self, universe: PoolUniverse, amount_in: int) -> int | None:
        try:
            return self.quote_exact_in(universe, amount_in).amount_out
        except ConstantProductArithmeticError:
            return None

    def maximum_safe_input(self, universe: PoolUniverse, requested_maximum: int) -> int:
        self.validate_against(universe)
        if (
            type(requested_maximum) is not int
            or requested_maximum < 0
            or requested_maximum > MAX_UINT256
        ):
            raise ValueError("requested_maximum must be a non-negative uint256 exact integer")
        if requested_maximum == 0 or self._try_amount_out_bound(universe, 1) is None:
            return 0
        lower = 1
        upper = requested_maximum
        while lower < upper:
            middle = (lower + upper + 1) // 2
            if self._try_amount_out_bound(universe, middle) is None:
                upper = middle - 1
            else:
                lower = middle
        return lower

    def continuous_coefficients(self, universe: PoolUniverse) -> tuple[int, int, int]:
        """Return A, B, C for the no-floor composition A*x/(B+C*x)."""

        self.validate_against(universe)
        aggregate_a = 1
        aggregate_b = 1
        aggregate_c = 0
        for leg in self.legs:
            pool = universe.get_pool(leg.pool_address)
            reserve_in, reserve_out, _capacity = pool.reserve_pair(leg.token_in)
            implementation = pool.spec.implementation
            leg_a = implementation.fee_numerator * reserve_out
            leg_b = implementation.fee_denominator * reserve_in
            leg_c = implementation.fee_numerator
            previous_a = aggregate_a
            aggregate_a = leg_a * previous_a
            aggregate_c = leg_b * aggregate_c + leg_c * previous_a
            aggregate_b = leg_b * aggregate_b
        return aggregate_a, aggregate_b, aggregate_c

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "universe_sha256": self.universe_sha256,
            "legs": [item.to_json_value() for item in self.legs],
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


def _directional_legs(pool: AuthenticatedConstantProductPool) -> tuple[RouteLeg, RouteLeg]:
    return (
        RouteLeg(pool.pool_address, pool.token0, pool.token1),
        RouteLeg(pool.pool_address, pool.token1, pool.token0),
    )


def enumerate_simple_cycles(
    universe: PoolUniverse,
    base_token: bytes,
    *,
    maximum_hops: int = MAX_ROUTE_HOPS,
) -> tuple[ConstantProductRoute, ...]:
    if type(universe) is not PoolUniverse:
        raise TypeError("universe must be an exact PoolUniverse")
    _require_address("base_token", base_token)
    if type(maximum_hops) is not int or not MIN_ROUTE_HOPS <= maximum_hops <= MAX_ROUTE_HOPS:
        raise ValueError("maximum_hops is outside the governed range")

    adjacency: dict[bytes, list[RouteLeg]] = {}
    for pool in universe.pools:
        for leg in _directional_legs(pool):
            adjacency.setdefault(leg.token_in, []).append(leg)
    for token in adjacency:
        adjacency[token].sort(
            key=lambda leg: (leg.pool_address, leg.token_out, leg.token_in)
        )

    routes: list[ConstantProductRoute] = []
    route_digests: set[str] = set()
    enumeration_steps = 0

    def visit(
        token: bytes,
        legs: tuple[RouteLeg, ...],
        used_pools: frozenset[bytes],
        visited_tokens: frozenset[bytes],
    ) -> None:
        nonlocal enumeration_steps
        if len(legs) >= maximum_hops:
            return
        for leg in adjacency.get(token, ()):
            enumeration_steps += 1
            if enumeration_steps > MAX_ENUMERATION_STEPS:
                raise ValueError("route enumeration work exceeds the governed ceiling")
            if leg.pool_address in used_pools:
                continue
            next_legs = (*legs, leg)
            next_token = leg.token_out
            if next_token == base_token:
                if len(next_legs) < MIN_ROUTE_HOPS:
                    continue
                route = ConstantProductRoute(
                    universe_sha256=universe.digest,
                    legs=next_legs,
                )
                if route.digest not in route_digests:
                    route_digests.add(route.digest)
                    routes.append(route)
                    if len(routes) > MAX_ENUMERATED_ROUTES:
                        raise ValueError("route count exceeds the governed ceiling")
                continue
            if next_token in visited_tokens:
                continue
            visit(
                next_token,
                next_legs,
                used_pools | {leg.pool_address},
                visited_tokens | {next_token},
            )

    visit(base_token, (), frozenset(), frozenset({base_token}))
    return tuple(sorted(routes, key=lambda route: route.digest))
