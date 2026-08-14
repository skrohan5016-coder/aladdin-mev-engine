from __future__ import annotations

from dataclasses import dataclass, field

from .canonical import canonical_json_bytes, canonical_sha256
from .constant_product import PoolUniverse
from .domain import Strategy
from .evm_hex import to_hex_data
from .opportunity_graph import (
    MAX_ROUTE_HOPS,
    MIN_ROUTE_HOPS,
    ConstantProductRoute,
    RouteQuote,
    enumerate_simple_cycles,
)
from .optimizer import (
    OptimizationLimits,
    OptimizationResult,
    OptimizationStatus,
    optimize_route,
)

ATOMIC_OPPORTUNITY_SCHEMA = "aladdin-mev-atomic-dex-opportunity/v1"
SEARCH_REPORT_SCHEMA = "aladdin-mev-opportunity-search-report/v1"
OPPORTUNITY_AUTHORITY = "authenticated-state-explicit-model-exact-gross-shadow-only"
SEARCH_AUTHORITY = "authenticated-state-explicit-model-gross-shadow-search"
COST_COMPLETENESS = "gross-only-no-gas-no-inclusion-no-funding"
MAX_UINT64 = (1 << 64) - 1
MAX_SEARCH_WORK_UNITS = 4_000_000


def _require_address(name: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 20 or value == bytes(20):
        raise ValueError(f"{name} must be a non-zero exact 20-byte address")
    return value


def _require_time(name: str, value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT64:
        raise ValueError(f"{name} must be an unsigned 64-bit exact integer")
    return value


@dataclass(frozen=True, slots=True)
class AtomicDexOpportunityEvidence:
    universe: PoolUniverse
    route: ConstantProductRoute
    optimization_limits: OptimizationLimits
    created_at_unix_ms: int
    schema: str = ATOMIC_OPPORTUNITY_SCHEMA
    _optimization: OptimizationResult = field(init=False, repr=False)
    _route_quote: RouteQuote = field(init=False, repr=False)
    _opportunity_id: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != ATOMIC_OPPORTUNITY_SCHEMA:
            raise ValueError("unsupported atomic opportunity schema")
        if type(self.universe) is not PoolUniverse:
            raise TypeError("universe must be an exact PoolUniverse")
        if type(self.route) is not ConstantProductRoute:
            raise TypeError("route must be an exact ConstantProductRoute")
        if type(self.optimization_limits) is not OptimizationLimits:
            raise TypeError("optimization_limits must be exact governed limits")
        _require_time("created_at_unix_ms", self.created_at_unix_ms)
        if self.created_at_unix_ms < self.universe.observed_at_unix_ms:
            raise ValueError("opportunity creation time precedes authenticated state")
        self.route.validate_against(self.universe)
        optimization = optimize_route(
            self.universe,
            self.route,
            self.optimization_limits,
        )
        if (
            not optimization.complete
            or optimization.status is not OptimizationStatus.COMPLETE
            or optimization.gross_profit <= 0
            or optimization.amount_in <= 0
        ):
            raise ValueError(
                "atomic opportunity requires complete positive exact gross optimization"
            )
        quote = self.route.quote_exact_in(
            self.universe,
            optimization.amount_in,
        )
        if (
            quote.amount_out != optimization.amount_out
            or quote.gross_profit != optimization.gross_profit
            or quote.gross_profit <= 0
        ):
            raise ValueError("opportunity route quote disagrees with exact optimization")
        identity = {
            "schema": self.schema,
            "chain": self.universe.chain.value,
            "strategy": Strategy.ATOMIC_DEX_ARBITRAGE.value,
            "state_reference": self.universe.state_reference.to_json_value(),
            "universe_sha256": self.universe.digest,
            "model_registry_sha256": self.universe.model_registry.digest,
            "route_sha256": self.route.digest,
            "route_quote_sha256": quote.digest,
            "optimization_sha256": optimization.digest,
            "authority": OPPORTUNITY_AUTHORITY,
            "cost_completeness": COST_COMPLETENESS,
            "execution_eligible": False,
        }
        object.__setattr__(self, "_optimization", optimization)
        object.__setattr__(self, "_route_quote", quote)
        object.__setattr__(
            self,
            "_opportunity_id",
            "atomic-dex-" + canonical_sha256(identity),
        )
        canonical_json_bytes(self.to_json_value())

    @property
    def optimization(self) -> OptimizationResult:
        return self._optimization

    @property
    def route_quote(self) -> RouteQuote:
        return self._route_quote

    @property
    def opportunity_id(self) -> str:
        return self._opportunity_id

    @property
    def capital_at_risk(self) -> int:
        return self.optimization.amount_in

    @property
    def gross_profit(self) -> int:
        return self.optimization.gross_profit

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "opportunity_id": self.opportunity_id,
            "chain": self.universe.chain.value,
            "strategy": Strategy.ATOMIC_DEX_ARBITRAGE.value,
            "state_reference": self.universe.state_reference.to_json_value(),
            "capital_at_risk": str(self.capital_at_risk),
            "gross_profit": str(self.gross_profit),
            "universe_sha256": self.universe.digest,
            "model_registry_sha256": self.universe.model_registry.digest,
            "route": self.route.to_json_value(),
            "route_sha256": self.route.digest,
            "route_quote": self.route_quote.to_json_value(),
            "route_quote_sha256": self.route_quote.digest,
            "optimization": self.optimization.to_json_value(),
            "optimization_sha256": self.optimization.digest,
            "authority": OPPORTUNITY_AUTHORITY,
            "cost_completeness": COST_COMPLETENESS,
            "execution_eligible": False,
            "created_at_unix_ms": str(self.created_at_unix_ms),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class OpportunitySearchReport:
    universe: PoolUniverse
    base_token: bytes
    maximum_hops: int
    optimization_limits: OptimizationLimits
    created_at_unix_ms: int
    schema: str = SEARCH_REPORT_SCHEMA
    _routes: tuple[ConstantProductRoute, ...] = field(init=False, repr=False)
    _results: tuple[OptimizationResult, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != SEARCH_REPORT_SCHEMA:
            raise ValueError("unsupported opportunity-search report schema")
        if type(self.universe) is not PoolUniverse:
            raise TypeError("universe must be an exact PoolUniverse")
        _require_address("base_token", self.base_token)
        if type(self.maximum_hops) is not int or not MIN_ROUTE_HOPS <= self.maximum_hops <= MAX_ROUTE_HOPS:
            raise ValueError("maximum_hops is outside the governed range")
        if type(self.optimization_limits) is not OptimizationLimits:
            raise TypeError("optimization_limits must be exact governed limits")
        _require_time("created_at_unix_ms", self.created_at_unix_ms)
        if self.created_at_unix_ms < self.universe.observed_at_unix_ms:
            raise ValueError("search report creation time precedes authenticated state")
        routes = enumerate_simple_cycles(
            self.universe,
            self.base_token,
            maximum_hops=self.maximum_hops,
        )
        total_work_ceiling = (
            len(routes) * self.optimization_limits.maximum_work_units
        )
        if total_work_ceiling > MAX_SEARCH_WORK_UNITS:
            raise ValueError("opportunity search work exceeds the governed ceiling")
        results = tuple(
            optimize_route(self.universe, route, self.optimization_limits)
            for route in routes
        )
        object.__setattr__(self, "_routes", routes)
        object.__setattr__(self, "_results", results)
        canonical_json_bytes(self.to_json_value())

    @property
    def routes(self) -> tuple[ConstantProductRoute, ...]:
        return self._routes

    @property
    def results(self) -> tuple[OptimizationResult, ...]:
        return self._results

    @property
    def complete(self) -> bool:
        return all(result.complete for result in self.results)

    @property
    def route_count(self) -> int:
        return len(self.routes)

    @property
    def positive_route_count(self) -> int:
        return sum(
            1
            for result in self.results
            if result.complete
            and result.status is OptimizationStatus.COMPLETE
            and result.gross_profit > 0
        )

    @property
    def incomplete_route_sha256(self) -> tuple[str, ...]:
        return tuple(
            route.digest
            for route, result in zip(self.routes, self.results)
            if not result.complete
        )

    @property
    def positive_route_sha256(self) -> tuple[str, ...]:
        return tuple(
            route.digest
            for route, result in zip(self.routes, self.results)
            if result.complete
            and result.status is OptimizationStatus.COMPLETE
            and result.gross_profit > 0
        )

    def opportunities(self) -> tuple[AtomicDexOpportunityEvidence, ...]:
        return tuple(
            AtomicDexOpportunityEvidence(
                universe=self.universe,
                route=route,
                optimization_limits=self.optimization_limits,
                created_at_unix_ms=self.created_at_unix_ms,
            )
            for route, result in zip(self.routes, self.results)
            if result.complete
            and result.status is OptimizationStatus.COMPLETE
            and result.gross_profit > 0
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "state_reference": self.universe.state_reference.to_json_value(),
            "universe_sha256": self.universe.digest,
            "model_registry_sha256": self.universe.model_registry.digest,
            "base_token": to_hex_data(self.base_token),
            "maximum_hops": str(self.maximum_hops),
            "optimization_limits": self.optimization_limits.to_json_value(),
            "complete": self.complete,
            "route_count": str(self.route_count),
            "positive_route_count": str(self.positive_route_count),
            "route_sha256": [route.digest for route in self.routes],
            "result_sha256": [result.digest for result in self.results],
            "incomplete_route_sha256": list(self.incomplete_route_sha256),
            "positive_route_sha256": list(self.positive_route_sha256),
            "authority": SEARCH_AUTHORITY,
            "execution_eligible": False,
            "created_at_unix_ms": str(self.created_at_unix_ms),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())
