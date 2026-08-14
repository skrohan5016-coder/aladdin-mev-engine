from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import heapq
import math

from .canonical import canonical_json_bytes, canonical_sha256
from .constant_product import MAX_UINT256, PoolUniverse
from .opportunity_graph import ConstantProductRoute

MAX_OPTIMIZER_INTERVALS = 1_000_000
MAX_EXHAUSTIVE_THRESHOLD = 4096
MAX_OPTIMIZER_WORK_UNITS = 1_000_000
OPTIMIZATION_SCHEMA = "aladdin-mev-route-optimization/v1"


class OptimizationStatus(StrEnum):
    COMPLETE = "complete"
    NO_VALID_INPUT = "no-valid-input"
    NO_POSITIVE_CONTINUOUS_EDGE = "no-positive-continuous-edge"
    NO_POSITIVE_EXACT_PROFIT = "no-positive-exact-profit"
    BUDGET_EXHAUSTED = "budget-exhausted"


@dataclass(frozen=True, slots=True)
class OptimizationLimits:
    maximum_input: int
    maximum_intervals: int = 10_000
    exhaustive_threshold: int = 32

    def __post_init__(self) -> None:
        if (
            type(self.maximum_input) is not int
            or self.maximum_input <= 0
            or self.maximum_input > MAX_UINT256
        ):
            raise ValueError("maximum_input must be a positive uint256 exact integer")
        if type(self.maximum_intervals) is not int or not 1 <= self.maximum_intervals <= MAX_OPTIMIZER_INTERVALS:
            raise ValueError("maximum_intervals is outside the governed range")
        if type(self.exhaustive_threshold) is not int or not 1 <= self.exhaustive_threshold <= MAX_EXHAUSTIVE_THRESHOLD:
            raise ValueError("exhaustive_threshold is outside the governed range")
        if self.maximum_work_units > MAX_OPTIMIZER_WORK_UNITS:
            raise ValueError("optimizer work budget exceeds the governed ceiling")
        canonical_json_bytes(self.to_json_value())

    @property
    def maximum_work_units(self) -> int:
        return self.maximum_intervals * (self.exhaustive_threshold + 1)

    def to_json_value(self) -> dict[str, str]:
        return {
            "maximum_input": str(self.maximum_input),
            "maximum_intervals": str(self.maximum_intervals),
            "exhaustive_threshold": str(self.exhaustive_threshold),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class OptimizationResult:
    route_sha256: str
    status: OptimizationStatus
    complete: bool
    effective_maximum_input: int
    amount_in: int
    amount_out: int
    gross_profit: int
    evaluated_inputs: int
    explored_intervals: int
    pruned_intervals: int
    continuous_upper_bound: int
    limits: OptimizationLimits
    schema: str = OPTIMIZATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != OPTIMIZATION_SCHEMA:
            raise ValueError("unsupported route-optimization schema")
        if type(self.route_sha256) is not str or len(self.route_sha256) != 64 or any(
            char not in "0123456789abcdef" for char in self.route_sha256
        ):
            raise ValueError("route_sha256 must be a canonical SHA-256 digest")
        if type(self.status) is not OptimizationStatus:
            raise TypeError("status must be an exact OptimizationStatus")
        if type(self.complete) is not bool:
            raise TypeError("complete must be an exact bool")
        for name in (
            "effective_maximum_input",
            "amount_in",
            "amount_out",
            "evaluated_inputs",
            "explored_intervals",
            "pruned_intervals",
            "continuous_upper_bound",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative exact integer")
        if type(self.gross_profit) is not int:
            raise ValueError("gross_profit must be an exact integer")
        if type(self.limits) is not OptimizationLimits:
            raise TypeError("limits must be an exact OptimizationLimits")
        for name in (
            "effective_maximum_input",
            "amount_in",
            "amount_out",
        ):
            if getattr(self, name) > MAX_UINT256:
                raise ValueError(f"{name} exceeds uint256")
        if not -MAX_UINT256 <= self.gross_profit <= MAX_UINT256:
            raise ValueError("gross_profit exceeds the governed signed uint256 range")
        if self.continuous_upper_bound > MAX_UINT256:
            raise ValueError("continuous_upper_bound exceeds uint256")
        if self.effective_maximum_input > self.limits.maximum_input:
            raise ValueError("effective maximum exceeds the requested maximum")
        if self.explored_intervals > self.limits.maximum_intervals:
            raise ValueError("explored_intervals exceeds the governed interval budget")
        if self.evaluated_inputs > self.limits.maximum_work_units:
            raise ValueError("evaluated_inputs exceeds the governed work budget")
        if self.evaluated_inputs > (
            self.explored_intervals * self.limits.exhaustive_threshold
        ):
            raise ValueError("evaluated_inputs exceeds explored exhaustive work")
        if self.pruned_intervals > 2 * self.explored_intervals + 1:
            raise ValueError("pruned_intervals exceeds the governed tree bound")
        if self.amount_in > self.effective_maximum_input:
            raise ValueError("winning amount exceeds the effective maximum")
        if self.continuous_upper_bound < max(self.gross_profit, 0):
            raise ValueError("continuous_upper_bound understates claimed exact profit")
        if self.amount_in == 0:
            if self.amount_out != 0 or self.gross_profit != 0:
                raise ValueError("zero-input optimization result must have zero output/profit")
        elif self.gross_profit != self.amount_out - self.amount_in:
            raise ValueError("optimization profit does not reconcile")
        if self.status is OptimizationStatus.COMPLETE:
            if not self.complete or self.amount_in <= 0 or self.gross_profit <= 0:
                raise ValueError("complete optimization requires a positive exact winner")
        elif self.status is OptimizationStatus.BUDGET_EXHAUSTED:
            if (
                self.complete
                or self.effective_maximum_input == 0
                or self.amount_in != 0
                or self.amount_out != 0
                or self.gross_profit != 0
                or self.explored_intervals != self.limits.maximum_intervals
                or self.continuous_upper_bound == 0
            ):
                raise ValueError("budget-exhausted optimization has inconsistent authority")
        else:
            if not self.complete:
                raise ValueError("only budget-exhausted optimization may be incomplete")
            if self.amount_in != 0 or self.amount_out != 0 or self.gross_profit != 0:
                raise ValueError("no-winner optimization status cannot carry a winner")
            if self.status is OptimizationStatus.NO_VALID_INPUT:
                if (
                    self.effective_maximum_input != 0
                    or self.evaluated_inputs != 0
                    or self.explored_intervals != 0
                    or self.pruned_intervals != 0
                    or self.continuous_upper_bound != 0
                ):
                    raise ValueError("no-valid-input result has inconsistent authority")
            elif self.status is OptimizationStatus.NO_POSITIVE_CONTINUOUS_EDGE:
                if (
                    self.effective_maximum_input == 0
                    or self.evaluated_inputs != 0
                    or self.explored_intervals != 0
                    or self.pruned_intervals != 0
                    or self.continuous_upper_bound != 0
                ):
                    raise ValueError(
                        "no-positive-continuous-edge result has inconsistent authority"
                    )
            elif self.status is OptimizationStatus.NO_POSITIVE_EXACT_PROFIT:
                if (
                    self.effective_maximum_input == 0
                    or self.evaluated_inputs == 0
                    or self.explored_intervals == 0
                    or self.continuous_upper_bound == 0
                ):
                    raise ValueError(
                        "no-positive-exact-profit result has inconsistent authority"
                    )
        canonical_json_bytes(self.to_json_value())

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "route_sha256": self.route_sha256,
            "status": self.status.value,
            "complete": self.complete,
            "effective_maximum_input": str(self.effective_maximum_input),
            "amount_in": str(self.amount_in),
            "amount_out": str(self.amount_out),
            "gross_profit": str(self.gross_profit),
            "evaluated_inputs": str(self.evaluated_inputs),
            "explored_intervals": str(self.explored_intervals),
            "pruned_intervals": str(self.pruned_intervals),
            "continuous_upper_bound": str(self.continuous_upper_bound),
            "limits": self.limits.to_json_value(),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


def _ceil_div(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        raise ValueError("denominator must be positive")
    return -((-numerator) // denominator)


def _endpoint_upper(a: int, b: int, c: int, value: int) -> int:
    denominator = b + c * value
    numerator = a * value - value * denominator
    return _ceil_div(numerator, denominator)


def _interval_continuous_upper(
    a: int,
    b: int,
    c: int,
    lower: int,
    upper: int,
) -> int:
    """Optimistic integer upper bound for A*x/(B+C*x)-x on [lower, upper]."""

    if any(type(item) is not int for item in (a, b, c, lower, upper)):
        raise TypeError("continuous-bound inputs must be exact integers")
    if a <= 0 or b <= 0 or c <= 0 or lower <= 0 or upper < lower:
        raise ValueError("continuous-bound inputs are outside the governed domain")
    ab = a * b
    lower_denominator = b + c * lower
    upper_denominator = b + c * upper
    if ab <= lower_denominator * lower_denominator:
        return _endpoint_upper(a, b, c, lower)
    if ab >= upper_denominator * upper_denominator:
        return _endpoint_upper(a, b, c, upper)
    # The unique interior continuous maximum is
    # (sqrt(a) - sqrt(b))^2 / c = (a+b-2*sqrt(a*b))/c.
    # floor_sqrt(a*b) <= sqrt(a*b), so replacing the root with its floor
    # can only raise the numerator and therefore yields a safe upper bound.
    root_floor = math.isqrt(ab)
    numerator_upper = a + b - 2 * root_floor
    return _ceil_div(numerator_upper, c)


def _governed_interval_continuous_upper(
    a: int,
    b: int,
    c: int,
    lower: int,
    upper: int,
) -> int:
    """Clamp an optimistic continuous bound to the maximum exact EVM profit domain."""

    return min(
        _interval_continuous_upper(a, b, c, lower, upper),
        MAX_UINT256,
    )


def _can_interval_beat(
    bound: int,
    lower: int,
    best_profit: int,
    best_input: int,
) -> bool:
    if bound > best_profit:
        return True
    if bound < best_profit:
        return False
    if best_profit <= 0 or best_input == 0:
        return bound > 0
    return lower < best_input


def _empty_result(
    route: ConstantProductRoute,
    limits: OptimizationLimits,
    status: OptimizationStatus,
    *,
    effective_maximum_input: int,
    evaluated_inputs: int = 0,
    explored_intervals: int = 0,
    pruned_intervals: int = 0,
    continuous_upper_bound: int = 0,
    complete: bool = True,
) -> OptimizationResult:
    return OptimizationResult(
        route_sha256=route.digest,
        status=status,
        complete=complete,
        effective_maximum_input=effective_maximum_input,
        amount_in=0,
        amount_out=0,
        gross_profit=0,
        evaluated_inputs=evaluated_inputs,
        explored_intervals=explored_intervals,
        pruned_intervals=pruned_intervals,
        continuous_upper_bound=max(continuous_upper_bound, 0),
        limits=limits,
    )


def optimize_route(
    universe: PoolUniverse,
    route: ConstantProductRoute,
    limits: OptimizationLimits,
) -> OptimizationResult:
    if type(universe) is not PoolUniverse:
        raise TypeError("universe must be an exact PoolUniverse")
    if type(route) is not ConstantProductRoute:
        raise TypeError("route must be an exact ConstantProductRoute")
    if type(limits) is not OptimizationLimits:
        raise TypeError("limits must be an exact OptimizationLimits")
    route.validate_against(universe)
    effective_maximum = route.maximum_safe_input(universe, limits.maximum_input)
    if effective_maximum == 0:
        return _empty_result(
            route,
            limits,
            OptimizationStatus.NO_VALID_INPUT,
            effective_maximum_input=0,
        )

    a, b, c = route.continuous_coefficients(universe)
    if a <= b:
        return _empty_result(
            route,
            limits,
            OptimizationStatus.NO_POSITIVE_CONTINUOUS_EDGE,
            effective_maximum_input=effective_maximum,
        )
    full_bound = _governed_interval_continuous_upper(
        a, b, c, 1, effective_maximum
    )
    if full_bound <= 0:
        return _empty_result(
            route,
            limits,
            OptimizationStatus.NO_POSITIVE_CONTINUOUS_EDGE,
            effective_maximum_input=effective_maximum,
            continuous_upper_bound=full_bound,
        )

    queue: list[tuple[int, int, int]] = [(-full_bound, 1, effective_maximum)]
    best_profit = 0
    best_input = 0
    best_output = 0
    evaluated_inputs = 0
    explored_intervals = 0
    pruned_intervals = 0

    while queue:
        if explored_intervals >= limits.maximum_intervals:
            return _empty_result(
                route,
                limits,
                OptimizationStatus.BUDGET_EXHAUSTED,
                effective_maximum_input=effective_maximum,
                evaluated_inputs=evaluated_inputs,
                explored_intervals=explored_intervals,
                pruned_intervals=pruned_intervals,
                continuous_upper_bound=full_bound,
                complete=False,
            )
        negative_bound, lower, upper = heapq.heappop(queue)
        bound = -negative_bound
        explored_intervals += 1
        if not _can_interval_beat(bound, lower, best_profit, best_input):
            pruned_intervals += 1
            continue
        if upper - lower + 1 <= limits.exhaustive_threshold:
            for amount in range(lower, upper + 1):
                quote = route.quote_exact_in(universe, amount)
                evaluated_inputs += 1
                profit = quote.gross_profit
                if profit > best_profit or (
                    profit == best_profit
                    and profit > 0
                    and (best_input == 0 or amount < best_input)
                ):
                    best_profit = profit
                    best_input = amount
                    best_output = quote.amount_out
            continue
        middle = (lower + upper) // 2
        children = ((lower, middle), (middle + 1, upper))
        for child_lower, child_upper in children:
            child_bound = _governed_interval_continuous_upper(
                a, b, c, child_lower, child_upper
            )
            if _can_interval_beat(
                child_bound, child_lower, best_profit, best_input
            ):
                heapq.heappush(
                    queue,
                    (-child_bound, child_lower, child_upper),
                )
            else:
                pruned_intervals += 1

    if best_profit <= 0:
        return _empty_result(
            route,
            limits,
            OptimizationStatus.NO_POSITIVE_EXACT_PROFIT,
            effective_maximum_input=effective_maximum,
            evaluated_inputs=evaluated_inputs,
            explored_intervals=explored_intervals,
            pruned_intervals=pruned_intervals,
            continuous_upper_bound=full_bound,
        )
    return OptimizationResult(
        route_sha256=route.digest,
        status=OptimizationStatus.COMPLETE,
        complete=True,
        effective_maximum_input=effective_maximum,
        amount_in=best_input,
        amount_out=best_output,
        gross_profit=best_profit,
        evaluated_inputs=evaluated_inputs,
        explored_intervals=explored_intervals,
        pruned_intervals=pruned_intervals,
        continuous_upper_bound=full_bound,
        limits=limits,
    )
