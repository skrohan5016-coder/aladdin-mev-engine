from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from .assets import AssetId, AssetKind
from .canonical import canonical_json_bytes, canonical_sha256
from .constant_product import MAX_UINT256, PoolSwapQuote
from .domain import require_bounded_text, require_sha256
from .evm_hex import to_hex_data
from .opportunity import AtomicDexOpportunityEvidence, MAX_UINT64

FUNDING_SCHEMA = "aladdin-mev-funding-plan/v1"
EXECUTION_PLAN_SCHEMA = "aladdin-mev-atomic-execution-plan/v1"
MAX_EXECUTION_STEPS = 4


class FundingKind(StrEnum):
    OWN_INVENTORY = "own-inventory"
    FLASH_LOAN = "flash-loan"


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


@dataclass(frozen=True, slots=True)
class FundingPlan:
    kind: FundingKind
    asset: AssetId
    principal: int
    fee: int
    provider_id: str
    observed_at_unix_ms: int
    valid_until_unix_ms: int
    source_sha256: str
    schema: str = FUNDING_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != FUNDING_SCHEMA:
            raise ValueError("unsupported funding-plan schema")
        if type(self.kind) is not FundingKind:
            raise TypeError("kind must be an exact FundingKind")
        if type(self.asset) is not AssetId:
            raise TypeError("asset must be an exact AssetId")
        if self.asset.kind is not AssetKind.ERC20:
            raise ValueError("F4 atomic route funding must use the exact ERC20 base asset")
        _uint("principal", self.principal, positive=True)
        _uint("fee", self.fee)
        require_bounded_text("provider_id", self.provider_id, maximum=128)
        _time("observed_at_unix_ms", self.observed_at_unix_ms)
        _time("valid_until_unix_ms", self.valid_until_unix_ms)
        if self.valid_until_unix_ms < self.observed_at_unix_ms:
            raise ValueError("funding validity cannot precede observation")
        require_sha256("source_sha256", self.source_sha256)
        if self.kind is FundingKind.OWN_INVENTORY:
            if self.provider_id != "self":
                raise ValueError("own-inventory funding provider_id must be self")
            if self.fee != 0:
                raise ValueError("own-inventory funding cannot claim a flash-loan fee")
        elif self.kind is FundingKind.FLASH_LOAN:
            if self.provider_id == "self":
                raise ValueError("flash-loan funding requires an external provider identity")
        canonical_json_bytes(self.to_json_value())

    def is_valid_at(self, at_unix_ms: int) -> bool:
        _time("at_unix_ms", at_unix_ms)
        return self.observed_at_unix_ms <= at_unix_ms <= self.valid_until_unix_ms

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "kind": self.kind.value,
            "asset": self.asset.to_json_value(),
            "principal": str(self.principal),
            "fee": str(self.fee),
            "provider_id": self.provider_id,
            "observed_at_unix_ms": str(self.observed_at_unix_ms),
            "valid_until_unix_ms": str(self.valid_until_unix_ms),
            "source_sha256": self.source_sha256,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class ExecutionStep:
    index: int
    pool_address: bytes
    token_in: bytes
    token_out: bytes
    amount_in: int
    amount_out: int
    quote_sha256: str

    def __post_init__(self) -> None:
        if type(self.index) is not int or not 0 <= self.index < MAX_EXECUTION_STEPS:
            raise ValueError("execution-step index is outside the governed range")
        for name, value in (
            ("pool_address", self.pool_address),
            ("token_in", self.token_in),
            ("token_out", self.token_out),
        ):
            if type(value) is not bytes or len(value) != 20 or value == bytes(20):
                raise ValueError(f"{name} must be a non-zero exact 20-byte address")
        if self.token_in == self.token_out:
            raise ValueError("execution-step tokens must be distinct")
        _uint("amount_in", self.amount_in)
        _uint("amount_out", self.amount_out)
        require_sha256("quote_sha256", self.quote_sha256)
        canonical_json_bytes(self.to_json_value())

    @classmethod
    def from_quote(cls, index: int, quote: PoolSwapQuote) -> ExecutionStep:
        if type(quote) is not PoolSwapQuote:
            raise TypeError("quote must be an exact PoolSwapQuote")
        return cls(
            index=index,
            pool_address=quote.pool_address,
            token_in=quote.token_in,
            token_out=quote.token_out,
            amount_in=quote.amount_in,
            amount_out=quote.amount_out,
            quote_sha256=quote.digest,
        )

    def to_json_value(self) -> dict[str, str]:
        return {
            "index": str(self.index),
            "pool_address": to_hex_data(self.pool_address),
            "token_in": to_hex_data(self.token_in),
            "token_out": to_hex_data(self.token_out),
            "amount_in": str(self.amount_in),
            "amount_out": str(self.amount_out),
            "quote_sha256": self.quote_sha256,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class AtomicExecutionPlan:
    opportunity: AtomicDexOpportunityEvidence
    funding: FundingPlan
    created_at_unix_ms: int
    schema: str = EXECUTION_PLAN_SCHEMA
    _base_asset: AssetId = field(init=False, repr=False)
    _steps: tuple[ExecutionStep, ...] = field(init=False, repr=False)
    _plan_id: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != EXECUTION_PLAN_SCHEMA:
            raise ValueError("unsupported atomic-execution-plan schema")
        if type(self.opportunity) is not AtomicDexOpportunityEvidence:
            raise TypeError("opportunity must be exact AtomicDexOpportunityEvidence")
        if type(self.funding) is not FundingPlan:
            raise TypeError("funding must be an exact FundingPlan")
        _time("created_at_unix_ms", self.created_at_unix_ms)
        if self.created_at_unix_ms < self.opportunity.created_at_unix_ms:
            raise ValueError("execution plan cannot precede its F3 opportunity")
        if not self.funding.is_valid_at(self.created_at_unix_ms):
            raise ValueError("funding plan is not valid at execution-plan creation time")
        base_asset = AssetId.erc20(
            self.opportunity.universe.chain,
            self.opportunity.route.base_token,
        )
        if self.funding.asset != base_asset:
            raise ValueError("funding asset does not match the exact route base asset")
        if self.funding.principal != self.opportunity.capital_at_risk:
            raise ValueError("funding principal does not match exact F3 capital at risk")
        steps = tuple(
            ExecutionStep.from_quote(index, quote)
            for index, quote in enumerate(self.opportunity.route_quote.legs)
        )
        if not 2 <= len(steps) <= MAX_EXECUTION_STEPS:
            raise ValueError("execution-plan step count is outside the governed range")
        if steps[0].amount_in != self.funding.principal:
            raise ValueError("first execution step does not consume the exact principal")
        for previous, current in zip(steps, steps[1:]):
            if (
                previous.token_out != current.token_in
                or previous.amount_out != current.amount_in
            ):
                raise ValueError("execution-plan token or amount flow is disconnected")
        if steps[-1].token_out != steps[0].token_in:
            raise ValueError("execution plan does not return to its base token")
        if steps[-1].amount_out != self.opportunity.route_quote.amount_out:
            raise ValueError("execution plan output does not match exact F3 route output")
        identity = {
            "schema": self.schema,
            "opportunity_sha256": self.opportunity.digest,
            "funding_sha256": self.funding.digest,
            "base_asset_sha256": base_asset.digest,
            "step_sha256": [item.digest for item in steps],
            "execution_authority": "none",
        }
        object.__setattr__(self, "_base_asset", base_asset)
        object.__setattr__(self, "_steps", steps)
        object.__setattr__(self, "_plan_id", "atomic-plan-" + canonical_sha256(identity))
        canonical_json_bytes(self.to_json_value())

    @property
    def base_asset(self) -> AssetId:
        return self._base_asset

    @property
    def steps(self) -> tuple[ExecutionStep, ...]:
        return self._steps

    @property
    def plan_id(self) -> str:
        return self._plan_id

    @property
    def gross_profit(self) -> int:
        return self.opportunity.gross_profit

    @property
    def residual_before_external_costs(self) -> int:
        return self.gross_profit - self.funding.fee

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "opportunity_id": self.opportunity.opportunity_id,
            "opportunity_sha256": self.opportunity.digest,
            "state_reference": self.opportunity.universe.state_reference.to_json_value(),
            "base_asset": self.base_asset.to_json_value(),
            "funding": self.funding.to_json_value(),
            "funding_sha256": self.funding.digest,
            "steps": [item.to_json_value() for item in self.steps],
            "step_sha256": [item.digest for item in self.steps],
            "gross_profit": str(self.gross_profit),
            "residual_before_external_costs": str(self.residual_before_external_costs),
            "calldata_authority": "none",
            "signing_authority": "none",
            "execution_eligible": False,
            "created_at_unix_ms": str(self.created_at_unix_ms),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())
