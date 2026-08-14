from __future__ import annotations

from dataclasses import dataclass, field
import hashlib

from .canonical import canonical_json_bytes, canonical_sha256
from .constant_product import MAX_UINT256
from .cost_evidence import ConservativeNetProfitEvidence
from .deployments import (
    AuthenticatedExecutorDeployment,
    ROUTE_COMMAND_BINARY_BYTES,
    ROUTE_COMMAND_SCHEMA,
)
from .domain import require_bounded_text, require_sha256
from .evm_hex import to_hex_data
from .execution_plan import FundingKind
from .profit import BASIS_POINTS

CONSTRAINT_POLICY_SCHEMA = "aladdin-mev-execution-constraint-policy/v1"
ROUTE_COMMAND_SCHEMA_JSON = "aladdin-mev-route-command/v1"
EXECUTOR_CALL_SCHEMA = "aladdin-mev-governed-executor-call/v1"

MAX_UINT64 = (1 << 64) - 1
MAX_ROUTE_PAYLOAD_BYTES = 32_768
ROUTE_PAYLOAD_HEADER = b"AMEVF5R1"
ROUTE_PAYLOAD_VERSION = 1


def _uint256(name: str, value: object, *, positive: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT256:
        raise ValueError(f"{name} must be an unsigned 256-bit exact integer")
    if positive and value == 0:
        raise ValueError(f"{name} must be positive")
    return value


def _uint64(name: str, value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT64:
        raise ValueError(f"{name} must be an unsigned 64-bit exact integer")
    return value


def _address(name: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 20 or value == bytes(20):
        raise ValueError(f"{name} must be a non-zero exact 20-byte address")
    return value


def _bytes32(name: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise ValueError(f"{name} must be exact immutable 32-byte data")
    return value


def _checked_add(left: int, right: int, name: str) -> int:
    _uint256(f"{name} left", left)
    _uint256(f"{name} right", right)
    if right > MAX_UINT256 - left:
        raise ValueError(f"{name} exceeds uint256")
    return left + right


def _checked_mul(left: int, right: int, name: str) -> int:
    _uint256(f"{name} left", left)
    _uint256(f"{name} right", right)
    if left and right > MAX_UINT256 // left:
        raise ValueError(f"{name} exceeds uint256")
    return left * right


def _ceil_div(numerator: int, denominator: int) -> int:
    _uint256("ceil numerator", numerator)
    _uint256("ceil denominator", denominator, positive=True)
    quotient, remainder = divmod(numerator, denominator)
    return quotient + (1 if remainder else 0)


def _abi_word_uint(value: int) -> bytes:
    _uint256("ABI integer", value)
    return value.to_bytes(32, "big")


def _abi_word_address(value: bytes) -> bytes:
    _address("ABI address", value)
    return bytes(12) + value


def _abi_word_bytes32(value: bytes) -> bytes:
    return _bytes32("ABI bytes32", value)


def _abi_dynamic_bytes(payload: bytes) -> bytes:
    if type(payload) is not bytes:
        raise TypeError("ABI dynamic bytes payload must be exact immutable bytes")
    if len(payload) > MAX_ROUTE_PAYLOAD_BYTES:
        raise ValueError("ABI dynamic bytes payload exceeds the governed ceiling")
    padding = (-len(payload)) % 32
    return _abi_word_uint(len(payload)) + payload + bytes(padding)


def _validate_governed_route_payload(
    route_payload: object,
    *,
    base_token: bytes,
    principal: int,
    minimum_final_output: int,
) -> bytes:
    if type(route_payload) is not bytes:
        raise TypeError("route_payload must be exact immutable bytes")
    if len(route_payload) > MAX_ROUTE_PAYLOAD_BYTES:
        raise ValueError("route_payload exceeds the governed byte ceiling")
    header_length = len(ROUTE_PAYLOAD_HEADER) + 2
    if len(route_payload) < header_length:
        raise ValueError("route_payload is shorter than the governed frame header")
    if route_payload[: len(ROUTE_PAYLOAD_HEADER)] != ROUTE_PAYLOAD_HEADER:
        raise ValueError("route_payload header is not governed")
    version = route_payload[len(ROUTE_PAYLOAD_HEADER)]
    command_count = route_payload[len(ROUTE_PAYLOAD_HEADER) + 1]
    if version != ROUTE_PAYLOAD_VERSION:
        raise ValueError("route_payload version is not governed")
    if not 2 <= command_count <= 4:
        raise ValueError("route_payload command count is outside the governed range")
    expected_length = header_length + command_count * ROUTE_COMMAND_BINARY_BYTES
    if len(route_payload) != expected_length:
        raise ValueError("route_payload length does not match its command count")

    parsed: list[tuple[bytes, bytes, bytes, int, int, int]] = []
    used_pools: set[bytes] = set()
    for index in range(command_count):
        start = header_length + index * ROUTE_COMMAND_BINARY_BYTES
        command = route_payload[start : start + ROUTE_COMMAND_BINARY_BYTES]
        if command[0] != index:
            raise ValueError("route_payload command indexes must be contiguous and canonical")
        pool_address = command[1:21]
        token_in = command[21:41]
        token_out = command[41:61]
        _address("route payload pool_address", pool_address)
        _address("route payload token_in", token_in)
        _address("route payload token_out", token_out)
        if pool_address in used_pools:
            raise ValueError("route_payload cannot reuse a pool")
        used_pools.add(pool_address)
        if token_in == token_out:
            raise ValueError("route_payload command tokens must be distinct")
        amount_in = int.from_bytes(command[61:93], "big")
        expected_amount_out = int.from_bytes(command[93:125], "big")
        minimum_amount_out = int.from_bytes(command[125:157], "big")
        _uint256("route payload amount_in", amount_in, positive=True)
        _uint256("route payload expected_amount_out", expected_amount_out, positive=True)
        _uint256("route payload minimum_amount_out", minimum_amount_out)
        if minimum_amount_out > expected_amount_out:
            raise ValueError("route_payload minimum output exceeds expected output")
        if command[157:189] == bytes(32):
            raise ValueError("route_payload quote digest cannot be zero")
        parsed.append(
            (
                pool_address,
                token_in,
                token_out,
                amount_in,
                expected_amount_out,
                minimum_amount_out,
            )
        )

    first = parsed[0]
    if first[1] != base_token:
        raise ValueError("route_payload first input token must equal the governed base token")
    if first[3] != principal:
        raise ValueError("route_payload first input amount must equal the governed principal")

    intermediate_tokens: set[bytes] = set()
    for index, current in enumerate(parsed):
        _pool, _token_in, token_out, _amount_in, expected_out, minimum_out = current
        if index:
            previous = parsed[index - 1]
            if previous[2] != current[1]:
                raise ValueError("route_payload token flow is disconnected")
            if previous[4] != current[3]:
                raise ValueError("route_payload amount flow is disconnected")
        if index < command_count - 1:
            if token_out == base_token:
                raise ValueError("route_payload returns to the base token before the final command")
            if token_out in intermediate_tokens:
                raise ValueError("route_payload repeats an intermediate token")
            intermediate_tokens.add(token_out)
        else:
            if token_out != base_token:
                raise ValueError("route_payload final output token must equal the governed base token")
            if expected_out < minimum_final_output:
                raise ValueError("route_payload final expected output is below the governed minimum")
            if minimum_out != minimum_final_output:
                raise ValueError("route_payload final command minimum must equal the governed final minimum")
    return route_payload


def encode_governed_execute_call(
    *,
    selector: bytes,
    plan_sha256: bytes,
    base_token: bytes,
    principal: int,
    minimum_final_output: int,
    deadline_unix_s: int,
    route_payload: bytes,
) -> bytes:
    if type(selector) is not bytes or len(selector) != 4 or selector == bytes(4):
        raise ValueError("function selector must be non-zero exact 4-byte data")
    _bytes32("plan_sha256", plan_sha256)
    if plan_sha256 == bytes(32):
        raise ValueError("plan_sha256 cannot be zero")
    _address("base_token", base_token)
    _uint256("principal", principal, positive=True)
    _uint256("minimum_final_output", minimum_final_output, positive=True)
    if minimum_final_output < principal:
        raise ValueError("minimum_final_output cannot be smaller than principal")
    _uint64("deadline_unix_s", deadline_unix_s)
    if deadline_unix_s == 0:
        raise ValueError("deadline_unix_s must be positive")
    payload = _validate_governed_route_payload(
        route_payload,
        base_token=base_token,
        principal=principal,
        minimum_final_output=minimum_final_output,
    )
    dynamic_offset = 32 * 6
    head = b"".join(
        (
            _abi_word_bytes32(plan_sha256),
            _abi_word_address(base_token),
            _abi_word_uint(principal),
            _abi_word_uint(minimum_final_output),
            _abi_word_uint(deadline_unix_s),
            _abi_word_uint(dynamic_offset),
        )
    )
    return selector + head + _abi_dynamic_bytes(payload)


@dataclass(frozen=True, slots=True)
class ExecutionConstraintPolicy:
    policy_id: str
    maximum_slippage_bps: int
    maximum_deadline_horizon_ms: int
    schema: str = CONSTRAINT_POLICY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != CONSTRAINT_POLICY_SCHEMA:
            raise ValueError("unsupported execution-constraint-policy schema")
        require_bounded_text("policy_id", self.policy_id, maximum=128)
        _uint256("maximum_slippage_bps", self.maximum_slippage_bps)
        if self.maximum_slippage_bps > BASIS_POINTS:
            raise ValueError("maximum_slippage_bps cannot exceed 10000")
        _uint64("maximum_deadline_horizon_ms", self.maximum_deadline_horizon_ms)
        if self.maximum_deadline_horizon_ms == 0:
            raise ValueError("maximum_deadline_horizon_ms must be positive")
        canonical_json_bytes(self.to_json_value())

    def to_json_value(self) -> dict[str, str]:
        return {
            "schema": self.schema,
            "policy_id": self.policy_id,
            "maximum_slippage_bps": str(self.maximum_slippage_bps),
            "maximum_deadline_horizon_ms": str(self.maximum_deadline_horizon_ms),
            "minimum_output_semantics": "max-economic-policy-floor-slippage-floor",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class RouteCommand:
    index: int
    pool_address: bytes
    token_in: bytes
    token_out: bytes
    amount_in: int
    expected_amount_out: int
    minimum_amount_out: int
    quote_sha256: str
    schema: str = ROUTE_COMMAND_SCHEMA_JSON

    def __post_init__(self) -> None:
        if self.schema != ROUTE_COMMAND_SCHEMA_JSON:
            raise ValueError("unsupported route-command schema")
        if type(self.index) is not int or not 0 <= self.index < 4:
            raise ValueError("route-command index must be an exact integer from 0 through 3")
        _address("pool_address", self.pool_address)
        _address("token_in", self.token_in)
        _address("token_out", self.token_out)
        if self.token_in == self.token_out:
            raise ValueError("route-command tokens must be distinct")
        _uint256("amount_in", self.amount_in, positive=True)
        _uint256("expected_amount_out", self.expected_amount_out, positive=True)
        _uint256("minimum_amount_out", self.minimum_amount_out)
        if self.minimum_amount_out > self.expected_amount_out:
            raise ValueError("route-command minimum output exceeds expected output")
        require_sha256("quote_sha256", self.quote_sha256)
        if self.quote_sha256 == "0" * 64:
            raise ValueError("route-command quote_sha256 cannot be zero")
        canonical_json_bytes(self.to_json_value())

    @property
    def binary(self) -> bytes:
        return b"".join(
            (
                bytes((self.index,)),
                self.pool_address,
                self.token_in,
                self.token_out,
                self.amount_in.to_bytes(32, "big"),
                self.expected_amount_out.to_bytes(32, "big"),
                self.minimum_amount_out.to_bytes(32, "big"),
                bytes.fromhex(self.quote_sha256),
            )
        )

    def to_json_value(self) -> dict[str, str]:
        return {
            "schema": self.schema,
            "index": str(self.index),
            "pool_address": to_hex_data(self.pool_address),
            "token_in": to_hex_data(self.token_in),
            "token_out": to_hex_data(self.token_out),
            "amount_in": str(self.amount_in),
            "expected_amount_out": str(self.expected_amount_out),
            "minimum_amount_out": str(self.minimum_amount_out),
            "quote_sha256": self.quote_sha256,
            "binary": to_hex_data(self.binary),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class GovernedExecutorCall:
    net_profit_evidence: ConservativeNetProfitEvidence
    deployment: AuthenticatedExecutorDeployment
    constraints: ExecutionConstraintPolicy
    created_at_unix_ms: int
    schema: str = EXECUTOR_CALL_SCHEMA
    _commands: tuple[RouteCommand, ...] = field(init=False, repr=False)
    _route_payload: bytes = field(init=False, repr=False)
    _minimum_final_output: int = field(init=False, repr=False)
    _deadline_unix_s: int = field(init=False, repr=False)
    _inputs_valid_until_unix_ms: int = field(init=False, repr=False)
    _calldata: bytes = field(init=False, repr=False)
    _call_id: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != EXECUTOR_CALL_SCHEMA:
            raise ValueError("unsupported governed-executor-call schema")
        if type(self.net_profit_evidence) is not ConservativeNetProfitEvidence:
            raise TypeError("net_profit_evidence must be exact ConservativeNetProfitEvidence")
        if type(self.deployment) is not AuthenticatedExecutorDeployment:
            raise TypeError("deployment must be exact AuthenticatedExecutorDeployment")
        if type(self.constraints) is not ExecutionConstraintPolicy:
            raise TypeError("constraints must be exact ExecutionConstraintPolicy")
        _uint64("created_at_unix_ms", self.created_at_unix_ms)
        evidence = self.net_profit_evidence
        if not evidence.decision.approved:
            raise ValueError("F5 call construction requires an approved F4 shadow decision")
        if self.created_at_unix_ms < evidence.created_at_unix_ms:
            raise ValueError("executor call cannot precede F4 net-profit evidence")
        if self.created_at_unix_ms > evidence.inputs_valid_until_unix_ms:
            raise ValueError("F4 net-profit inputs are expired at executor-call creation")
        if self.created_at_unix_ms < self.deployment.evidence.proof_observed_at_unix_ms:
            raise ValueError("executor call cannot precede deployment proof observation")
        plan = evidence.plan
        interface = self.deployment.spec.interface
        if plan.funding.kind is not FundingKind.FLASH_LOAN:
            raise ValueError("F5 executor interface v1 supports recorded flash-loan funding only")
        if (
            plan.funding.provider_id != interface.flash_loan_provider_id
            or plan.funding.source_sha256 != interface.flash_loan_source_sha256
        ):
            raise ValueError("F4 funding plan does not match the executor interface funding authority")
        chain = plan.opportunity.universe.chain
        if self.deployment.chain is not chain:
            raise ValueError("executor deployment chain does not match the execution plan")
        if self.deployment.anchor_sha256 != plan.opportunity.universe.snapshot.anchor.digest:
            raise ValueError("executor deployment does not bind the exact F4 state anchor")

        expected_final = plan.opportunity.route_quote.amount_out
        principal = plan.opportunity.capital_at_risk
        policy = evidence.profit_policy
        required_return = _ceil_div(
            _checked_mul(principal, policy.minimum_return_bps, "required return"),
            BASIS_POINTS,
        )
        required_profit = max(policy.minimum_absolute_profit, required_return)
        economic_floor = _checked_add(
            _checked_add(principal, evidence.cost_envelope.costs.total_cost, "economic floor"),
            required_profit,
            "economic floor",
        )
        slippage_numerator = BASIS_POINTS - self.constraints.maximum_slippage_bps
        slippage_floor = _ceil_div(
            _checked_mul(expected_final, slippage_numerator, "slippage floor"),
            BASIS_POINTS,
        )
        minimum_final = max(economic_floor, slippage_floor)
        if minimum_final > expected_final:
            raise ValueError("F4 economics cannot satisfy the governed minimum-output constraint")

        commands: list[RouteCommand] = []
        steps = plan.steps
        for index, step in enumerate(steps):
            minimum = _ceil_div(
                _checked_mul(
                    step.amount_out,
                    slippage_numerator,
                    "route-command slippage floor",
                ),
                BASIS_POINTS,
            )
            if index == len(steps) - 1:
                minimum = max(minimum, minimum_final)
            commands.append(
                RouteCommand(
                    index=index,
                    pool_address=step.pool_address,
                    token_in=step.token_in,
                    token_out=step.token_out,
                    amount_in=step.amount_in,
                    expected_amount_out=step.amount_out,
                    minimum_amount_out=minimum,
                    quote_sha256=step.quote_sha256,
                )
            )
        command_tuple = tuple(commands)
        if not 2 <= len(command_tuple) <= 4:
            raise ValueError("executor-call route command count is outside the governed range")
        payload = ROUTE_PAYLOAD_HEADER + bytes((ROUTE_PAYLOAD_VERSION, len(command_tuple))) + b"".join(
            item.binary for item in command_tuple
        )
        if len(payload) > MAX_ROUTE_PAYLOAD_BYTES:
            raise ValueError("route-command payload exceeds the governed byte ceiling")

        inputs_valid_until_ms = min(
            evidence.inputs_valid_until_unix_ms,
            self.created_at_unix_ms + self.constraints.maximum_deadline_horizon_ms,
        )
        deadline_s = inputs_valid_until_ms // 1000
        if deadline_s <= self.created_at_unix_ms // 1000:
            raise ValueError("executor-call deadline must be strictly after creation time")
        calldata = encode_governed_execute_call(
            selector=self.deployment.spec.interface.function_selector,
            plan_sha256=bytes.fromhex(plan.digest),
            base_token=plan.base_asset.address,
            principal=principal,
            minimum_final_output=minimum_final,
            deadline_unix_s=deadline_s,
            route_payload=payload,
        )
        if len(calldata) > self.deployment.spec.interface.maximum_calldata_bytes:
            raise ValueError("executor calldata exceeds the authenticated interface ceiling")
        identity = {
            "schema": self.schema,
            "net_profit_evidence_sha256": evidence.digest,
            "deployment_sha256": self.deployment.digest,
            "constraint_policy_sha256": self.constraints.digest,
            "route_command_sha256": [item.digest for item in command_tuple],
            "minimum_final_output": str(minimum_final),
            "deadline_unix_s": str(deadline_s),
            "inputs_valid_until_unix_ms": str(inputs_valid_until_ms),
            "calldata": to_hex_data(calldata),
            "created_at_unix_ms": str(self.created_at_unix_ms),
        }
        object.__setattr__(self, "_commands", command_tuple)
        object.__setattr__(self, "_route_payload", payload)
        object.__setattr__(self, "_minimum_final_output", minimum_final)
        object.__setattr__(self, "_deadline_unix_s", deadline_s)
        object.__setattr__(self, "_inputs_valid_until_unix_ms", inputs_valid_until_ms)
        object.__setattr__(self, "_calldata", calldata)
        object.__setattr__(self, "_call_id", "executor-call-" + canonical_sha256(identity))
        canonical_json_bytes(self.to_json_value())

    @property
    def commands(self) -> tuple[RouteCommand, ...]:
        return self._commands

    @property
    def route_payload(self) -> bytes:
        return self._route_payload

    @property
    def minimum_final_output(self) -> int:
        return self._minimum_final_output

    @property
    def deadline_unix_s(self) -> int:
        return self._deadline_unix_s

    @property
    def inputs_valid_until_unix_ms(self) -> int:
        return self._inputs_valid_until_unix_ms

    @property
    def calldata(self) -> bytes:
        return self._calldata

    @property
    def call_id(self) -> str:
        return self._call_id

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "call_id": self.call_id,
            "net_profit_evidence_sha256": self.net_profit_evidence.digest,
            "execution_plan_sha256": self.net_profit_evidence.plan.digest,
            "deployment": self.deployment.to_json_value(),
            "deployment_sha256": self.deployment.digest,
            "constraint_policy": self.constraints.to_json_value(),
            "constraint_policy_sha256": self.constraints.digest,
            "route_command_schema": ROUTE_COMMAND_SCHEMA,
            "commands": [item.to_json_value() for item in self.commands],
            "route_command_sha256": [item.digest for item in self.commands],
            "route_payload": to_hex_data(self.route_payload),
            "principal": str(self.net_profit_evidence.plan.opportunity.capital_at_risk),
            "minimum_final_output": str(self.minimum_final_output),
            "deadline_unix_s": str(self.deadline_unix_s),
            "inputs_valid_until_unix_ms": str(self.inputs_valid_until_unix_ms),
            "function_selector": to_hex_data(self.deployment.spec.interface.function_selector),
            "calldata": to_hex_data(self.calldata),
            "calldata_sha256": hashlib.sha256(self.calldata).hexdigest(),
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "calldata_authority": "deterministic-governed-unsigned-only",
            "signing_eligible": False,
            "execution_eligible": False,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())
