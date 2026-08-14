from __future__ import annotations

from dataclasses import dataclass, field

from .canonical import canonical_json_bytes, canonical_sha256
from .constant_product import MAX_UINT256
from .cost_evidence import ConservativeNetProfitEvidence
from .domain import require_bounded_text, require_sha256
from .evm_abi import GovernedExecutorCall
from .evm_hex import to_hex_data
from .head_tracker import EvmHead
from .evm_transaction import PrivateBundleIntent, UnsignedEip1559Transaction

TX_SIMULATION_SCHEMA = "aladdin-mev-transaction-simulation-result/v1"
UNSIGNED_PACKAGE_SCHEMA = "aladdin-mev-unsigned-execution-package/v1"
MAX_SIMULATIONS = 8
MAX_UINT64 = (1 << 64) - 1


def _uint256(name: str, value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT256:
        raise ValueError(f"{name} must be an unsigned 256-bit exact integer")
    return value


def _uint64(name: str, value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT64:
        raise ValueError(f"{name} must be an unsigned 64-bit exact integer")
    return value


def _address(name: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 20 or value == bytes(20):
        raise ValueError(f"{name} must be a non-zero exact 20-byte address")
    return value


def _checked_add(left: int, right: int, name: str) -> int:
    _uint256(f"{name} left", left)
    _uint256(f"{name} right", right)
    if right > MAX_UINT256 - left:
        raise ValueError(f"{name} exceeds uint256")
    return left + right


@dataclass(frozen=True, slots=True)
class TransactionSimulationResult:
    engine_id: str
    engine_implementation_sha256: str
    environment_sha256: str
    result_source_sha256: str
    state_anchor_sha256: str
    transaction_sha256: str
    transaction_signing_hash: str
    bundle_sha256: str
    simulated_block_number: int
    simulated_block_timestamp_unix_s: int
    simulated_base_fee_per_gas: int
    success: bool
    gas_used: int
    operator_fee_paid: int
    output_amount: int
    base_token: bytes
    flash_loan_principal_repaid: int
    flash_loan_fee_paid: int
    base_token_residual_before_external_costs: int
    base_token_beneficiary: bytes
    base_token_beneficiary_delta: int
    token_deltas_sha256: str
    logs_sha256: str
    post_state_sha256: str
    coinbase_payment: int
    observed_at_unix_ms: int
    valid_until_unix_ms: int
    error_code: str | None = None
    schema: str = TX_SIMULATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != TX_SIMULATION_SCHEMA:
            raise ValueError("unsupported transaction-simulation-result schema")
        require_bounded_text("engine_id", self.engine_id, maximum=128)
        for name in (
            "engine_implementation_sha256",
            "environment_sha256",
            "result_source_sha256",
            "state_anchor_sha256",
            "transaction_sha256",
            "bundle_sha256",
            "token_deltas_sha256",
            "logs_sha256",
            "post_state_sha256",
        ):
            require_sha256(name, getattr(self, name))
        if not isinstance(self.transaction_signing_hash, str) or not self.transaction_signing_hash.startswith("0x"):
            raise ValueError("transaction_signing_hash must be canonical 0x-prefixed data")
        raw = self.transaction_signing_hash[2:]
        if len(raw) != 64 or any(char not in "0123456789abcdef" for char in raw):
            raise ValueError("transaction_signing_hash must be a lowercase exact 32-byte hash")
        _uint64("simulated_block_number", self.simulated_block_number)
        _uint64(
            "simulated_block_timestamp_unix_s",
            self.simulated_block_timestamp_unix_s,
        )
        _uint256("simulated_base_fee_per_gas", self.simulated_base_fee_per_gas)
        if type(self.success) is not bool:
            raise TypeError("success must be an exact bool")
        _uint256("gas_used", self.gas_used)
        _uint256("operator_fee_paid", self.operator_fee_paid)
        _uint256("output_amount", self.output_amount)
        _address("base_token", self.base_token)
        _uint256("flash_loan_principal_repaid", self.flash_loan_principal_repaid)
        _uint256("flash_loan_fee_paid", self.flash_loan_fee_paid)
        _uint256(
            "base_token_residual_before_external_costs",
            self.base_token_residual_before_external_costs,
        )
        _address("base_token_beneficiary", self.base_token_beneficiary)
        _uint256("base_token_beneficiary_delta", self.base_token_beneficiary_delta)
        _uint256("coinbase_payment", self.coinbase_payment)
        _uint64("observed_at_unix_ms", self.observed_at_unix_ms)
        _uint64("valid_until_unix_ms", self.valid_until_unix_ms)
        if self.valid_until_unix_ms < self.observed_at_unix_ms:
            raise ValueError("transaction simulation validity cannot precede observation")
        if self.error_code is not None:
            require_bounded_text("error_code", self.error_code, maximum=128)
        if self.success:
            if self.error_code is not None:
                raise ValueError("successful transaction simulation cannot carry an error code")
            if self.gas_used == 0:
                raise ValueError("successful transaction simulation requires positive gas")
            if self.flash_loan_principal_repaid == 0:
                raise ValueError("successful F5 simulation requires positive principal repayment")
            repayment = _checked_add(
                self.flash_loan_principal_repaid,
                self.flash_loan_fee_paid,
                "flash-loan repayment",
            )
            if self.output_amount < repayment:
                raise ValueError("simulation output cannot cover recorded flash-loan repayment")
            if self.base_token_residual_before_external_costs != self.output_amount - repayment:
                raise ValueError("simulation base-token residual does not reconcile")
            if self.base_token_beneficiary_delta != self.base_token_residual_before_external_costs:
                raise ValueError("simulation beneficiary delta does not equal the complete base-token residual")
        else:
            if self.error_code is None:
                raise ValueError("failed transaction simulation requires an error code")
            if any((
                self.gas_used,
                self.operator_fee_paid,
                self.output_amount,
                self.flash_loan_principal_repaid,
                self.flash_loan_fee_paid,
                self.base_token_residual_before_external_costs,
                self.base_token_beneficiary_delta,
                self.coinbase_payment,
            )):
                raise ValueError("failed transaction simulation cannot claim economic outputs")
        canonical_json_bytes(self.to_json_value())

    def is_valid_at(self, at_unix_ms: int) -> bool:
        _uint64("at_unix_ms", at_unix_ms)
        return self.observed_at_unix_ms <= at_unix_ms <= self.valid_until_unix_ms

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "engine_id": self.engine_id,
            "engine_implementation_sha256": self.engine_implementation_sha256,
            "environment_sha256": self.environment_sha256,
            "result_source_sha256": self.result_source_sha256,
            "state_anchor_sha256": self.state_anchor_sha256,
            "transaction_sha256": self.transaction_sha256,
            "transaction_signing_hash": self.transaction_signing_hash,
            "bundle_sha256": self.bundle_sha256,
            "simulated_block_number": str(self.simulated_block_number),
            "simulated_block_timestamp_unix_s": str(
                self.simulated_block_timestamp_unix_s
            ),
            "simulated_base_fee_per_gas": str(self.simulated_base_fee_per_gas),
            "success": self.success,
            "gas_used": str(self.gas_used),
            "operator_fee_paid": str(self.operator_fee_paid),
            "output_amount": str(self.output_amount),
            "base_token": to_hex_data(self.base_token),
            "flash_loan_principal_repaid": str(self.flash_loan_principal_repaid),
            "flash_loan_fee_paid": str(self.flash_loan_fee_paid),
            "base_token_residual_before_external_costs": str(
                self.base_token_residual_before_external_costs
            ),
            "base_token_beneficiary": to_hex_data(self.base_token_beneficiary),
            "base_token_beneficiary_delta": str(self.base_token_beneficiary_delta),
            "token_deltas_sha256": self.token_deltas_sha256,
            "logs_sha256": self.logs_sha256,
            "post_state_sha256": self.post_state_sha256,
            "coinbase_payment": str(self.coinbase_payment),
            "observed_at_unix_ms": str(self.observed_at_unix_ms),
            "valid_until_unix_ms": str(self.valid_until_unix_ms),
            "error_code": self.error_code,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


def transaction_simulations_agree(
    simulations: tuple[TransactionSimulationResult, ...],
) -> bool:
    if type(simulations) is not tuple or not 2 <= len(simulations) <= MAX_SIMULATIONS:
        return False
    if any(type(item) is not TransactionSimulationResult for item in simulations):
        return False
    if len({item.engine_id for item in simulations}) != len(simulations):
        return False
    if len({item.engine_implementation_sha256 for item in simulations}) != len(simulations):
        return False
    if len({item.result_source_sha256 for item in simulations}) != len(simulations):
        return False
    if len({item.environment_sha256 for item in simulations}) != 1:
        return False
    reference = simulations[0]
    if not reference.success:
        return False
    return all(
        item.success
        and item.state_anchor_sha256 == reference.state_anchor_sha256
        and item.transaction_sha256 == reference.transaction_sha256
        and item.transaction_signing_hash == reference.transaction_signing_hash
        and item.bundle_sha256 == reference.bundle_sha256
        and item.simulated_block_number == reference.simulated_block_number
        and (
            item.simulated_block_timestamp_unix_s
            == reference.simulated_block_timestamp_unix_s
        )
        and item.simulated_base_fee_per_gas == reference.simulated_base_fee_per_gas
        and item.gas_used == reference.gas_used
        and item.operator_fee_paid == reference.operator_fee_paid
        and item.output_amount == reference.output_amount
        and item.base_token == reference.base_token
        and item.flash_loan_principal_repaid == reference.flash_loan_principal_repaid
        and item.flash_loan_fee_paid == reference.flash_loan_fee_paid
        and (
            item.base_token_residual_before_external_costs
            == reference.base_token_residual_before_external_costs
        )
        and item.base_token_beneficiary == reference.base_token_beneficiary
        and item.base_token_beneficiary_delta == reference.base_token_beneficiary_delta
        and item.token_deltas_sha256 == reference.token_deltas_sha256
        and item.logs_sha256 == reference.logs_sha256
        and item.post_state_sha256 == reference.post_state_sha256
        and item.coinbase_payment == reference.coinbase_payment
        and item.error_code == reference.error_code
        for item in simulations[1:]
    )


@dataclass(frozen=True, slots=True)
class UnsignedExecutionPackageEvidence:
    net_profit_evidence: ConservativeNetProfitEvidence
    call: GovernedExecutorCall
    transaction: UnsignedEip1559Transaction
    bundle: PrivateBundleIntent
    simulations: tuple[TransactionSimulationResult, ...]
    created_at_unix_ms: int
    schema: str = UNSIGNED_PACKAGE_SCHEMA
    _valid_until_unix_ms: int = field(init=False, repr=False)
    _package_id: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema != UNSIGNED_PACKAGE_SCHEMA:
            raise ValueError("unsupported unsigned-execution-package schema")
        if type(self.net_profit_evidence) is not ConservativeNetProfitEvidence:
            raise TypeError("net_profit_evidence must be exact ConservativeNetProfitEvidence")
        if type(self.call) is not GovernedExecutorCall:
            raise TypeError("call must be exact GovernedExecutorCall")
        if type(self.transaction) is not UnsignedEip1559Transaction:
            raise TypeError("transaction must be exact UnsignedEip1559Transaction")
        if type(self.bundle) is not PrivateBundleIntent:
            raise TypeError("bundle must be exact PrivateBundleIntent")
        if type(self.simulations) is not tuple or not 2 <= len(self.simulations) <= MAX_SIMULATIONS:
            raise ValueError("two to eight transaction simulations are required")
        if any(type(item) is not TransactionSimulationResult for item in self.simulations):
            raise TypeError("simulations contain an ungoverned result")
        ordered = tuple(
            sorted(
                self.simulations,
                key=lambda item: (
                    item.engine_id,
                    item.engine_implementation_sha256,
                    item.digest,
                ),
            )
        )
        object.__setattr__(self, "simulations", ordered)
        _uint64("created_at_unix_ms", self.created_at_unix_ms)
        evidence = self.net_profit_evidence
        if not evidence.decision.approved:
            raise ValueError("unsigned execution package requires approved F4 shadow economics")
        if self.call.net_profit_evidence.digest != evidence.digest:
            raise ValueError("executor call does not bind the exact F4 evidence")
        if self.transaction.call.digest != self.call.digest:
            raise ValueError("unsigned transaction does not bind the exact executor call")
        if len(self.bundle.transactions) != 1 or self.bundle.transactions[0].digest != self.transaction.digest:
            raise ValueError("F5 package requires exactly the bound unsigned transaction")
        if self.created_at_unix_ms < self.bundle.created_at_unix_ms:
            raise ValueError("unsigned execution package cannot precede its bundle intent")
        if self.created_at_unix_ms > self.bundle.inputs_valid_until_unix_ms:
            raise ValueError("bundle inputs are expired at package creation")
        if not transaction_simulations_agree(self.simulations):
            raise ValueError("transaction simulations do not provide independent exact agreement")
        reference = self.simulations[0]
        expected_anchor = self.transaction.sender_state.anchor_sha256
        for item in self.simulations:
            if item.observed_at_unix_ms < self.bundle.created_at_unix_ms:
                raise ValueError("transaction simulation cannot precede its bundle intent")
            if not item.is_valid_at(self.created_at_unix_ms):
                raise ValueError("transaction simulation is not valid at package creation")
        if reference.state_anchor_sha256 != expected_anchor:
            raise ValueError("transaction simulation does not bind the exact state anchor")
        if reference.transaction_sha256 != self.transaction.digest:
            raise ValueError("transaction simulation does not bind the exact unsigned transaction")
        if reference.transaction_signing_hash != self.transaction.signing_hash_hex:
            raise ValueError("transaction simulation signing hash mismatch")
        if reference.bundle_sha256 != self.bundle.digest:
            raise ValueError("transaction simulation does not bind the exact bundle intent")
        if not (
            self.bundle.target_block_number
            <= reference.simulated_block_number
            <= self.bundle.maximum_block_number
        ):
            raise ValueError("transaction simulation block is outside the bundle target range")
        anchor_head = EvmHead.from_observation(
            self.transaction.sender_state.evidence.anchor.head_observation
        )
        if reference.simulated_block_timestamp_unix_s <= anchor_head.block_timestamp_unix_s:
            raise ValueError(
                "transaction simulation block timestamp must follow the authenticated anchor block"
            )
        if reference.simulated_block_timestamp_unix_s > self.call.deadline_unix_s:
            raise ValueError("transaction simulation block timestamp exceeds the executor deadline")
        if reference.simulated_base_fee_per_gas > self.transaction.max_fee_per_gas:
            raise ValueError("transaction simulation base fee exceeds the transaction max fee")
        if reference.gas_used < self.transaction.intrinsic_gas:
            raise ValueError("transaction simulation gas is below the canonical intrinsic gas floor")
        if reference.gas_used > self.transaction.gas_limit:
            raise ValueError("transaction simulation gas exceeds unsigned transaction gas limit")
        operator_fee_upper_bound = evidence.cost_envelope.fee_envelope.operator_fee_upper_bound
        if reference.operator_fee_paid > operator_fee_upper_bound:
            raise ValueError("transaction simulation operator fee exceeds the recorded upper bound")
        expected_output = evidence.plan.opportunity.route_quote.amount_out
        if reference.output_amount != expected_output:
            raise ValueError("transaction simulation output disagrees with exact F4 route output")
        if reference.base_token != evidence.plan.base_asset.address:
            raise ValueError("transaction simulation output asset is not the exact F4 base token")
        if reference.flash_loan_principal_repaid != evidence.plan.funding.principal:
            raise ValueError("transaction simulation principal repayment disagrees with the F4 funding plan")
        if reference.flash_loan_fee_paid != evidence.plan.funding.fee:
            raise ValueError("transaction simulation flash-loan fee disagrees with the F4 funding plan")
        if (
            reference.base_token_residual_before_external_costs
            != evidence.plan.residual_before_external_costs
        ):
            raise ValueError("transaction simulation residual disagrees with the F4 execution plan")
        if reference.base_token_beneficiary != self.transaction.sender:
            raise ValueError("transaction simulation base-token beneficiary is not the authenticated sender")
        if (
            reference.base_token_beneficiary_delta
            != evidence.plan.residual_before_external_costs
        ):
            raise ValueError("transaction simulation beneficiary delta disagrees with the F4 residual")
        if reference.output_amount < self.call.minimum_final_output:
            raise ValueError("transaction simulation output violates the governed minimum")
        if reference.coinbase_payment > self.transaction.value:
            raise ValueError("transaction simulation coinbase payment exceeds the recorded direct payment")
        valid_until = min(
            self.bundle.inputs_valid_until_unix_ms,
            *(item.valid_until_unix_ms for item in self.simulations),
        )
        identity = {
            "schema": self.schema,
            "net_profit_evidence_sha256": evidence.digest,
            "call_sha256": self.call.digest,
            "transaction_sha256": self.transaction.digest,
            "bundle_sha256": self.bundle.digest,
            "simulation_sha256": [item.digest for item in ordered],
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "valid_until_unix_ms": str(valid_until),
        }
        object.__setattr__(self, "_valid_until_unix_ms", valid_until)
        object.__setattr__(self, "_package_id", "unsigned-package-" + canonical_sha256(identity))
        canonical_json_bytes(self.to_json_value())

    @property
    def package_id(self) -> str:
        return self._package_id

    @property
    def valid_until_unix_ms(self) -> int:
        return self._valid_until_unix_ms

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "package_id": self.package_id,
            "net_profit_evidence": self.net_profit_evidence.to_json_value(),
            "net_profit_evidence_sha256": self.net_profit_evidence.digest,
            "call": self.call.to_json_value(),
            "call_sha256": self.call.digest,
            "transaction": self.transaction.to_json_value(),
            "transaction_sha256": self.transaction.digest,
            "bundle": self.bundle.to_json_value(),
            "bundle_sha256": self.bundle.digest,
            "simulations": [item.to_json_value() for item in self.simulations],
            "simulation_sha256": [item.digest for item in self.simulations],
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "valid_until_unix_ms": str(self.valid_until_unix_ms),
            "package_authority": "offline-unsigned-transaction-bound-shadow-only",
            "private_delivery_intent": True,
            "signature_present": False,
            "relay_credentials_present": False,
            "signing_authority": "none",
            "submission_authority": "none",
            "signing_eligible": False,
            "submission_eligible": False,
            "execution_eligible": False,
            "inclusion_guarantee": False,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())
