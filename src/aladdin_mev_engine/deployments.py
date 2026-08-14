from __future__ import annotations

from dataclasses import dataclass

from .canonical import canonical_json_bytes, canonical_sha256
from .constant_product import MAX_UINT256
from .domain import Chain, require_bounded_text, require_sha256
from .evm_hex import to_hex_data
from .execution_plan import FundingKind
from .keccak import keccak256
from .mpt import EMPTY_TRIE_ROOT
from .state_proof import EMPTY_CODE_HASH, EvmStateProofEvidence

INTERFACE_SCHEMA = "aladdin-mev-executor-interface/v1"
DEPLOYMENT_SPEC_SCHEMA = "aladdin-mev-executor-deployment-spec/v1"
AUTHENTICATED_DEPLOYMENT_SCHEMA = "aladdin-mev-authenticated-executor-deployment/v1"
DEPLOYMENT_REGISTRY_SCHEMA = "aladdin-mev-executor-deployment-registry/v1"

EXECUTE_SIGNATURE = "execute(bytes32,address,uint256,uint256,uint64,bytes)"
ROUTE_COMMAND_SCHEMA = "aladdin-mev-route-command-binary/v1"
MAX_REGISTRY_DEPLOYMENTS = 32
MAX_CALLDATA_BYTES = 65_536
ROUTE_COMMAND_BINARY_BYTES = 189
FLASH_FUNDING_SEMANTICS = "runtime-bound-recorded-flash-loan-provider-only"
VALUE_SEMANTICS = "msg-value-conditional-coinbase-payment-upper-bound"
BENEFICIARY_SEMANTICS = "msg-sender-receives-complete-base-token-residual"
STORAGE_SEMANTICS = "empty-storage-root-stateless-runtime"
MAX_UINT64 = (1 << 64) - 1


def _uint64(name: str, value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT64:
        raise ValueError(f"{name} must be an unsigned 64-bit exact integer")
    return value


def _uint256(name: str, value: object, *, positive: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT256:
        raise ValueError(f"{name} must be an unsigned 256-bit exact integer")
    if positive and value == 0:
        raise ValueError(f"{name} must be positive")
    return value


def _address(name: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 20 or value == bytes(20):
        raise ValueError(f"{name} must be a non-zero exact 20-byte address")
    return value


def _hash(name: str, value: object, *, allow_empty_code: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != 32 or value == bytes(32):
        raise ValueError(f"{name} must be a non-zero exact 32-byte hash")
    if not allow_empty_code and value == EMPTY_CODE_HASH:
        raise ValueError(f"{name} cannot identify empty runtime code")
    return value


@dataclass(frozen=True, slots=True)
class ExecutorInterfaceSpec:
    interface_id: str
    interface_source_sha256: str
    flash_loan_provider_id: str
    flash_loan_source_sha256: str
    maximum_calldata_bytes: int = MAX_CALLDATA_BYTES
    function_signature: str = EXECUTE_SIGNATURE
    route_command_schema: str = ROUTE_COMMAND_SCHEMA
    schema: str = INTERFACE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != INTERFACE_SCHEMA:
            raise ValueError("unsupported executor-interface schema")
        require_bounded_text("interface_id", self.interface_id, maximum=128)
        require_sha256("interface_source_sha256", self.interface_source_sha256)
        require_bounded_text("flash_loan_provider_id", self.flash_loan_provider_id, maximum=128)
        if self.flash_loan_provider_id == "self":
            raise ValueError("F5 executor interface requires an external flash-loan provider identity")
        require_sha256("flash_loan_source_sha256", self.flash_loan_source_sha256)
        if self.function_signature != EXECUTE_SIGNATURE:
            raise ValueError("executor interface must use the exact governed execute signature")
        if self.route_command_schema != ROUTE_COMMAND_SCHEMA:
            raise ValueError("executor interface must use the exact governed route-command schema")
        _uint256("maximum_calldata_bytes", self.maximum_calldata_bytes, positive=True)
        if self.maximum_calldata_bytes > MAX_CALLDATA_BYTES:
            raise ValueError("maximum_calldata_bytes exceeds the governed ceiling")
        canonical_json_bytes(self.to_json_value())

    @property
    def function_selector(self) -> bytes:
        return keccak256(self.function_signature.encode("ascii"))[:4]

    @property
    def route_command_schema_sha256(self) -> str:
        return canonical_sha256(
            {
                "schema": self.route_command_schema,
                "version_byte": "1",
                "header": "AMEVF5R1",
                "payload_prefix_fields": [
                    "header:raw-8-byte",
                    "version:uint8",
                    "command_count:uint8",
                ],
                "command_length_bytes": str(ROUTE_COMMAND_BINARY_BYTES),
                "byte_order": "big-endian",
                "address_encoding": "raw-20-byte",
                "uint256_encoding": "unsigned-big-endian-exact-32-byte",
                "quote_encoding": "raw-32-byte-sha256",
                "fields": [
                    "index:uint8",
                    "pool:address",
                    "token_in:address",
                    "token_out:address",
                    "amount_in:uint256",
                    "expected_amount_out:uint256",
                    "minimum_amount_out:uint256",
                    "quote_sha256:bytes32",
                ],
            }
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "interface_id": self.interface_id,
            "function_signature": self.function_signature,
            "function_selector": to_hex_data(self.function_selector),
            "route_command_schema": self.route_command_schema,
            "route_command_schema_sha256": self.route_command_schema_sha256,
            "maximum_calldata_bytes": str(self.maximum_calldata_bytes),
            "interface_source_sha256": self.interface_source_sha256,
            "funding_kind": FundingKind.FLASH_LOAN.value,
            "flash_loan_provider_id": self.flash_loan_provider_id,
            "flash_loan_source_sha256": self.flash_loan_source_sha256,
            "funding_semantics": FLASH_FUNDING_SEMANTICS,
            "value_semantics": VALUE_SEMANTICS,
            "beneficiary_semantics": BENEFICIARY_SEMANTICS,
            "storage_semantics": STORAGE_SEMANTICS,
            "proxy_semantics": "direct-runtime-only",
            "authority": "recorded-interface-identity-only",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class ExecutorDeploymentSpec:
    deployment_id: str
    chain: Chain
    address: bytes
    runtime_code_hash: bytes
    interface: ExecutorInterfaceSpec
    valid_from_block: int
    valid_until_block: int
    deployment_source_sha256: str
    schema: str = DEPLOYMENT_SPEC_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != DEPLOYMENT_SPEC_SCHEMA:
            raise ValueError("unsupported executor-deployment-spec schema")
        require_bounded_text("deployment_id", self.deployment_id, maximum=128)
        if type(self.chain) is not Chain or self.chain not in {Chain.ETHEREUM, Chain.BASE}:
            raise ValueError("F5 executor deployments support Ethereum and Base only")
        _address("address", self.address)
        _hash("runtime_code_hash", self.runtime_code_hash)
        if type(self.interface) is not ExecutorInterfaceSpec:
            raise TypeError("interface must be an exact ExecutorInterfaceSpec")
        _uint64("valid_from_block", self.valid_from_block)
        _uint64("valid_until_block", self.valid_until_block)
        if self.valid_until_block < self.valid_from_block:
            raise ValueError("deployment validity cannot end before it begins")
        require_sha256("deployment_source_sha256", self.deployment_source_sha256)
        canonical_json_bytes(self.to_json_value())

    def is_valid_at_block(self, block_number: int) -> bool:
        _uint64("block_number", block_number)
        return self.valid_from_block <= block_number <= self.valid_until_block

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "deployment_id": self.deployment_id,
            "chain": self.chain.value,
            "address": to_hex_data(self.address),
            "runtime_code_hash": to_hex_data(self.runtime_code_hash),
            "interface": self.interface.to_json_value(),
            "interface_sha256": self.interface.digest,
            "valid_from_block": str(self.valid_from_block),
            "valid_until_block": str(self.valid_until_block),
            "deployment_source_sha256": self.deployment_source_sha256,
            "deployment_semantics": "authenticated-recorded-direct-runtime",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class AuthenticatedExecutorDeployment:
    spec: ExecutorDeploymentSpec
    evidence: EvmStateProofEvidence
    registry: ExecutorDeploymentRegistry
    schema: str = AUTHENTICATED_DEPLOYMENT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != AUTHENTICATED_DEPLOYMENT_SCHEMA:
            raise ValueError("unsupported authenticated-executor-deployment schema")
        if type(self.spec) is not ExecutorDeploymentSpec:
            raise TypeError("spec must be an exact ExecutorDeploymentSpec")
        if type(self.evidence) is not EvmStateProofEvidence:
            raise TypeError("evidence must be exact EvmStateProofEvidence")
        if type(self.registry) is not ExecutorDeploymentRegistry:
            raise TypeError("registry must be an exact ExecutorDeploymentRegistry")
        if not self.evidence.account_exists:
            raise ValueError("executor deployment account must exist")
        if self.evidence.chain is not self.spec.chain:
            raise ValueError("executor deployment evidence chain mismatch")
        if self.evidence.address != self.spec.address:
            raise ValueError("executor deployment evidence address mismatch")
        if self.evidence.code_hash != self.spec.runtime_code_hash:
            raise ValueError("executor runtime code hash mismatch")
        if not self.spec.is_valid_at_block(self.evidence.block_number):
            raise ValueError("executor deployment is not valid at the authenticated block")
        if self.evidence.storage_root != EMPTY_TRIE_ROOT:
            raise ValueError("F5 executor runtime requires the canonical empty storage root")
        if self.evidence.storage_values:
            raise ValueError("F5 direct-runtime deployment evidence must not carry unused storage proofs")
        registered = self.registry.resolve(
            self.spec.chain, self.spec.address, self.evidence.block_number
        )
        if registered.digest != self.spec.digest:
            raise ValueError("executor deployment spec is not the exact registry authority")
        canonical_json_bytes(self.to_json_value())

    @property
    def chain(self) -> Chain:
        return self.spec.chain

    @property
    def address(self) -> bytes:
        return self.spec.address

    @property
    def anchor_sha256(self) -> str:
        return self.evidence.anchor.digest

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "registry": self.registry.to_json_value(),
            "registry_sha256": self.registry.digest,
            "spec": self.spec.to_json_value(),
            "spec_sha256": self.spec.digest,
            "evidence": self.evidence.to_json_value(),
            "evidence_sha256": self.evidence.digest,
            "authenticated_block_number": str(self.evidence.block_number),
            "authenticated_anchor_sha256": self.anchor_sha256,
            "production_approval": False,
            "deployment_authority": "authenticated-recorded-shadow-only",
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class ExecutorDeploymentRegistry:
    registry_id: str
    deployments: tuple[ExecutorDeploymentSpec, ...]
    schema: str = DEPLOYMENT_REGISTRY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != DEPLOYMENT_REGISTRY_SCHEMA:
            raise ValueError("unsupported executor-deployment-registry schema")
        require_bounded_text("registry_id", self.registry_id, maximum=128)
        if type(self.deployments) is not tuple or not self.deployments:
            raise TypeError("deployments must be a non-empty exact tuple")
        if len(self.deployments) > MAX_REGISTRY_DEPLOYMENTS:
            raise ValueError("executor deployment registry exceeds the governed ceiling")
        if any(type(item) is not ExecutorDeploymentSpec for item in self.deployments):
            raise TypeError("executor deployment registry contains an ungoverned spec")
        ordered = tuple(
            sorted(
                self.deployments,
                key=lambda item: (item.chain.value, item.address, item.valid_from_block, item.digest),
            )
        )
        object.__setattr__(self, "deployments", ordered)
        ids = [item.deployment_id for item in ordered]
        if len(ids) != len(set(ids)):
            raise ValueError("executor deployment registry contains duplicate deployment_id")
        identities = [(item.chain, item.address, item.valid_from_block, item.valid_until_block) for item in ordered]
        if len(identities) != len(set(identities)):
            raise ValueError("executor deployment registry contains duplicate deployment identity")
        by_code_hash: dict[bytes, str] = {}
        for item in ordered:
            interface_digest = item.interface.digest
            previous = by_code_hash.get(item.runtime_code_hash)
            if previous is not None and previous != interface_digest:
                raise ValueError("one executor runtime code hash cannot authorize conflicting interfaces")
            by_code_hash[item.runtime_code_hash] = interface_digest
        for index, left in enumerate(ordered):
            for right in ordered[index + 1 :]:
                if left.chain is not right.chain or left.address != right.address:
                    continue
                if max(left.valid_from_block, right.valid_from_block) <= min(
                    left.valid_until_block, right.valid_until_block
                ):
                    raise ValueError("executor deployment registry has overlapping authority for one address")
        canonical_json_bytes(self.to_json_value())

    def resolve(self, chain: Chain, address: bytes, block_number: int) -> ExecutorDeploymentSpec:
        if type(chain) is not Chain:
            raise TypeError("chain must be an exact Chain")
        _address("address", address)
        _uint64("block_number", block_number)
        matches = [
            item
            for item in self.deployments
            if item.chain is chain and item.address == address and item.is_valid_at_block(block_number)
        ]
        if len(matches) != 1:
            raise ValueError("executor deployment registry does not resolve exactly one spec")
        return matches[0]

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "registry_id": self.registry_id,
            "deployments": [item.to_json_value() for item in self.deployments],
            "deployment_sha256": [item.digest for item in self.deployments],
            "production_approval": False,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())
