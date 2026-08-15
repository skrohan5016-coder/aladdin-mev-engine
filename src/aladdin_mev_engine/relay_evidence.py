from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from .canonical import canonical_json_bytes, canonical_sha256, strict_json_loads
from .domain import Chain, require_bounded_text, require_sha256
from .evm_transaction import MAX_BUNDLE_TRANSACTIONS, PrivateDeliveryClass
from .execution_package import UnsignedExecutionPackageEvidence
from .signed_transaction import (
    SignedEip1559TransactionEvidence,
    SignedPrivateBundleEvidence,
)

RELAY_ENDPOINT_SCHEMA = "aladdin-mev-relay-endpoint-spec/v1"
RELAY_REGISTRY_SCHEMA = "aladdin-mev-relay-endpoint-registry/v1"
RELAY_REQUEST_SCHEMA = "aladdin-mev-relay-submission-request/v1"
RELAY_RESPONSE_SCHEMA = "aladdin-mev-relay-response-evidence/v1"
SIGNED_PACKAGE_SCHEMA = "aladdin-mev-externally-signed-execution-package/v1"
MAX_UINT64 = (1 << 64) - 1
MAX_RELAY_ENDPOINTS = 64
MAX_RELAY_RESPONSES = 8


class RelayProtocol(StrEnum):
    NORMALIZED_PRIVATE_BUNDLE_V1 = "normalized-private-bundle-v1"


class RelayResponseStatus(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    ERROR = "error"


def _uint64(name: str, value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_UINT64:
        raise ValueError(f"{name} must be an unsigned 64-bit exact integer")
    return value


@dataclass(frozen=True, slots=True)
class RelayEndpointSpec:
    endpoint_id: str
    chain: Chain
    delivery_class: PrivateDeliveryClass
    maximum_transactions: int
    supports_replacement: bool
    requires_authentication: bool
    protocol: RelayProtocol = RelayProtocol.NORMALIZED_PRIVATE_BUNDLE_V1
    schema: str = RELAY_ENDPOINT_SCHEMA
    _digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.schema != RELAY_ENDPOINT_SCHEMA:
            raise ValueError("unsupported relay-endpoint schema")
        require_bounded_text("endpoint_id", self.endpoint_id, maximum=128)
        if type(self.chain) is not Chain or self.chain not in {Chain.ETHEREUM, Chain.BASE}:
            raise ValueError("F6 relay endpoints support Ethereum and Base only")
        if type(self.delivery_class) is not PrivateDeliveryClass:
            raise TypeError("delivery_class must be exact PrivateDeliveryClass")
        expected = (
            PrivateDeliveryClass.BUILDER
            if self.chain is Chain.ETHEREUM
            else PrivateDeliveryClass.SEQUENCER
        )
        if self.delivery_class is not expected:
            raise ValueError("relay delivery class does not match its chain")
        if type(self.maximum_transactions) is not int or not 1 <= self.maximum_transactions <= MAX_BUNDLE_TRANSACTIONS:
            raise ValueError("maximum_transactions is outside the governed range")
        if type(self.supports_replacement) is not bool:
            raise TypeError("supports_replacement must be an exact bool")
        if type(self.requires_authentication) is not bool:
            raise TypeError("requires_authentication must be an exact bool")
        if type(self.protocol) is not RelayProtocol:
            raise TypeError("protocol must be exact RelayProtocol")
        payload = self.to_json_value()
        canonical_json_bytes(payload)
        object.__setattr__(self, "_digest", canonical_sha256(payload))

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "endpoint_id": self.endpoint_id,
            "chain": self.chain.value,
            "delivery_class": self.delivery_class.value,
            "protocol": self.protocol.value,
            "maximum_transactions": str(self.maximum_transactions),
            "supports_replacement": self.supports_replacement,
            "requires_authentication": self.requires_authentication,
            "endpoint_url_present": False,
            "credential_present": False,
            "production_approval": False,
        }

    @property
    def digest(self) -> str:
        return self._digest


@dataclass(frozen=True, slots=True)
class RelayEndpointRegistry:
    registry_id: str
    endpoints: tuple[RelayEndpointSpec, ...]
    schema: str = RELAY_REGISTRY_SCHEMA
    _endpoint_sha256: tuple[str, ...] = field(init=False, repr=False)
    _digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.schema != RELAY_REGISTRY_SCHEMA:
            raise ValueError("unsupported relay-endpoint-registry schema")
        require_bounded_text("registry_id", self.registry_id, maximum=128)
        if type(self.endpoints) is not tuple or not self.endpoints:
            raise TypeError("endpoints must be a non-empty exact tuple")
        if len(self.endpoints) > MAX_RELAY_ENDPOINTS:
            raise ValueError("relay endpoint registry exceeds the governed ceiling")
        if any(type(item) is not RelayEndpointSpec for item in self.endpoints):
            raise TypeError("relay registry contains an ungoverned endpoint")
        ordered = tuple(sorted(self.endpoints, key=lambda item: (item.endpoint_id, item.digest)))
        object.__setattr__(self, "endpoints", ordered)
        ids = [item.endpoint_id for item in ordered]
        if len(ids) != len(set(ids)):
            raise ValueError("relay endpoint id cannot authorize conflicting specifications")
        object.__setattr__(self, "_endpoint_sha256", tuple(item.digest for item in ordered))
        payload = self.to_json_value()
        canonical_json_bytes(payload)
        object.__setattr__(self, "_digest", canonical_sha256(payload))

    def resolve(self, endpoint_id: str) -> RelayEndpointSpec:
        require_bounded_text("endpoint_id", endpoint_id, maximum=128)
        for item in self.endpoints:
            if item.endpoint_id == endpoint_id:
                return item
        raise ValueError("relay endpoint id is absent from the registry")

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "registry_id": self.registry_id,
            "endpoints": [item.to_json_value() for item in self.endpoints],
            "endpoint_sha256": list(self._endpoint_sha256),
            "registry_authority": "explicit-offline-evidence-only-not-production-approval",
        }

    @property
    def digest(self) -> str:
        return self._digest


@dataclass(frozen=True, slots=True)
class RelaySubmissionRequestEvidence:
    registry: RelayEndpointRegistry
    endpoint_id: str
    signed_bundle: SignedPrivateBundleEvidence
    request_id: str
    created_at_unix_ms: int
    schema: str = RELAY_REQUEST_SCHEMA
    _endpoint: RelayEndpointSpec = field(init=False, repr=False)
    _request_payload_bytes: bytes = field(init=False, repr=False)
    _request_payload_sha256: str = field(init=False, repr=False)
    _request_id_digest: str = field(init=False, repr=False)
    _registry_sha256: str = field(init=False, repr=False)
    _endpoint_sha256: str = field(init=False, repr=False)
    _signed_bundle_sha256: str = field(init=False, repr=False)
    _digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.schema != RELAY_REQUEST_SCHEMA:
            raise ValueError("unsupported relay-submission-request schema")
        if type(self.registry) is not RelayEndpointRegistry:
            raise TypeError("registry must be exact RelayEndpointRegistry")
        if type(self.signed_bundle) is not SignedPrivateBundleEvidence:
            raise TypeError("signed_bundle must be exact SignedPrivateBundleEvidence")
        require_bounded_text("request_id", self.request_id, maximum=128)
        _uint64("created_at_unix_ms", self.created_at_unix_ms)
        endpoint = self.registry.resolve(self.endpoint_id)
        bundle = self.signed_bundle
        if endpoint.chain is not bundle.unsigned_bundle.chain:
            raise ValueError("relay endpoint chain does not match the signed bundle")
        if endpoint.delivery_class is not bundle.unsigned_bundle.delivery_class:
            raise ValueError("relay endpoint delivery class does not match the signed bundle")
        if len(bundle.signed_transactions) > endpoint.maximum_transactions:
            raise ValueError("signed bundle exceeds the relay endpoint transaction ceiling")
        if self.created_at_unix_ms < bundle.created_at_unix_ms:
            raise ValueError("relay request cannot predate the signed bundle")
        if self.created_at_unix_ms > bundle.inputs_valid_until_unix_ms:
            raise ValueError("signed bundle inputs expired before relay-request construction")
        payload: dict[str, object] = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": "aladdin_submitPrivateBundle",
            "params": [
                {
                    "protocol": endpoint.protocol.value,
                    "transactions": ["0x" + item.hex() for item in bundle.raw_transactions],
                    "target_block_number": hex(bundle.unsigned_bundle.target_block_number),
                    "maximum_block_number": hex(bundle.unsigned_bundle.maximum_block_number),
                    "replacement_id": None,
                }
            ],
        }
        payload_bytes = canonical_json_bytes(payload)
        payload_sha256 = canonical_sha256(payload)
        registry_sha256 = self.registry.digest
        endpoint_sha256 = endpoint.digest
        signed_bundle_sha256 = bundle.digest
        request_digest = canonical_sha256(
            {
                "schema": self.schema,
                "registry_sha256": registry_sha256,
                "endpoint_sha256": endpoint_sha256,
                "signed_bundle_sha256": signed_bundle_sha256,
                "request_payload_sha256": payload_sha256,
                "created_at_unix_ms": str(self.created_at_unix_ms),
            }
        )
        object.__setattr__(self, "_endpoint", endpoint)
        object.__setattr__(self, "_registry_sha256", registry_sha256)
        object.__setattr__(self, "_endpoint_sha256", endpoint_sha256)
        object.__setattr__(self, "_signed_bundle_sha256", signed_bundle_sha256)
        object.__setattr__(self, "_request_payload_bytes", payload_bytes)
        object.__setattr__(self, "_request_payload_sha256", payload_sha256)
        object.__setattr__(self, "_request_id_digest", "relay-request-" + request_digest)
        value = self.to_json_value()
        canonical_json_bytes(value)
        object.__setattr__(self, "_digest", canonical_sha256(value))

    @property
    def endpoint(self) -> RelayEndpointSpec:
        return self._endpoint

    @property
    def request_payload(self) -> dict[str, object]:
        value = strict_json_loads(self._request_payload_bytes)
        if type(value) is not dict:
            raise RuntimeError("governed relay request payload lost its object shape")
        return value

    @property
    def relay_request_id(self) -> str:
        return self._request_id_digest

    @property
    def inputs_valid_until_unix_ms(self) -> int:
        return self.signed_bundle.inputs_valid_until_unix_ms

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "relay_request_id": self.relay_request_id,
            "registry_sha256": self._registry_sha256,
            "endpoint": self.endpoint.to_json_value(),
            "endpoint_sha256": self._endpoint_sha256,
            "signed_bundle_sha256": self._signed_bundle_sha256,
            "request_payload": self.request_payload,
            "request_payload_sha256": self._request_payload_sha256,
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "inputs_valid_until_unix_ms": str(self.inputs_valid_until_unix_ms),
            "credential_present": False,
            "local_network_dispatched": False,
            "submission_authority": "none",
            "submission_eligible": False,
            "inclusion_guarantee": False,
        }

    @property
    def digest(self) -> str:
        return self._digest


@dataclass(frozen=True, slots=True)
class RelayResponseEvidence:
    request: RelaySubmissionRequestEvidence
    status: RelayResponseStatus
    observed_at_unix_ms: int
    response_source_id: str
    response_source_sha256: str
    relay_reference: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    schema: str = RELAY_RESPONSE_SCHEMA
    _request_sha256: str = field(init=False, repr=False)
    _digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.schema != RELAY_RESPONSE_SCHEMA:
            raise ValueError("unsupported relay-response-evidence schema")
        if type(self.request) is not RelaySubmissionRequestEvidence:
            raise TypeError("request must be exact RelaySubmissionRequestEvidence")
        if type(self.status) is not RelayResponseStatus:
            raise TypeError("status must be exact RelayResponseStatus")
        _uint64("observed_at_unix_ms", self.observed_at_unix_ms)
        require_bounded_text("response_source_id", self.response_source_id, maximum=128)
        require_sha256("response_source_sha256", self.response_source_sha256)
        if self.observed_at_unix_ms < self.request.created_at_unix_ms:
            raise ValueError("relay response cannot predate its request")
        if self.observed_at_unix_ms > self.request.inputs_valid_until_unix_ms:
            raise ValueError("relay response arrived after the request validity horizon")
        if self.status is RelayResponseStatus.ACCEPTED:
            if self.relay_reference is None:
                raise ValueError("accepted relay response requires a relay reference")
            require_bounded_text("relay_reference", self.relay_reference, maximum=256)
            if self.error_code is not None or self.error_message is not None:
                raise ValueError("accepted relay response cannot carry an error")
        else:
            if self.relay_reference is not None:
                raise ValueError("non-accepted relay response cannot carry a relay reference")
            if self.error_code is None or self.error_message is None:
                raise ValueError("rejected or error relay response requires exact error fields")
            require_bounded_text("error_code", self.error_code, maximum=128)
            require_bounded_text("error_message", self.error_message, maximum=512)
        object.__setattr__(self, "_request_sha256", self.request.digest)
        value = self.to_json_value()
        canonical_json_bytes(value)
        object.__setattr__(self, "_digest", canonical_sha256(value))

    @property
    def relay_acceptance_observed(self) -> bool:
        return self.status is RelayResponseStatus.ACCEPTED

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "request_sha256": self._request_sha256,
            "endpoint_id": self.request.endpoint.endpoint_id,
            "status": self.status.value,
            "observed_at_unix_ms": str(self.observed_at_unix_ms),
            "response_source_id": self.response_source_id,
            "response_source_sha256": self.response_source_sha256,
            "relay_reference": self.relay_reference,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "relay_acceptance_observed": self.relay_acceptance_observed,
            "inclusion_observed": False,
            "inclusion_guarantee": False,
            "response_authority": "recorded-input-only",
        }

    @property
    def digest(self) -> str:
        return self._digest


@dataclass(frozen=True, slots=True)
class ExternallySignedExecutionPackageEvidence:
    unsigned_package: UnsignedExecutionPackageEvidence
    signed_transaction: SignedEip1559TransactionEvidence
    signed_bundle: SignedPrivateBundleEvidence
    relay_request: RelaySubmissionRequestEvidence
    relay_responses: tuple[RelayResponseEvidence, ...]
    created_at_unix_ms: int
    schema: str = SIGNED_PACKAGE_SCHEMA
    _package_id: str = field(init=False, repr=False)
    _valid_until_unix_ms: int = field(init=False, repr=False)
    _unsigned_package_sha256: str = field(init=False, repr=False)
    _signed_transaction_sha256: str = field(init=False, repr=False)
    _signed_bundle_sha256: str = field(init=False, repr=False)
    _relay_request_sha256: str = field(init=False, repr=False)
    _relay_response_sha256: tuple[str, ...] = field(init=False, repr=False)
    _digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.schema != SIGNED_PACKAGE_SCHEMA:
            raise ValueError("unsupported externally-signed-execution-package schema")
        if type(self.unsigned_package) is not UnsignedExecutionPackageEvidence:
            raise TypeError("unsigned_package must be exact UnsignedExecutionPackageEvidence")
        if type(self.signed_transaction) is not SignedEip1559TransactionEvidence:
            raise TypeError("signed_transaction must be exact SignedEip1559TransactionEvidence")
        if type(self.signed_bundle) is not SignedPrivateBundleEvidence:
            raise TypeError("signed_bundle must be exact SignedPrivateBundleEvidence")
        if type(self.relay_request) is not RelaySubmissionRequestEvidence:
            raise TypeError("relay_request must be exact RelaySubmissionRequestEvidence")
        if type(self.relay_responses) is not tuple or len(self.relay_responses) > MAX_RELAY_RESPONSES:
            raise ValueError("relay_responses must be an exact bounded tuple")
        if any(type(item) is not RelayResponseEvidence for item in self.relay_responses):
            raise TypeError("relay responses contain an ungoverned record")
        ordered = tuple(sorted(self.relay_responses, key=lambda item: (item.response_source_id, item.digest)))
        object.__setattr__(self, "relay_responses", ordered)
        _uint64("created_at_unix_ms", self.created_at_unix_ms)
        unsigned_package_sha256 = self.unsigned_package.digest
        signed_transaction_sha256 = self.signed_transaction.digest
        signed_bundle_sha256 = self.signed_bundle.digest
        relay_request_sha256 = self.relay_request.digest
        if self.signed_transaction.unsigned_transaction.digest != self.unsigned_package.transaction.digest:
            raise ValueError("signed transaction does not bind the exact unsigned package transaction")
        if self.signed_bundle.unsigned_bundle.digest != self.unsigned_package.bundle.digest:
            raise ValueError("signed bundle does not bind the exact unsigned package bundle")
        if len(self.signed_bundle.signed_transactions) != 1 or self.signed_bundle.signed_transactions[0].digest != signed_transaction_sha256:
            raise ValueError("F6 package requires exactly the bound signed transaction")
        if self.relay_request.signed_bundle.digest != signed_bundle_sha256:
            raise ValueError("relay request does not bind the exact signed bundle")
        if self.created_at_unix_ms < self.relay_request.created_at_unix_ms:
            raise ValueError("externally signed package cannot predate the relay request")
        valid_until = min(
            self.unsigned_package.valid_until_unix_ms,
            self.signed_transaction.inputs_valid_until_unix_ms,
            self.signed_bundle.inputs_valid_until_unix_ms,
            self.relay_request.inputs_valid_until_unix_ms,
        )
        if self.created_at_unix_ms > valid_until:
            raise ValueError("externally signed package inputs are expired")
        seen_source_ids: set[str] = set()
        seen_source_digests: set[str] = set()
        for response in ordered:
            if response.request.digest != relay_request_sha256:
                raise ValueError("relay response does not bind the exact request")
            if response.observed_at_unix_ms > self.created_at_unix_ms:
                raise ValueError("externally signed package cannot predate a relay response")
            if response.response_source_id in seen_source_ids:
                raise ValueError("duplicate relay-response source id")
            if response.response_source_sha256 in seen_source_digests:
                raise ValueError("duplicate relay-response source digest")
            seen_source_ids.add(response.response_source_id)
            seen_source_digests.add(response.response_source_sha256)
        relay_response_sha256 = tuple(item.digest for item in ordered)
        identity = {
            "schema": self.schema,
            "unsigned_package_sha256": unsigned_package_sha256,
            "signed_transaction_sha256": signed_transaction_sha256,
            "signed_bundle_sha256": signed_bundle_sha256,
            "relay_request_sha256": relay_request_sha256,
            "relay_response_sha256": list(relay_response_sha256),
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "valid_until_unix_ms": str(valid_until),
        }
        object.__setattr__(self, "_valid_until_unix_ms", valid_until)
        object.__setattr__(self, "_unsigned_package_sha256", unsigned_package_sha256)
        object.__setattr__(self, "_signed_transaction_sha256", signed_transaction_sha256)
        object.__setattr__(self, "_signed_bundle_sha256", signed_bundle_sha256)
        object.__setattr__(self, "_relay_request_sha256", relay_request_sha256)
        object.__setattr__(self, "_relay_response_sha256", relay_response_sha256)
        object.__setattr__(self, "_package_id", "externally-signed-package-" + canonical_sha256(identity))
        value = self.to_json_value()
        canonical_json_bytes(value)
        object.__setattr__(self, "_digest", canonical_sha256(value))

    @property
    def package_id(self) -> str:
        return self._package_id

    @property
    def valid_until_unix_ms(self) -> int:
        return self._valid_until_unix_ms

    @property
    def relay_acceptance_observed(self) -> bool:
        return any(item.relay_acceptance_observed for item in self.relay_responses)

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "package_id": self.package_id,
            "unsigned_package_sha256": self._unsigned_package_sha256,
            "signed_transaction_sha256": self._signed_transaction_sha256,
            "signed_bundle_sha256": self._signed_bundle_sha256,
            "relay_request_sha256": self._relay_request_sha256,
            "relay_response_sha256": list(self._relay_response_sha256),
            "transaction_hash": self.signed_transaction.transaction_hash_hex,
            "endpoint_id": self.relay_request.endpoint.endpoint_id,
            "created_at_unix_ms": str(self.created_at_unix_ms),
            "valid_until_unix_ms": str(self.valid_until_unix_ms),
            "package_authority": "offline-external-signature-and-recorded-relay-evidence-only",
            "signature_present": True,
            "private_key_present": False,
            "relay_request_present": True,
            "relay_acceptance_observed": self.relay_acceptance_observed,
            "local_network_dispatched": False,
            "signing_authority": "external-unmodeled",
            "submission_authority": "none",
            "inclusion_observed": False,
            "signing_eligible": False,
            "submission_eligible": False,
            "execution_eligible": False,
            "inclusion_guarantee": False,
        }

    @property
    def digest(self) -> str:
        return self._digest
