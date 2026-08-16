from __future__ import annotations

from functools import lru_cache

from aladdin_mev_engine.evm_transaction import PrivateDeliveryClass
from aladdin_mev_engine.relay_evidence import (
    ExternallySignedExecutionPackageEvidence,
    RelayEndpointRegistry,
    RelayEndpointSpec,
    RelayResponseEvidence,
    RelayResponseStatus,
    RelaySubmissionRequestEvidence,
)
from aladdin_mev_engine.secp256k1 import (
    GENERATOR,
    GROUP_ORDER,
    HALF_GROUP_ORDER,
    public_key_to_address,
    scalar_multiply,
)
from aladdin_mev_engine.signed_transaction import (
    Eip1559Signature,
    SignedEip1559TransactionEvidence,
    SignedPrivateBundleEvidence,
)

from f5_helpers import f5_bundle, f5_package, f5_transaction

PRIVATE_KEY = 2
SIGNATURE_SOURCE = "b0" * 32
RELAY_RESPONSE_SOURCE = "b1" * 32
RELAY_RESPONSE_SOURCE_2 = "b2" * 32
EXPECTED_SENDER = bytes.fromhex("2b5ad5c4795c026514f8317c7a215e218dccd6cf")


def expected_sender_from_private_key(private_key: int = PRIVATE_KEY) -> bytes:
    point = scalar_multiply(private_key, GENERATOR)
    if point is None:
        raise RuntimeError("test private key mapped to infinity")
    return public_key_to_address(point)


def deterministic_signature(
    message_hash: bytes,
    *,
    private_key: int = PRIVATE_KEY,
    nonce: int = 0xA11ADD1,
    source_id: str = "external-test-signer",
    source_sha256: str = SIGNATURE_SOURCE,
    observed_at_unix_ms: int | None = None,
) -> Eip1559Signature:
    """Create deterministic external-signature fixture evidence for tests only."""

    if type(message_hash) is not bytes or len(message_hash) != 32:
        raise ValueError("message_hash must be exact 32-byte data")
    if type(private_key) is not int or not 1 <= private_key < GROUP_ORDER:
        raise ValueError("test private_key is outside the secp256k1 scalar domain")
    if type(nonce) is not int or not 1 <= nonce < GROUP_ORDER:
        raise ValueError("test nonce is outside the secp256k1 scalar domain")
    point = scalar_multiply(nonce, GENERATOR)
    if point is None:
        raise RuntimeError("test nonce mapped to infinity")
    r = point.x % GROUP_ORDER
    if r == 0:
        raise RuntimeError("test nonce produced zero r")
    z = int.from_bytes(message_hash, "big") % GROUP_ORDER
    s = (pow(nonce, -1, GROUP_ORDER) * (z + r * private_key)) % GROUP_ORDER
    if s == 0:
        raise RuntimeError("test nonce produced zero s")
    y_parity = point.y & 1
    if s > HALF_GROUP_ORDER:
        s = GROUP_ORDER - s
        y_parity ^= 1
    if observed_at_unix_ms is None:
        observed_at_unix_ms = f5_transaction().created_at_unix_ms + 1
    return Eip1559Signature(
        y_parity=y_parity,
        r=r,
        s=s,
        observed_at_unix_ms=observed_at_unix_ms,
        source_id=source_id,
        source_sha256=source_sha256,
    )


@lru_cache(maxsize=1)
def f6_signed_transaction() -> SignedEip1559TransactionEvidence:
    unsigned = f5_transaction()
    signature = deterministic_signature(
        unsigned.signing_hash,
        observed_at_unix_ms=unsigned.created_at_unix_ms + 1,
    )
    return SignedEip1559TransactionEvidence(
        unsigned_transaction=unsigned,
        signature=signature,
        created_at_unix_ms=signature.observed_at_unix_ms + 1,
    )


@lru_cache(maxsize=1)
def f6_signed_bundle() -> SignedPrivateBundleEvidence:
    signed = f6_signed_transaction()
    return SignedPrivateBundleEvidence(
        unsigned_bundle=f5_bundle(),
        signed_transactions=(signed,),
        created_at_unix_ms=signed.created_at_unix_ms + 1,
    )


@lru_cache(maxsize=1)
def f6_relay_registry() -> RelayEndpointRegistry:
    bundle = f5_bundle()
    return RelayEndpointRegistry(
        registry_id="f6-offline-test-relays",
        endpoints=(
            RelayEndpointSpec(
                endpoint_id="ethereum-builder-evidence-v1",
                chain=bundle.chain,
                delivery_class=PrivateDeliveryClass.BUILDER,
                maximum_transactions=1,
                supports_replacement=False,
                requires_authentication=True,
            ),
        ),
    )


@lru_cache(maxsize=1)
def f6_relay_request() -> RelaySubmissionRequestEvidence:
    bundle = f6_signed_bundle()
    return RelaySubmissionRequestEvidence(
        registry=f6_relay_registry(),
        endpoint_id="ethereum-builder-evidence-v1",
        signed_bundle=bundle,
        request_id="f6-request-1",
        created_at_unix_ms=bundle.created_at_unix_ms + 1,
    )


def f6_relay_response(
    *,
    status: RelayResponseStatus = RelayResponseStatus.ACCEPTED,
    source_id: str = "recorded-relay-response-a",
    source_sha256: str = RELAY_RESPONSE_SOURCE,
    observed_at_unix_ms: int | None = None,
) -> RelayResponseEvidence:
    request = f6_relay_request()
    if observed_at_unix_ms is None:
        observed_at_unix_ms = request.created_at_unix_ms + 1
    if status is RelayResponseStatus.ACCEPTED:
        return RelayResponseEvidence(
            request=request,
            status=status,
            observed_at_unix_ms=observed_at_unix_ms,
            response_source_id=source_id,
            response_source_sha256=source_sha256,
            relay_reference="recorded-relay-reference-f6",
        )
    return RelayResponseEvidence(
        request=request,
        status=status,
        observed_at_unix_ms=observed_at_unix_ms,
        response_source_id=source_id,
        response_source_sha256=source_sha256,
        error_code="recorded-relay-error",
        error_message="recorded offline relay response",
    )


def f6_package_variant(
    *,
    signature_nonce: int,
    request_id: str,
) -> ExternallySignedExecutionPackageEvidence:
    unsigned_transaction = f5_transaction()
    signature = deterministic_signature(
        unsigned_transaction.signing_hash,
        nonce=signature_nonce,
        observed_at_unix_ms=unsigned_transaction.created_at_unix_ms + 1,
    )
    signed_transaction = SignedEip1559TransactionEvidence(
        unsigned_transaction=unsigned_transaction,
        signature=signature,
        created_at_unix_ms=signature.observed_at_unix_ms + 1,
    )
    signed_bundle = SignedPrivateBundleEvidence(
        unsigned_bundle=f5_bundle(),
        signed_transactions=(signed_transaction,),
        created_at_unix_ms=signed_transaction.created_at_unix_ms + 1,
    )
    relay_request = RelaySubmissionRequestEvidence(
        registry=f6_relay_registry(),
        endpoint_id="ethereum-builder-evidence-v1",
        signed_bundle=signed_bundle,
        request_id=request_id,
        created_at_unix_ms=signed_bundle.created_at_unix_ms + 1,
    )
    relay_response = RelayResponseEvidence(
        request=relay_request,
        status=RelayResponseStatus.ACCEPTED,
        observed_at_unix_ms=relay_request.created_at_unix_ms + 1,
        response_source_id="recorded-relay-response-a",
        response_source_sha256=RELAY_RESPONSE_SOURCE,
        relay_reference=f"recorded-relay-reference-{request_id}",
    )
    return ExternallySignedExecutionPackageEvidence(
        unsigned_package=f5_package(),
        signed_transaction=signed_transaction,
        signed_bundle=signed_bundle,
        relay_request=relay_request,
        relay_responses=(relay_response,),
        created_at_unix_ms=relay_response.observed_at_unix_ms + 1,
    )


@lru_cache(maxsize=1)
def f6_package() -> ExternallySignedExecutionPackageEvidence:
    response = f6_relay_response()
    return ExternallySignedExecutionPackageEvidence(
        unsigned_package=f5_package(),
        signed_transaction=f6_signed_transaction(),
        signed_bundle=f6_signed_bundle(),
        relay_request=f6_relay_request(),
        relay_responses=(response,),
        created_at_unix_ms=response.observed_at_unix_ms + 1,
    )
