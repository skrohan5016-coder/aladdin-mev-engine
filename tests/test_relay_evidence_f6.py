from __future__ import annotations

from dataclasses import replace
import unittest

from aladdin_mev_engine.domain import Chain
from aladdin_mev_engine.evm_transaction import PrivateDeliveryClass
from aladdin_mev_engine.relay_evidence import (
    ExternallySignedExecutionPackageEvidence,
    RelayEndpointRegistry,
    RelayEndpointSpec,
    RelayResponseEvidence,
    RelayResponseStatus,
    RelaySubmissionRequestEvidence,
)

from f5_helpers import f5_package
from f6_helpers import (
    RELAY_RESPONSE_SOURCE,
    RELAY_RESPONSE_SOURCE_2,
    f6_package,
    f6_relay_registry,
    f6_relay_request,
    f6_relay_response,
    f6_signed_bundle,
    f6_signed_transaction,
)


class RelayEvidenceF6Tests(unittest.TestCase):
    def test_endpoint_chain_class_and_registry_identity_are_closed(self) -> None:
        endpoint = f6_relay_registry().endpoints[0]
        self.assertIs(endpoint.delivery_class, PrivateDeliveryClass.BUILDER)
        with self.assertRaisesRegex(ValueError, "delivery class"):
            RelayEndpointSpec(
                "wrong-class",
                Chain.ETHEREUM,
                PrivateDeliveryClass.SEQUENCER,
                1,
                False,
                True,
            )
        with self.assertRaisesRegex(ValueError, "conflicting"):
            RelayEndpointRegistry(
                "ambiguous",
                (
                    endpoint,
                    replace(endpoint, maximum_transactions=2),
                ),
            )

    def test_request_payload_is_canonical_copy_safe_and_never_dispatched(self) -> None:
        request = f6_relay_request()
        payload = request.request_payload
        self.assertEqual(payload["jsonrpc"], "2.0")
        self.assertEqual(payload["method"], "aladdin_submitPrivateBundle")
        self.assertEqual(payload["params"][0]["replacement_id"], None)
        self.assertEqual(payload["params"][0]["transactions"], ["0x" + f6_signed_transaction().raw_transaction.hex()])
        original_digest = request.digest
        payload["params"][0]["transactions"][0] = "0x00"
        self.assertNotEqual(payload, request.request_payload)
        self.assertEqual(request.digest, original_digest)
        value = request.to_json_value()
        self.assertFalse(value["local_network_dispatched"])
        self.assertEqual(value["submission_authority"], "none")

    def test_relay_response_cross_field_rules_and_acceptance_is_not_inclusion(self) -> None:
        request = f6_relay_request()
        accepted = f6_relay_response()
        self.assertTrue(accepted.relay_acceptance_observed)
        self.assertFalse(accepted.to_json_value()["inclusion_observed"])
        with self.assertRaisesRegex(ValueError, "requires a relay reference"):
            RelayResponseEvidence(
                request,
                RelayResponseStatus.ACCEPTED,
                request.created_at_unix_ms + 1,
                "source",
                RELAY_RESPONSE_SOURCE,
            )
        with self.assertRaisesRegex(ValueError, "requires exact error"):
            RelayResponseEvidence(
                request,
                RelayResponseStatus.REJECTED,
                request.created_at_unix_ms + 1,
                "source",
                RELAY_RESPONSE_SOURCE,
            )
        rejected = f6_relay_response(status=RelayResponseStatus.REJECTED)
        self.assertFalse(rejected.relay_acceptance_observed)

    def test_externally_signed_package_recomputes_all_identities_and_authority(self) -> None:
        package = f6_package()
        value = package.to_json_value()
        self.assertEqual(package.unsigned_package.digest, f5_package().digest)
        self.assertTrue(value["signature_present"])
        self.assertTrue(value["relay_request_present"])
        self.assertTrue(value["relay_acceptance_observed"])
        self.assertFalse(value["local_network_dispatched"])
        self.assertFalse(value["signing_eligible"])
        self.assertFalse(value["submission_eligible"])
        self.assertFalse(value["execution_eligible"])
        self.assertFalse(value["inclusion_guarantee"])

    def test_wrong_request_and_duplicate_sources_fail_closed(self) -> None:
        request = f6_relay_request()
        alternate = RelaySubmissionRequestEvidence(
            registry=f6_relay_registry(),
            endpoint_id=request.endpoint_id,
            signed_bundle=f6_signed_bundle(),
            request_id="alternate-request",
            created_at_unix_ms=request.created_at_unix_ms,
        )
        wrong_response = RelayResponseEvidence(
            alternate,
            RelayResponseStatus.ACCEPTED,
            alternate.created_at_unix_ms + 1,
            "alternate-source",
            RELAY_RESPONSE_SOURCE_2,
            relay_reference="alternate-reference",
        )
        with self.assertRaisesRegex(ValueError, "exact request"):
            ExternallySignedExecutionPackageEvidence(
                f5_package(),
                f6_signed_transaction(),
                f6_signed_bundle(),
                request,
                (wrong_response,),
                wrong_response.observed_at_unix_ms + 1,
            )
        first = f6_relay_response()
        duplicate_id = f6_relay_response(
            source_id=first.response_source_id,
            source_sha256=RELAY_RESPONSE_SOURCE_2,
        )
        with self.assertRaisesRegex(ValueError, "source id"):
            ExternallySignedExecutionPackageEvidence(
                f5_package(), f6_signed_transaction(), f6_signed_bundle(), request,
                (first, duplicate_id),
                max(first.observed_at_unix_ms, duplicate_id.observed_at_unix_ms) + 1,
            )
        duplicate_digest = f6_relay_response(
            source_id="recorded-relay-response-b",
            source_sha256=first.response_source_sha256,
        )
        with self.assertRaisesRegex(ValueError, "source digest"):
            ExternallySignedExecutionPackageEvidence(
                f5_package(), f6_signed_transaction(), f6_signed_bundle(), request,
                (first, duplicate_digest),
                max(first.observed_at_unix_ms, duplicate_digest.observed_at_unix_ms) + 1,
            )

    def test_response_order_is_canonical_and_future_response_fails(self) -> None:
        first = f6_relay_response(
            source_id="z-source",
            source_sha256=RELAY_RESPONSE_SOURCE,
        )
        second = f6_relay_response(
            status=RelayResponseStatus.REJECTED,
            source_id="a-source",
            source_sha256=RELAY_RESPONSE_SOURCE_2,
        )
        package = ExternallySignedExecutionPackageEvidence(
            f5_package(),
            f6_signed_transaction(),
            f6_signed_bundle(),
            f6_relay_request(),
            (first, second),
            max(first.observed_at_unix_ms, second.observed_at_unix_ms) + 1,
        )
        self.assertEqual([item.response_source_id for item in package.relay_responses], ["a-source", "z-source"])
        with self.assertRaisesRegex(ValueError, "cannot predate"):
            ExternallySignedExecutionPackageEvidence(
                f5_package(), f6_signed_transaction(), f6_signed_bundle(), f6_relay_request(),
                (first,), first.observed_at_unix_ms - 1,
            )


if __name__ == "__main__":
    unittest.main()
