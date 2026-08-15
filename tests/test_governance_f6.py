from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.canonical import canonical_sha256

ROOT = Path(__file__).resolve().parents[1]


class F6GovernanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.architecture = json.loads((ROOT / "governance" / "architecture.json").read_text(encoding="utf-8"))

    def test_architecture_binds_accepted_f5_and_disables_live_authority(self) -> None:
        a = self.architecture
        self.assertEqual(a["milestone"], "F6")
        self.assertEqual(a["accepted_parent_head"], "f068d1f1ffad9d4c2439dd6f0fa36e333d73817f")
        self.assertEqual(a["accepted_parent_tree"], "89df1b1bf5d665c1ea1b2abb80320d824b6e7bb4")
        self.assertEqual(a["accepted_parent_architecture_id"], "AMEV-F5-ARCH-v1-4359fcd9d1a2")
        for key in (
            "network_access", "relay_access", "credential_authority", "key_authority",
            "local_signing_authority", "submission_authority", "execution_authority",
            "inclusion_authority",
        ):
            self.assertEqual(a[key], "none")
        self.assertEqual(a["signing_authority"], "external-unmodeled")
        self.assertEqual(a["production_relay_registry_lock"], "none")
        self.assertEqual(a["inclusion_guarantee"], "none")

    def test_f6_authorities_are_offline_and_recorded_only(self) -> None:
        expected = {
            "signature_verification_authority": "offline-secp256k1-recovery-only",
            "signed_transaction_authority": "offline-external-signature-evidence-only",
            "signed_bundle_authority": "offline-externally-signed-private-intent-only",
            "relay_endpoint_registry_authority": "explicit-offline-evidence-only-not-production-approval",
            "relay_request_authority": "offline-normalized-request-only",
            "relay_response_authority": "recorded-input-only",
            "externally_signed_package_authority": "offline-external-signature-and-recorded-relay-evidence-only",
        }
        for key, value in expected.items():
            self.assertEqual(self.architecture[key], value)

    def test_f6_schema_and_architecture_locks_are_exact(self) -> None:
        schema_lock = json.loads((ROOT / "governance" / "f6-schemas.lock.json").read_text(encoding="utf-8"))
        architecture_lock = json.loads((ROOT / "governance" / "architecture.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(self.architecture["f6_schema_lock_sha256"], canonical_sha256(schema_lock))
        digest = canonical_sha256(self.architecture)
        self.assertEqual(architecture_lock["manifest_sha256"], digest)
        self.assertEqual(architecture_lock["architecture_id"], f"AMEV-F6-ARCH-v1-{digest[:12]}")

    def test_required_f6_invariants_and_schemas_are_machine_bound(self) -> None:
        required = {
            "eip1559-signature-y-parity-is-exactly-zero-or-one",
            "public-secp256k1-scalar-multiplication-rejects-values-above-the-group-order",
            "eip1559-signature-r-and-s-are-positive-below-the-secp256k1-group-order-and-s-is-low",
            "external-signature-evidence-uniquely-recovers-the-exact-f5-authenticated-sender",
            "signed-type-two-transaction-reuses-the-exact-f5-unsigned-fields-and-empty-access-list",
            "signed-transaction-hash-is-legacy-keccak256-of-the-exact-raw-type-two-transaction",
            "relay-request-payload-is-canonical-immutable-offline-and-never-dispatched",
            "relay-response-source-identifiers-and-source-digests-are-independently-unique",
            "relay-acceptance-is-not-inclusion-execution-or-profit-authority",
            "f6-never-grants-local-signing-submission-execution-or-inclusion-authority",
            "f6-schema-lock-binds-all-external-signature-and-relay-evidence-schemas",
        }
        self.assertTrue(required.issubset(set(self.architecture["invariants"])))
        schemas = set(self.architecture["schemas"])
        for schema in (
            "aladdin-mev-eip1559-signature/v1",
            "aladdin-mev-signed-eip1559-transaction/v1",
            "aladdin-mev-signed-private-bundle/v1",
            "aladdin-mev-relay-endpoint-spec/v1",
            "aladdin-mev-relay-endpoint-registry/v1",
            "aladdin-mev-relay-submission-request/v1",
            "aladdin-mev-relay-response-evidence/v1",
            "aladdin-mev-externally-signed-execution-package/v1",
        ):
            self.assertIn(schema, schemas)


if __name__ == "__main__":
    unittest.main()
