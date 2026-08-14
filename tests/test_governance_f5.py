from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.canonical import canonical_sha256

ROOT = Path(__file__).resolve().parents[1]


class F5GovernanceRetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.architecture = json.loads((ROOT / "governance" / "architecture.json").read_text(encoding="utf-8"))

    def test_f6_retains_f5_unsigned_package_authorities(self) -> None:
        a = self.architecture
        expected = {
            "deployment_registry_authority": "authenticated-recorded-direct-runtime-shadow-only",
            "calldata_authority": "offline-deterministic-governed-encoding-only",
            "sender_state_authority": "offline-authenticated-eoa-nonce-balance-only",
            "unsigned_transaction_authority": "offline-eip1559-signing-preimage-only",
            "private_bundle_intent_authority": "offline-relay-neutral-intent-only",
            "transaction_simulation_authority": "recorded-distinct-implementation-exact-agreement-only",
            "execution_package_authority": "offline-unsigned-transaction-bound-shadow-only",
        }
        for key, value in expected.items():
            self.assertEqual(a[key], value)

    def test_f5_schema_lock_is_retained_under_f6(self) -> None:
        schema_lock = json.loads((ROOT / "governance" / "f5-schemas.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(self.architecture["f5_schema_lock_sha256"], canonical_sha256(schema_lock))

    def test_required_f5_invariants_and_schemas_remain_bound(self) -> None:
        invariants = set(self.architecture["invariants"])
        required = {
            "executor-deployment-address-chain-code-hash-and-validity-bind-exact-f2-evidence",
            "one-executor-runtime-code-hash-cannot-authorize-conflicting-interfaces",
            "executor-calldata-uses-one-exact-selector-and-canonical-abi-layout",
            "sender-is-an-authenticated-eoa-with-empty-code-and-storage",
            "unsigned-transaction-nonce-and-balance-come-from-the-exact-shared-state-anchor",
            "private-bundle-transactions-share-chain-sender-anchor-and-contiguous-nonces",
            "transaction-simulations-bind-exact-anchor-transaction-signing-hash-and-bundle",
            "unsigned-execution-package-recomputes-all-f4-call-transaction-bundle-and-simulation-identities",
            "f5-never-grants-signing-submission-execution-or-inclusion-authority",
        }
        self.assertTrue(required.issubset(invariants))
        schemas = set(self.architecture["schemas"])
        for schema in (
            "aladdin-mev-authenticated-executor-deployment/v1",
            "aladdin-mev-governed-executor-call/v1",
            "aladdin-mev-unsigned-eip1559-transaction/v1",
            "aladdin-mev-private-bundle-intent/v1",
            "aladdin-mev-transaction-simulation-result/v1",
            "aladdin-mev-unsigned-execution-package/v1",
        ):
            self.assertIn(schema, schemas)


if __name__ == "__main__":
    unittest.main()
