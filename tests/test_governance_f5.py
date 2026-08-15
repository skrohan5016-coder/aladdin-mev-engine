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

    def test_f7_retains_f5_unsigned_package_authorities(self) -> None:
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

    def test_f5_schema_lock_is_retained_under_f7(self) -> None:
        schema_lock = json.loads((ROOT / "governance" / "f5-schemas.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(self.architecture["f5_schema_lock_sha256"], canonical_sha256(schema_lock))

    def test_required_f5_invariants_and_schemas_remain_bound(self) -> None:
        invariants = set(self.architecture["invariants"])
        required = {
            "executor-deployment-address-chain-code-hash-and-validity-bind-exact-f2-evidence",
            "one-executor-runtime-code-hash-cannot-authorize-conflicting-interfaces",
            "executor-calldata-uses-one-exact-selector-and-canonical-abi-layout",
            "executor-minimum-final-output-cannot-weaken-f4-cost-and-profit-policy",
            "sender-is-an-authenticated-eoa-with-empty-code-and-storage",
            "unsigned-transaction-nonce-and-balance-come-from-the-exact-shared-state-anchor",
            "private-bundle-transactions-share-chain-sender-anchor-and-contiguous-nonces",
            "transaction-simulations-bind-exact-anchor-transaction-signing-hash-and-bundle",
            "unsigned-execution-package-recomputes-all-f4-call-transaction-bundle-and-simulation-identities",
            "f5-never-grants-signing-submission-execution-or-inclusion-authority",
            "authenticated-executor-deployment-requires-exact-registry-membership",
            "route-and-final-slippage-minima-use-ceiling-rounding",
            "unsigned-eip1559-gas-limit-cannot-fall-below-canonical-intrinsic-gas",
            "unsigned-transaction-and-bundle-validity-are-bounded-by-the-executor-call-deadline",
            "executor-call-and-unsigned-transaction-cannot-predate-their-authenticated-proof-observations",
            "private-bundle-starts-at-the-authenticated-sender-nonce",
            "authenticated-sender-balance-covers-the-complete-private-bundle-upfront-upper-bound",
            "transaction-simulations-cannot-predate-the-bound-bundle-intent",
            "f5-package-v1-binds-exactly-one-unsigned-transaction",
            "route-command-schema-binds-exact-length-field-order-width-byte-order-and-encoding",
            "abi-calldata-and-eip1559-signing-preimage-are-independently-decoded-in-conformance-tests",
            "executor-interface-binds-the-exact-f4-flash-loan-provider-and-source-authority",
            "f5-package-v1-supports-runtime-bound-recorded-flash-loan-funding-only",
            "unsigned-transaction-value-equals-the-recorded-direct-payment-upper-bound-under-governed-msg-value-semantics",
            "private-bundle-intent-must-be-created-within-the-governed-authenticated-anchor-freshness-window",
            "bundle-and-package-validity-include-the-authenticated-anchor-freshness-ceiling",
            "successful-transaction-simulations-reconcile-route-output-principal-repayment-flash-fee-and-base-token-residual",
            "transaction-simulation-principal-fee-and-residual-match-the-exact-f4-funding-and-plan-authority",
            "failed-transaction-simulations-carry-no-economic-output-claims",
            "executor-interface-binds-msg-sender-as-the-base-token-residual-beneficiary",
            "successful-transaction-simulations-send-the-complete-base-token-residual-to-the-authenticated-sender",
            "transaction-simulation-output-asset-equals-the-exact-f4-base-token",
            "executor-runtime-storage-root-must-be-the-canonical-empty-trie",
            "transaction-simulations-bind-an-explicit-block-number-timestamp-and-base-fee",
            "simulated-block-lies-within-the-bundle-range-and-before-the-executor-deadline",
            "simulated-base-fee-does-not-exceed-the-unsigned-transaction-max-fee",
            "transaction-simulation-operator-fee-does-not-exceed-the-recorded-upper-bound",
            "transaction-simulation-gas-is-bounded-by-canonical-intrinsic-gas-and-the-unsigned-transaction-gas-limit",
            "public-governed-abi-encoder-enforces-simple-cycle-unique-pool-base-token-principal-amount-flow-final-minimum-and-bounded-frame-semantics",
            "simulated-block-timestamp-strictly-follows-the-authenticated-anchor-block-timestamp",
            "executor-call-validity-preserves-the-exact-millisecond-policy-and-f4-evidence-ceiling",
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
