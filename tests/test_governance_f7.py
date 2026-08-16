from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.canonical import canonical_sha256

ROOT = Path(__file__).resolve().parents[1]


class F7GovernanceRetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.architecture = json.loads(
            (ROOT / "governance" / "architecture.json").read_text(encoding="utf-8")
        )

    def test_f8_binds_accepted_f7_and_disables_live_authority(self) -> None:
        a = self.architecture
        self.assertEqual(a["milestone"], "F8")
        self.assertEqual(a["accepted_parent_head"], "ec4d9a211c204e3363e8a77d8de4ab2199a89be0")
        self.assertEqual(a["accepted_parent_tree"], "42592ed5ce7dc8d87755ff95af4824dc20c9e6fa")
        self.assertEqual(a["accepted_parent_architecture_id"], "AMEV-F7-ARCH-v1-c611202acf40")
        for key in (
            "network_access",
            "relay_access",
            "credential_authority",
            "key_authority",
            "local_signing_authority",
            "submission_authority",
            "execution_authority",
        ):
            self.assertEqual(a[key], "none")
        self.assertEqual(a["realized_profit_authority"], "none")
        self.assertEqual(a["inclusion_guarantee"], "none")
        self.assertEqual(a["historical_outcome_scope"], ["ethereum", "base"])

    def test_f7_authorities_remain_offline_historical_and_bounded(self) -> None:
        expected = {
            "inclusion_authority": "offline-authenticated-transaction-receipt-and-executor-post-state-inclusion-only",
            "settlement_authority": "offline-code-hash-bound-executor-event-reconciliation-only",
            "realized_outcome_authority": "authenticated-inclusion-receipt-code-hash-bound-settlement-and-recorded-rollup-fees-only",
            "realized_profit_authority": "none",
        }
        for key, value in expected.items():
            self.assertEqual(self.architecture[key], value)

    def test_f7_schema_lock_is_retained_and_f8_architecture_lock_is_exact(self) -> None:
        schema_lock = json.loads(
            (ROOT / "governance" / "f7-schemas.lock.json").read_text(encoding="utf-8")
        )
        architecture_lock = json.loads(
            (ROOT / "governance" / "architecture.lock.json").read_text(encoding="utf-8")
        )
        self.assertEqual(self.architecture["f7_schema_lock_sha256"], canonical_sha256(schema_lock))
        digest = canonical_sha256(self.architecture)
        self.assertEqual(architecture_lock["manifest_sha256"], digest)
        self.assertEqual(architecture_lock["architecture_id"], f"AMEV-F8-ARCH-v1-{digest[:12]}")

    def test_complete_required_f7_invariant_and_schema_set_remains_bound(self) -> None:
        required = {
            "recorded-execution-header-hash-and-roots-bind-the-exact-authenticated-block",
            "inclusion-evidence-authenticates-the-executor-runtime-code-hash-and-canonical-empty-storage-at-the-inclusion-block",
            "transaction-and-receipt-inclusion-use-the-exact-same-index-and-authenticated-trie-roots",
            "authenticated-transaction-bytes-equal-the-exact-f6-signed-transaction",
            "nonzero-transaction-index-requires-the-immediately-preceding-authenticated-receipt",
            "transaction-gas-used-is-the-exact-cumulative-receipt-delta",
            "effective-gas-price-is-recomputed-from-authenticated-base-fee-and-f6-fee-caps",
            "successful-outcome-requires-exactly-one-code-hash-bound-executor-settlement-event",
            "settlement-event-plan-beneficiary-token-principal-and-fee-remain-exact-while-successful-output-residual-and-direct-payment-drift-remains-recordable",
            "actual-gas-rollup-and-direct-payment-cost-overruns-are-recorded-and-cannot-manufacture-conservative-floor-preservation",
            "successful-historical-economic-drift-is-recorded-instead-of-rejected-from-the-outcome-ledger",
            "simulation-gas-or-log-drift-is-reported-and-never-rewritten-as-realized-profit",
            "f7-outcome-evidence-never-claims-realized-profit-or-grants-key-submission-or-execution-authority",
            "f7-schema-lock-binds-all-receipt-inclusion-settlement-and-outcome-evidence-schemas",
            "decoded-settlement-event-fields-reconstruct-the-exact-authenticated-log-topics-and-data",
            "settlement-event-model-explicitly-binds-unused-msg-value-refund-to-the-authenticated-sender",
            "target-receipt-bloom-is-a-subset-of-the-authenticated-block-header-bloom",
            "receipt-log-and-topic-count-ceilings-are-enforced-before-canonicalization-or-topic-materialization",
            "canonical-receipt-log-array-digest-enforces-the-global-json-byte-ceiling-before-whole-array-materialization",
            "consensus-receipt-log-addresses-are-exact-bytes20-and-do-not-inherit-nonzero-deployment-policy",
            "executor-post-state-code-continuity-is-model-bound-and-is-not-an-intra-block-execution-trace",
            "f7-schema-references-resolve-by-their-declared-canonical-identifiers",
            "settlement-event-model-cannot-bind-the-canonical-empty-code-hash",
        }
        self.assertTrue(required.issubset(set(self.architecture["invariants"])))
        schemas = set(self.architecture["schemas"])
        for schema in (
            "aladdin-mev-evm-log-entry/v1",
            "aladdin-mev-transaction-receipt/v1",
            "aladdin-mev-evm-block-state-anchor/v1",
            "aladdin-mev-recorded-execution-block/v1",
            "aladdin-mev-authenticated-execution-block/v1",
            "aladdin-mev-indexed-trie-proof/v1",
            "aladdin-mev-authenticated-transaction-receipt-inclusion/v1",
            "aladdin-mev-executor-settlement-event-spec/v1",
            "aladdin-mev-executor-settlement-event-registry/v1",
            "aladdin-mev-executor-settlement-event/v1",
            "aladdin-mev-recorded-rollup-fee/v1",
            "aladdin-mev-realized-execution-outcome/v1",
        ):
            self.assertIn(schema, schemas)


if __name__ == "__main__":
    unittest.main()
