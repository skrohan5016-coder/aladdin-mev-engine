from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.canonical import canonical_sha256

ROOT = Path(__file__).resolve().parents[1]


class F8GovernanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.architecture = json.loads(
            (ROOT / "governance" / "architecture.json").read_text(encoding="utf-8")
        )

    def test_architecture_binds_accepted_f7_and_disables_live_authority(self) -> None:
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
            "realized_profit_authority",
            "production_promotion_authority",
        ):
            self.assertEqual(a[key], "none")
        self.assertEqual(a["historical_scoreboard_scope"], ["ethereum", "base"])

    def test_f8_authorities_are_offline_conditional_and_nonproduction(self) -> None:
        expected = {
            "historical_corpus_authority": "offline-exact-declared-source-window-inclusion-conditioned-history-only",
            "historical_source_manifest_authority": "offline-declared-source-window-reference-set-only",
            "historical_scoreboard_authority": "offline-exact-cohort-scoreboard-only",
            "calibration_authority": "offline-empirical-no-confidence-guarantee",
            "conditional_expected_value_authority": "offline-historical-conditional-estimate-only",
            "research_promotion_authority": "offline-research-evidence-only",
            "production_promotion_authority": "none",
        }
        for key, value in expected.items():
            self.assertEqual(self.architecture[key], value)

    def test_f8_schema_and_architecture_locks_are_exact(self) -> None:
        schema_lock = json.loads(
            (ROOT / "governance" / "f8-schemas.lock.json").read_text(encoding="utf-8")
        )
        architecture_lock = json.loads(
            (ROOT / "governance" / "architecture.lock.json").read_text(encoding="utf-8")
        )
        self.assertEqual(self.architecture["f8_schema_lock_sha256"], canonical_sha256(schema_lock))
        digest = canonical_sha256(self.architecture)
        self.assertEqual(architecture_lock["manifest_sha256"], digest)
        self.assertEqual(architecture_lock["architecture_id"], f"AMEV-F8-ARCH-v1-{digest[:12]}")

    def test_required_f8_invariants_and_schemas_are_machine_bound(self) -> None:
        required = {
            "all-declared-source-attempts-remain-in-the-corpus-with-explicit-scoreability",
            "reverted-settlement-missing-and-settlement-evidence-incomplete-records-remain-in-attempt-denominators-and-cannot-carry-economic-score-authority",
            "a-successful-receipt-with-a-governed-settlement-event-cannot-be-downgraded-to-settlement-missing-by-omitting-outcome-evidence",
            "settlement-event-presence-is-derived-from-the-authenticated-receipt-and-exact-registry-resolved-event-spec",
            "scoreable-economic-aggregates-use-only-authenticated-successful-settlements-with-exact-inclusion-time-valuations",
            "historical-cohort-identity-binds-sender-signature-source-policy-relay-endpoint-relay-response-sources-funding-executor-settlement-model-rollup-fee-source-historical-valuation-policy-pool-model-and-simulation-engines",
            "unscoreable-records-carry-the-same-explicit-historical-valuation-policy-as-scoreable-records-without-carrying-unused-rate-values",
            "scoreable-historical-valuation-rates-must-match-the-exact-policy-assets-direction-source-and-inclusion-time-validity",
            "historical-conservative-surplus-is-a-ceiling-costed-research-estimate-and-never-realized-profit",
            "historical-scoreboard-calibration-and-expected-value-math-use-only-exact-integers",
            "zero-scoreable-sample-expected-value-evidence-is-explicitly-unavailable-and-cannot-pass-research-promotion",
            "research-promotion-policies-require-positive-attempt-scoreable-block-and-nonempty-bucket-minima",
            "calibration-buckets-partition-all-cohort-attempts-and-retain-unscoreable-attempt-counts",
            "conditional-expected-value-evidence-explicitly-grants-no-confidence-guarantee",
            "research-promotion-requires-minimum-scoreable-coverage-and-unique-inclusion-block-diversity",
            "research-promotion-decisions-collect-all-confirmed-failures-without-short-circuiting",
            "research-promotion-never-grants-production-signing-submission-deployment-or-execution-authority",
            "f8-schema-lock-binds-all-historical-scoreboard-calibration-expected-value-and-promotion-schemas",
            "historical-corpus-consumes-the-exact-declared-source-manifest-reference-set",
            "historical-source-completeness-is-limited-to-the-declared-source-window",
            "historical-corpus-grants-no-global-source-completeness-guarantee",
            "scoreboard-calibration-expected-value-and-promotion-evidence-propagate-the-source-completeness-boundary",
        }
        self.assertTrue(required.issubset(set(self.architecture["invariants"])))
        schemas = set(self.architecture["schemas"])
        for schema in (
            "aladdin-mev-historical-attempt-reference/v1",
            "aladdin-mev-historical-cohort-key/v1",
            "aladdin-mev-historical-corpus-source-manifest/v1",
            "aladdin-mev-historical-execution-record/v1",
            "aladdin-mev-historical-outcome-corpus/v1",
            "aladdin-mev-historical-valuation-policy/v1",
            "aladdin-mev-historical-economic-scoreboard/v1",
            "aladdin-mev-calibration-policy/v1",
            "aladdin-mev-calibration-bucket/v1",
            "aladdin-mev-historical-calibration-report/v1",
            "aladdin-mev-historical-expected-value/v1",
            "aladdin-mev-research-promotion-policy/v1",
            "aladdin-mev-research-promotion-decision/v1",
        ):
            self.assertIn(schema, schemas)


if __name__ == "__main__":
    unittest.main()
