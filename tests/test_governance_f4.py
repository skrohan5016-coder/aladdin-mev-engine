from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.canonical import canonical_sha256

ROOT = Path(__file__).resolve().parents[1]


class F4GovernanceRetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.architecture = json.loads((ROOT / "governance" / "architecture.json").read_text(encoding="utf-8"))

    def test_f6_architecture_retains_f4_shadow_authorities(self) -> None:
        a = self.architecture
        self.assertEqual(a["milestone"], "F6")
        self.assertEqual(a["network_access"], "none")
        self.assertEqual(a["execution_authority"], "none")
        self.assertEqual(a["execution_plan_authority"], "offline-structural-plan-only")
        self.assertEqual(a["simulation_authority"], "recorded-distinct-implementation-exact-agreement-only")
        self.assertEqual(a["chain_health_authority"], "recorded-source-bound-shadow-context-only")
        self.assertEqual(a["risk_budget_authority"], "recorded-recomputed-snapshot-shadow-only")
        self.assertEqual(a["cost_evidence_authority"], "offline-recorded-upper-bound-shadow-only")
        self.assertEqual(a["cost_completeness"], "complete-recorded-upper-bound-no-inclusion-guarantee")

    def test_f4_schema_lock_is_retained_and_f6_architecture_lock_is_exact(self) -> None:
        schema_lock = json.loads((ROOT / "governance" / "f4-schemas.lock.json").read_text())
        lock = json.loads((ROOT / "governance" / "architecture.lock.json").read_text())
        self.assertEqual(self.architecture["f4_schema_lock_sha256"], canonical_sha256(schema_lock))
        digest = canonical_sha256(self.architecture)
        self.assertEqual(lock["manifest_sha256"], digest)
        self.assertEqual(lock["architecture_id"], f"AMEV-F6-ARCH-v1-{digest[:12]}")

    def test_f4_required_invariants_are_machine_bound(self) -> None:
        invariants = set(self.architecture["invariants"])
        required = {
            "valuation-is-directional-explicit-time-bounded-and-rounded-up",
            "valuation-book-contains-exactly-the-required-cost-conversion-pairs",
            "execution-plans-recompute-every-step-from-the-exact-f3-route-quote",
            "eip1559-priority-fee-is-contained-inside-max-fee-and-never-added-again",
            "every-reserve-cost-category-is-present-exactly-once",
            "route-simulation-independence-requires-distinct-engine-implementation-and-result-source-digests",
            "risk-budget-is-recomputed-from-a-source-bound-snapshot-and-binds-plan-cost-and-notional",
            "cost-complete-shadow-approval-never-grants-inclusion-signing-or-execution-authority",
            "op-stack-operator-fee-is-explicit-separate-from-eip1559-gas-l1-data-and-direct-payment",
        }
        self.assertTrue(required.issubset(invariants))

    def test_context_schemas_are_retained(self) -> None:
        schemas = set(self.architecture["schemas"])
        self.assertIn("aladdin-mev-chain-health-evidence/v1", schemas)
        self.assertIn("aladdin-mev-risk-budget-evidence/v1", schemas)


if __name__ == "__main__":
    unittest.main()
