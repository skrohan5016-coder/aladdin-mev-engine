from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.canonical import canonical_sha256

ROOT = Path(__file__).resolve().parents[1]


class F4GovernanceTests(unittest.TestCase):
    def test_architecture_binds_accepted_f3_and_disables_live_authority(self) -> None:
        architecture = json.loads((ROOT / "governance" / "architecture.json").read_text())
        self.assertEqual(architecture["milestone"], "F4")
        self.assertEqual(
            architecture["accepted_parent_head"],
            "046b6b2e39c06feba8eb77da2f2139663e84e50e",
        )
        self.assertEqual(
            architecture["accepted_parent_tree"],
            "1c94f705477863b62906f5ec6e5a37ad7a850580",
        )
        self.assertEqual(
            architecture["accepted_parent_architecture_id"],
            "AMEV-F3-ARCH-v1-d2caf73e6121",
        )
        self.assertEqual(architecture["network_access"], "none")
        self.assertEqual(architecture["signing_authority"], "none")
        self.assertEqual(architecture["execution_authority"], "none")
        self.assertEqual(
            architecture["execution_plan_authority"],
            "offline-structural-plan-only",
        )
        self.assertEqual(
            architecture["simulation_authority"],
            "recorded-distinct-implementation-exact-agreement-only",
        )
        self.assertEqual(
            architecture["chain_health_authority"],
            "recorded-source-bound-shadow-context-only",
        )
        self.assertEqual(
            architecture["risk_budget_authority"],
            "recorded-recomputed-snapshot-shadow-only",
        )
        self.assertEqual(
            architecture["cost_evidence_authority"],
            "offline-recorded-upper-bound-shadow-only",
        )
        self.assertEqual(
            architecture["cost_completeness"],
            "complete-recorded-upper-bound-no-inclusion-guarantee",
        )
        self.assertEqual(architecture["runtime_dependencies"], [])

    def test_f4_schema_lock_and_architecture_lock_are_exact(self) -> None:
        architecture = json.loads((ROOT / "governance" / "architecture.json").read_text())
        schema_lock = json.loads((ROOT / "governance" / "f4-schemas.lock.json").read_text())
        lock = json.loads((ROOT / "governance" / "architecture.lock.json").read_text())
        self.assertEqual(
            architecture["f4_schema_lock_sha256"],
            canonical_sha256(schema_lock),
        )
        digest = canonical_sha256(architecture)
        self.assertEqual(lock["manifest_sha256"], digest)
        self.assertEqual(lock["architecture_id"], f"AMEV-F4-ARCH-v1-{digest[:12]}")

    def test_f4_required_invariants_are_machine_bound(self) -> None:
        architecture = json.loads((ROOT / "governance" / "architecture.json").read_text())
        invariants = set(architecture["invariants"])
        required = {
            "valuation-is-directional-explicit-time-bounded-and-rounded-up",
            "valuation-book-contains-exactly-the-required-cost-conversion-pairs",
            "execution-plans-recompute-every-step-from-the-exact-f3-route-quote",
            "eip1559-priority-fee-is-contained-inside-max-fee-and-never-added-again",
            "every-reserve-cost-category-is-present-exactly-once",
            "route-simulation-independence-requires-distinct-engine-implementation-and-result-source-digests",
            "route-simulations-bind-the-exact-state-reference-and-remain-valid-at-final-evidence-time",
            "chain-health-is-source-bound-time-bound-and-chain-bound",
            "risk-budget-is-recomputed-from-a-source-bound-snapshot-and-binds-plan-cost-and-notional",
            "cost-envelope-and-all-transitive-inputs-remain-valid-at-final-net-evidence-time",
            "bare-chain-health-and-risk-budget-values-have-no-decision-authority",
            "cost-complete-shadow-approval-never-grants-inclusion-signing-or-execution-authority",
            "route-simulation-agreement-requires-one-exact-environment-digest",
            "risk-budget-pending-daily-and-concurrency-aggregation-is-checked-uint256",
            "risk-budget-snapshot-cannot-precede-the-bound-execution-cost-envelope",
            "f4-profit-policy-integer-fields-are-closed-to-uint256",
        }
        self.assertTrue(required.issubset(invariants))

    def test_context_schemas_are_part_of_the_governed_f4_surface(self) -> None:
        architecture = json.loads((ROOT / "governance" / "architecture.json").read_text())
        schemas = set(architecture["schemas"])
        self.assertIn("aladdin-mev-chain-health-evidence/v1", schemas)
        self.assertIn("aladdin-mev-risk-budget-evidence/v1", schemas)


if __name__ == "__main__":
    unittest.main()
