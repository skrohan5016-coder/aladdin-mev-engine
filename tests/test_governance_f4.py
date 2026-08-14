from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.canonical import canonical_sha256

ROOT = Path(__file__).resolve().parents[1]


class F4GovernanceRetentionTests(unittest.TestCase):
    def test_f5_architecture_retains_f4_shadow_authorities(self) -> None:
        architecture = json.loads((ROOT / "governance" / "architecture.json").read_text())
        self.assertEqual(architecture["milestone"], "F5")
        self.assertEqual(
            architecture["accepted_parent_head"],
            "5e9497695c08ec4bd1ef724b39fb941f100c3e73",
        )
        self.assertEqual(
            architecture["accepted_parent_tree"],
            "d909eb7d378a5c188e71a5c475cb36b8c61099a3",
        )
        self.assertEqual(
            architecture["accepted_parent_architecture_id"],
            "AMEV-F4-ARCH-v1-36ee2dc379f7",
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

    def test_f4_schema_lock_is_retained_and_f5_architecture_lock_is_exact(self) -> None:
        architecture = json.loads((ROOT / "governance" / "architecture.json").read_text())
        schema_lock = json.loads((ROOT / "governance" / "f4-schemas.lock.json").read_text())
        lock = json.loads((ROOT / "governance" / "architecture.lock.json").read_text())
        self.assertEqual(
            architecture["f4_schema_lock_sha256"],
            canonical_sha256(schema_lock),
        )
        digest = canonical_sha256(architecture)
        self.assertEqual(lock["manifest_sha256"], digest)
        self.assertEqual(lock["architecture_id"], f"AMEV-F5-ARCH-v1-{digest[:12]}")

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
            "op-stack-operator-fee-is-explicit-separate-from-eip1559-gas-l1-data-and-direct-payment",
            "ethereum-operator-fee-upper-bound-and-paid-amount-are-zero",
            "base-operator-fee-upper-bound-is-recorded-converted-and-included-in-authenticated-sender-balance",
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
