from __future__ import annotations

from pathlib import Path
import unittest

from scripts.check_repo_policy import workflow_policy_errors

ROOT = Path(__file__).resolve().parents[1]


class RepositoryWorkflowPolicyF2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

    def test_governed_workflow_is_accepted(self) -> None:
        self.assertEqual(workflow_policy_errors(self.workflow), [])

    def test_f2_exact_head_identity_is_mandatory(self) -> None:
        mutated = self.workflow.replace(
            "name: F2 exact-head conformance",
            "name: generic validation",
            1,
        )
        self.assertTrue(
            any("F2 exact-head" in error for error in workflow_policy_errors(mutated))
        )

    def test_liquidation_mechanism_verification_is_mandatory(self) -> None:
        mutated = self.workflow.replace(
            "python scripts/verify_liquidation_mechanisms.py",
            "python -V",
            1,
        )
        self.assertTrue(
            any("liquidation-mechanism" in error for error in workflow_policy_errors(mutated))
        )

    def test_source_contract_verification_remains_mandatory(self) -> None:
        mutated = self.workflow.replace(
            "python scripts/verify_source_contracts.py",
            "python -V",
            1,
        )
        self.assertTrue(
            any("source-contract" in error for error in workflow_policy_errors(mutated))
        )

    def test_merge_revision_identity_remains_mandatory(self) -> None:
        mutated = self.workflow.replace(
            'test "$(git rev-parse HEAD)" = "${{ github.sha }}"',
            "python -V",
            1,
        )
        self.assertTrue(
            any("merge-integration identity" in error for error in workflow_policy_errors(mutated))
        )


if __name__ == "__main__":
    unittest.main()
