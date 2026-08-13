from __future__ import annotations

from pathlib import Path
import unittest

from scripts.check_repo_policy import workflow_policy_errors

ROOT = Path(__file__).resolve().parents[1]


class RepositoryWorkflowPolicyF1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    def test_governed_workflow_is_accepted(self) -> None:
        self.assertEqual(workflow_policy_errors(self.workflow), [])

    def test_source_head_binding_is_mandatory(self) -> None:
        mutated = self.workflow.replace(
            "ref: ${{ github.event.pull_request.head.sha || github.sha }}",
            "ref: ${{ github.sha }}",
        )
        self.assertTrue(workflow_policy_errors(mutated))

    def test_source_contract_verification_is_mandatory(self) -> None:
        mutated = self.workflow.replace("python scripts/verify_source_contracts.py", "python -V", 1)
        self.assertTrue(any("source-contract" in error for error in workflow_policy_errors(mutated)))

    def test_write_permissions_are_rejected(self) -> None:
        mutated = self.workflow.replace("contents: read", "contents: write")
        self.assertTrue(any("write permissions" in error for error in workflow_policy_errors(mutated)))

    def test_unapproved_or_drifted_actions_are_rejected(self) -> None:
        unapproved = self.workflow.replace(
            "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
            "example/unapproved@5fda3b95a4ea91299a34e894583c3862153e4b97",
            1,
        )
        drifted = self.workflow.replace(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/checkout@0000000000000000000000000000000000000000",
            1,
        )
        self.assertTrue(any("not allowlisted" in error for error in workflow_policy_errors(unapproved)))
        self.assertTrue(any("pin drift" in error for error in workflow_policy_errors(drifted)))

    def test_network_or_publication_commands_are_rejected(self) -> None:
        mutated = self.workflow + "\n      - run: curl https://example.invalid\n"
        self.assertTrue(any("forbidden network" in error for error in workflow_policy_errors(mutated)))


if __name__ == "__main__":
    unittest.main()
