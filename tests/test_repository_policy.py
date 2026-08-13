from __future__ import annotations

from pathlib import Path
import unittest

from scripts.check_repo_policy import workflow_policy_errors

ROOT = Path(__file__).resolve().parents[1]


class RepositoryWorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

    def test_governed_workflow_is_accepted(self) -> None:
        self.assertEqual(workflow_policy_errors(self.workflow), [])

    def test_source_head_binding_is_mandatory(self) -> None:
        mutated = self.workflow.replace(
            "ref: ${{ github.event.pull_request.head.sha || github.sha }}",
            "ref: ${{ github.sha }}",
        )
        self.assertTrue(workflow_policy_errors(mutated))

    def test_write_permissions_are_rejected(self) -> None:
        mutated = self.workflow.replace("contents: read", "contents: write")
        errors = workflow_policy_errors(mutated)
        self.assertTrue(any("write permissions" in error for error in errors))

    def test_mutable_or_drifted_action_pin_is_rejected(self) -> None:
        mutable = self.workflow.replace(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/checkout@v7",
            1,
        )
        drifted = self.workflow.replace(
            "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
            "actions/setup-python@0000000000000000000000000000000000000000",
            1,
        )
        self.assertTrue(any("full SHA" in error for error in workflow_policy_errors(mutable)))
        self.assertTrue(any("pin drift" in error for error in workflow_policy_errors(drifted)))

    def test_unapproved_action_is_rejected_even_when_sha_pinned(self) -> None:
        mutated = self.workflow.replace(
            "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
            "example/unapproved@5fda3b95a4ea91299a34e894583c3862153e4b97",
            1,
        )
        self.assertTrue(any("not allowlisted" in error for error in workflow_policy_errors(mutated)))

    def test_network_or_publication_commands_are_rejected(self) -> None:
        mutated = self.workflow + "\n      - run: curl https://example.invalid\n"
        self.assertTrue(any("forbidden network" in error for error in workflow_policy_errors(mutated)))


if __name__ == "__main__":
    unittest.main()
