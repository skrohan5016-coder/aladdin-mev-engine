from __future__ import annotations

from pathlib import Path
import unittest

from scripts.check_repo_policy import workflow_policy_errors

ROOT = Path(__file__).resolve().parents[1]


class RepositoryWorkflowPolicyF3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

    def test_governed_f3_workflow_is_accepted(self) -> None:
        self.assertEqual(workflow_policy_errors(self.workflow), [])

    def test_f3_schema_verification_is_mandatory(self) -> None:
        mutated = self.workflow.replace(
            "python scripts/verify_f3_schemas.py",
            "python -V",
            1,
        )
        errors = workflow_policy_errors(mutated)
        self.assertTrue(
            any("run command is not allowlisted" in error for error in errors)
        )
        self.assertTrue(
            any("verify_f3_schemas.py" in error for error in errors)
        )

    def test_source_head_and_merge_job_identities_are_mandatory(self) -> None:
        source_mutation = self.workflow.replace(
            "name: F3 exact-head conformance",
            "name: generic validation",
            1,
        )
        merge_mutation = self.workflow.replace(
            "name: F3 merge integration",
            "name: generic merge validation",
            1,
        )
        self.assertTrue(
            any(
                "F3 exact-head" in error
                for error in workflow_policy_errors(source_mutation)
            )
        )
        self.assertTrue(
            any(
                "F3 merge-integration" in error
                for error in workflow_policy_errors(merge_mutation)
            )
        )

    def test_secrets_write_permissions_and_publication_commands_are_rejected(self) -> None:
        secret = self.workflow + "\n    env:\n      RPC: ${{ secrets.RPC_URL }}\n"
        write = self.workflow.replace("contents: read", "contents: write")
        network = self.workflow + "\n      - run: git push origin HEAD\n"
        self.assertTrue(
            any("secret references" in error for error in workflow_policy_errors(secret))
        )
        self.assertTrue(
            any("write permissions" in error for error in workflow_policy_errors(write))
        )
        self.assertTrue(
            any("forbidden network" in error for error in workflow_policy_errors(network))
        )


if __name__ == "__main__":
    unittest.main()
