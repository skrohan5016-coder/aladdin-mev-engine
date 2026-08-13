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

    def test_governed_f2_workflow_is_accepted(self) -> None:
        self.assertEqual(workflow_policy_errors(self.workflow), [])

    def test_f2_schema_verification_is_mandatory(self) -> None:
        mutated = self.workflow.replace(
            "python scripts/verify_f2_schemas.py",
            "python -V",
            1,
        )
        errors = workflow_policy_errors(mutated)
        self.assertTrue(any("run command is not allowlisted" in error for error in errors))
        self.assertTrue(any("verify_f2_schemas.py" in error for error in errors))

    def test_alternate_python_network_command_is_rejected(self) -> None:
        mutated = self.workflow.replace(
            "python scripts/verify_f2_schemas.py",
            "python -c \"__import__('urllib.request').urlopen('https://example.invalid')\"",
            1,
        )
        errors = workflow_policy_errors(mutated)
        self.assertTrue(any("run command is not allowlisted" in error for error in errors))

    def test_f2_job_identity_is_mandatory(self) -> None:
        mutated = self.workflow.replace(
            "name: F2 exact-head conformance",
            "name: generic validation",
            1,
        )
        self.assertTrue(any("F2 exact-head" in error for error in workflow_policy_errors(mutated)))


if __name__ == "__main__":
    unittest.main()
