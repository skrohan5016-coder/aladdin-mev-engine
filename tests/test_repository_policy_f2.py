from __future__ import annotations

from pathlib import Path
import unittest

from scripts.check_repo_policy import workflow_policy_errors

ROOT = Path(__file__).resolve().parents[1]


class RepositoryWorkflowPolicyF2RetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

    def test_governed_f5_workflow_retains_f2_gates(self) -> None:
        self.assertEqual(workflow_policy_errors(self.workflow), [])
        self.assertEqual(
            self.workflow.count("python scripts/verify_f2_schemas.py"),
            2,
        )

    def test_f2_schema_verification_is_mandatory(self) -> None:
        mutated = self.workflow.replace(
            "python scripts/verify_f2_schemas.py",
            "python -V",
            1,
        )
        errors = workflow_policy_errors(mutated)
        self.assertTrue(
            any("run command is not allowlisted" in error for error in errors)
        )
        self.assertTrue(
            any("verify_f2_schemas.py" in error for error in errors)
        )

    def test_alternate_python_network_command_is_rejected(self) -> None:
        mutated = self.workflow.replace(
            "python scripts/verify_f2_schemas.py",
            "python -c \"__import__('urllib.request').urlopen('https://example.invalid')\"",
            1,
        )
        self.assertTrue(
            any(
                "run command is not allowlisted" in error
                for error in workflow_policy_errors(mutated)
            )
        )

    def test_f5_job_identity_replaces_stale_f2_identity(self) -> None:
        self.assertIn("name: F5 exact-head conformance", self.workflow)
        self.assertNotIn("name: F2 exact-head conformance", self.workflow)


if __name__ == "__main__":
    unittest.main()
