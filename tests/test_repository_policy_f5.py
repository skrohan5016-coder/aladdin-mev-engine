from __future__ import annotations

from pathlib import Path
import unittest

from scripts.check_repo_policy import workflow_policy_errors

ROOT = Path(__file__).resolve().parents[1]


class RepositoryWorkflowPolicyF5Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    def test_governed_f6_workflow_is_accepted(self) -> None:
        self.assertEqual(workflow_policy_errors(self.workflow), [])

    def test_f5_schema_verification_is_mandatory(self) -> None:
        mutated = self.workflow.replace("python scripts/verify_f5_schemas.py", "python -V", 1)
        errors = workflow_policy_errors(mutated)
        self.assertTrue(any("run command is not allowlisted" in error for error in errors))
        self.assertTrue(any("verify_f5_schemas.py" in error for error in errors))

    def test_source_and_merge_identities_are_mandatory(self) -> None:
        source = self.workflow.replace("name: F6 exact-head conformance", "name: generic", 1)
        merge = self.workflow.replace("name: F6 merge integration", "name: generic", 1)
        self.assertTrue(any("F6 exact-head" in error for error in workflow_policy_errors(source)))
        self.assertTrue(any("F6 merge-integration" in error for error in workflow_policy_errors(merge)))

    def test_execution_wrapper_and_network_bypasses_are_rejected(self) -> None:
        mutations = (
            self.workflow + "\ndefaults:\n  run:\n    shell: python {0}\n",
            self.workflow.replace("    timeout-minutes: 10", "    timeout-minutes: 10\n    env:\n      BASH_ENV: tests/x.sh", 1),
            self.workflow.replace("runs-on: ubuntu-latest", "runs-on: self-hosted", 1),
            self.workflow.replace("      - name: Unit and adversarial tests", "      - name: Unit and adversarial tests\n        continue-on-error: true", 1),
            self.workflow.replace("      - name: Repository policy", "      - name: Repository policy\n        if: false", 1),
            self.workflow.replace("          persist-credentials: false", "          persist-credentials: false\n          submodules: recursive", 1),
            self.workflow + "\n      - run: git push origin HEAD\n",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertTrue(workflow_policy_errors(mutation))


if __name__ == "__main__":
    unittest.main()
