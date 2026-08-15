from __future__ import annotations

from pathlib import Path
import unittest

from scripts.check_repo_policy import source_policy_errors, workflow_policy_errors

ROOT = Path(__file__).resolve().parents[1]


class RepositoryWorkflowPolicyF8Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

    def test_governed_f8_workflow_is_accepted(self) -> None:
        self.assertEqual(workflow_policy_errors(self.workflow), [])
        self.assertEqual(self.workflow.count("python scripts/verify_f8_schemas.py"), 2)

    def test_f8_schema_verification_is_mandatory(self) -> None:
        mutated = self.workflow.replace("python scripts/verify_f8_schemas.py", "python -V", 1)
        errors = workflow_policy_errors(mutated)
        self.assertTrue(any("run command is not allowlisted" in item for item in errors))
        self.assertTrue(any("verify_f8_schemas.py" in item for item in errors))

    def test_exact_source_and_merge_identities_are_mandatory(self) -> None:
        source = self.workflow.replace("name: F8 exact-head conformance", "name: generic", 1)
        merge = self.workflow.replace("name: F8 merge integration", "name: generic", 1)
        self.assertTrue(any("F8 exact-head" in item for item in workflow_policy_errors(source)))
        self.assertTrue(any("F8 merge-integration" in item for item in workflow_policy_errors(merge)))

    def test_live_collection_submission_and_automatic_promotion_surfaces_are_rejected(self) -> None:
        cases = {
            "src/http.py": "import requests\n",
            "src/send.py": "def send_raw_transaction(raw):\n    return raw\n",
            "scripts/dispatch.py": "def submit_bundle(bundle):\n    return bundle\n",
            "src/poll.py": "def poll_transaction_receipt(tx_hash):\n    return tx_hash\n",
        }
        for path, source in cases.items():
            with self.subTest(path=path):
                self.assertTrue(source_policy_errors(path, source))
        allowed = (
            "def build_offline_research_promotion_decision(scoreboard):\n"
            "    return scoreboard\n"
        )
        self.assertEqual(source_policy_errors("src/offline_scoreboard.py", allowed), [])

    def test_workflow_wrappers_secrets_and_permissions_are_rejected(self) -> None:
        mutations = (
            self.workflow + "\ndefaults:\n  run:\n    shell: python {0}\n",
            self.workflow.replace(
                "    timeout-minutes: 10",
                "    timeout-minutes: 10\n    env:\n      BASH_ENV: tests/attacker.sh",
                1,
            ),
            self.workflow.replace("runs-on: ubuntu-latest", "runs-on: self-hosted", 1),
            self.workflow.replace("contents: read", "contents: write", 1),
            self.workflow.replace(
                "      - name: Unit and adversarial tests",
                "      - name: Unit and adversarial tests\n        continue-on-error: true",
                1,
            ),
            self.workflow + "\n      - run: curl https://example.invalid\n",
            self.workflow + "\n    env:\n      RPC: ${{ secrets.RPC_URL }}\n",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertTrue(workflow_policy_errors(mutation))


if __name__ == "__main__":
    unittest.main()
