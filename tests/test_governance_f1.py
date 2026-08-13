from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.canonical import canonical_sha256
from aladdin_mev_engine.source_contracts import SOURCE_CONTRACTS, source_contract_set_digest

ROOT = Path(__file__).resolve().parents[1]


class F2GovernanceTests(unittest.TestCase):
    def test_architecture_binds_parent_source_registry_and_disabled_authorities(self) -> None:
        architecture = json.loads(
            (ROOT / "governance" / "architecture.json").read_text(encoding="utf-8")
        )
        self.assertEqual(architecture["milestone"], "F2")
        self.assertEqual(
            architecture["accepted_parent_head"],
            "f1ce79430bf6d4d4857e4c6ee83fca766b68082c",
        )
        self.assertEqual(
            architecture["accepted_parent_tree"],
            "855a53af31cca7fdae064377309c756b048c0654",
        )
        self.assertEqual(
            architecture["accepted_parent_architecture_id"],
            "AMEV-F1-ARCH-v1-e0cc085585eb",
        )
        self.assertEqual(architecture["source_contract_ids"], sorted(SOURCE_CONTRACTS))
        self.assertEqual(
            architecture["source_contract_set_sha256"],
            source_contract_set_digest(),
        )
        self.assertEqual(architecture["observation_authority"], "recorded-input-only")
        self.assertEqual(
            architecture["state_proof_authority"],
            "offline-recorded-input-only",
        )
        self.assertEqual(architecture["state_proof_scope"], ["ethereum", "base"])
        schema_lock = json.loads(
            (ROOT / "governance" / "f2-schemas.lock.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            architecture["f2_schema_lock_sha256"],
            canonical_sha256(schema_lock),
        )
        for key in ("network_access", "signing_authority", "execution_authority"):
            self.assertEqual(architecture[key], "none")
        self.assertEqual(architecture["runtime_dependencies"], [])

    def test_architecture_lock_matches_canonical_manifest(self) -> None:
        architecture = json.loads(
            (ROOT / "governance" / "architecture.json").read_text(encoding="utf-8")
        )
        lock = json.loads(
            (ROOT / "governance" / "architecture.lock.json").read_text(encoding="utf-8")
        )
        digest = canonical_sha256(architecture)
        self.assertEqual(lock["manifest_sha256"], digest)
        self.assertEqual(lock["architecture_id"], f"AMEV-F2-ARCH-v1-{digest[:12]}")
        self.assertEqual(lock["manifest_path"], "governance/architecture.json")
        self.assertEqual(lock["schema"], "aladdin-mev-architecture-lock/v1")

    def test_machine_source_contract_digest_binds_exact_sorted_contract_vector(self) -> None:
        document = json.loads(
            (ROOT / "governance" / "source-contracts.json").read_text(encoding="utf-8")
        )
        expected_contracts = [
            SOURCE_CONTRACTS[source_id].to_json_value()
            for source_id in sorted(SOURCE_CONTRACTS)
        ]
        self.assertEqual(document["contracts"], expected_contracts)
        self.assertEqual(document["contracts_sha256"], canonical_sha256(expected_contracts))


if __name__ == "__main__":
    unittest.main()
