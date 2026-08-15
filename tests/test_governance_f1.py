from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.canonical import canonical_sha256
from aladdin_mev_engine.source_contracts import SOURCE_CONTRACTS, source_contract_set_digest

ROOT = Path(__file__).resolve().parents[1]


class InheritedGovernanceRetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.architecture = json.loads((ROOT / "governance" / "architecture.json").read_text(encoding="utf-8"))

    def test_architecture_binds_accepted_f6_parent_and_retains_early_authorities(self) -> None:
        a = self.architecture
        self.assertEqual(a["milestone"], "F7")
        self.assertEqual(a["accepted_parent_head"], "6481e17b2345c54261865125b61523610b7f87af")
        self.assertEqual(a["accepted_parent_tree"], "1115dccd7952225dfa1d58238aa550bf9e0aa995")
        self.assertEqual(a["accepted_parent_architecture_id"], "AMEV-F6-ARCH-v1-c91039d7d800")
        self.assertEqual(a["source_contract_ids"], sorted(SOURCE_CONTRACTS))
        self.assertEqual(a["source_contract_set_sha256"], source_contract_set_digest())
        self.assertEqual(a["observation_authority"], "recorded-input-only")
        self.assertEqual(a["state_proof_authority"], "offline-recorded-input-only")
        self.assertEqual(a["opportunity_authority"], "offline-authenticated-model-bound-gross-shadow-only")
        self.assertEqual(a["production_model_lock"], "none")
        self.assertEqual(a["constant_product_opportunity_scope"], ["ethereum", "base"])
        self.assertEqual(a["runtime_dependencies"], [])
        for key in ("network_access", "relay_access", "execution_authority"):
            self.assertEqual(a[key], "none")

    def test_architecture_retains_f2_through_f7_schema_locks(self) -> None:
        for milestone in ("f2", "f3", "f4", "f5", "f6", "f7"):
            lock = json.loads((ROOT / "governance" / f"{milestone}-schemas.lock.json").read_text(encoding="utf-8"))
            self.assertEqual(self.architecture[f"{milestone}_schema_lock_sha256"], canonical_sha256(lock))

    def test_architecture_lock_matches_canonical_f7_manifest(self) -> None:
        lock = json.loads((ROOT / "governance" / "architecture.lock.json").read_text(encoding="utf-8"))
        digest = canonical_sha256(self.architecture)
        self.assertEqual(lock["manifest_sha256"], digest)
        self.assertEqual(lock["architecture_id"], f"AMEV-F7-ARCH-v1-{digest[:12]}")
        self.assertEqual(lock["manifest_path"], "governance/architecture.json")
        self.assertEqual(lock["schema"], "aladdin-mev-architecture-lock/v1")

    def test_machine_source_contract_digest_remains_exact(self) -> None:
        document = json.loads((ROOT / "governance" / "source-contracts.json").read_text(encoding="utf-8"))
        expected_contracts = [SOURCE_CONTRACTS[source_id].to_json_value() for source_id in sorted(SOURCE_CONTRACTS)]
        self.assertEqual(document["contracts"], expected_contracts)
        self.assertEqual(document["contracts_sha256"], canonical_sha256(expected_contracts))


if __name__ == "__main__":
    unittest.main()
