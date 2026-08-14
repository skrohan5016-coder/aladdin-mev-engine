from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.canonical import canonical_sha256
from aladdin_mev_engine.source_contracts import (
    SOURCE_CONTRACTS,
    source_contract_set_digest,
)

ROOT = Path(__file__).resolve().parents[1]


class InheritedGovernanceRetentionTests(unittest.TestCase):
    def test_architecture_binds_accepted_f3_parent_and_disabled_live_authorities(self) -> None:
        architecture = json.loads(
            (ROOT / "governance" / "architecture.json").read_text(encoding="utf-8")
        )
        self.assertEqual(architecture["milestone"], "F4")
        self.assertEqual(
            architecture["accepted_parent_head"],
            "046b6b2e39c06feba8eb77da2f2139663e84e50e",
        )
        self.assertEqual(
            architecture["accepted_parent_tree"],
            "1c94f705477863b62906f5ec6e5a37ad7a850580",
        )
        self.assertEqual(
            architecture["accepted_parent_architecture_id"],
            "AMEV-F3-ARCH-v1-d2caf73e6121",
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
        self.assertEqual(
            architecture["opportunity_authority"],
            "offline-authenticated-model-bound-gross-shadow-only",
        )
        self.assertEqual(architecture["production_model_lock"], "none")
        self.assertEqual(
            architecture["constant_product_opportunity_scope"],
            ["ethereum", "base"],
        )
        self.assertEqual(architecture["runtime_dependencies"], [])
        for key in ("network_access", "signing_authority", "execution_authority"):
            self.assertEqual(architecture[key], "none")

    def test_architecture_retains_f2_and_f3_schema_locks(self) -> None:
        architecture = json.loads(
            (ROOT / "governance" / "architecture.json").read_text(encoding="utf-8")
        )
        for milestone in ("f2", "f3"):
            lock = json.loads(
                (ROOT / "governance" / f"{milestone}-schemas.lock.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                architecture[f"{milestone}_schema_lock_sha256"],
                canonical_sha256(lock),
            )

    def test_architecture_lock_matches_canonical_f4_manifest(self) -> None:
        architecture = json.loads(
            (ROOT / "governance" / "architecture.json").read_text(encoding="utf-8")
        )
        lock = json.loads(
            (ROOT / "governance" / "architecture.lock.json").read_text(
                encoding="utf-8"
            )
        )
        digest = canonical_sha256(architecture)
        self.assertEqual(lock["manifest_sha256"], digest)
        self.assertEqual(lock["architecture_id"], f"AMEV-F4-ARCH-v1-{digest[:12]}")
        self.assertEqual(lock["manifest_path"], "governance/architecture.json")
        self.assertEqual(lock["schema"], "aladdin-mev-architecture-lock/v1")

    def test_machine_source_contract_digest_remains_exact(self) -> None:
        document = json.loads(
            (ROOT / "governance" / "source-contracts.json").read_text(
                encoding="utf-8"
            )
        )
        expected_contracts = [
            SOURCE_CONTRACTS[source_id].to_json_value()
            for source_id in sorted(SOURCE_CONTRACTS)
        ]
        self.assertEqual(document["contracts"], expected_contracts)
        self.assertEqual(
            document["contracts_sha256"],
            canonical_sha256(expected_contracts),
        )


if __name__ == "__main__":
    unittest.main()
