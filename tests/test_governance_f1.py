from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.canonical import canonical_sha256
from aladdin_mev_engine.liquidation_contracts import (
    LIQUIDATION_MECHANISMS,
    liquidation_mechanism_set_digest,
)
from aladdin_mev_engine.source_contracts import SOURCE_CONTRACTS, source_contract_set_digest

ROOT = Path(__file__).resolve().parents[1]


class F2GovernanceTests(unittest.TestCase):
    def test_architecture_binds_stacked_parent_registries_and_disabled_authorities(self) -> None:
        architecture = json.loads(
            (ROOT / "governance" / "architecture.json").read_text(encoding="utf-8")
        )
        self.assertEqual(architecture["milestone"], "F2")
        self.assertEqual(
            architecture["stacked_parent_head"],
            "a16253f6643d9a69e2f92dc79ae1c653e193e964",
        )
        self.assertEqual(
            architecture["stacked_parent_tree"],
            "348eb916ad320ccaad0127dd97c630bab1f3d641",
        )
        self.assertEqual(
            architecture["stacked_parent_architecture_id"],
            "AMEV-F1-ARCH-v1-e0cc085585eb",
        )
        self.assertEqual(
            architecture["stacked_parent_status"],
            "draft-unmerged-ci-green",
        )
        self.assertEqual(architecture["source_contract_ids"], sorted(SOURCE_CONTRACTS))
        self.assertEqual(
            architecture["source_contract_set_sha256"],
            source_contract_set_digest(),
        )
        self.assertEqual(
            architecture["liquidation_protocol_ids"],
            sorted(protocol.value for protocol in LIQUIDATION_MECHANISMS),
        )
        self.assertEqual(
            architecture["liquidation_mechanism_set_sha256"],
            liquidation_mechanism_set_digest(),
        )
        self.assertEqual(architecture["observation_authority"], "recorded-input-only")
        self.assertEqual(
            architecture["discovery_authority"],
            "offline-recorded-input-only",
        )
        self.assertEqual(
            architecture["deployment_authority"],
            "none-recorded-input-only",
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

    def test_machine_liquidation_digest_binds_exact_sorted_mechanism_vector(self) -> None:
        document = json.loads(
            (ROOT / "governance" / "liquidation-mechanisms.json").read_text(
                encoding="utf-8"
            )
        )
        expected_mechanisms = [
            LIQUIDATION_MECHANISMS[protocol].to_json_value()
            for protocol in sorted(LIQUIDATION_MECHANISMS, key=lambda item: item.value)
        ]
        self.assertEqual(document["mechanisms"], expected_mechanisms)
        self.assertEqual(
            document["mechanisms_sha256"],
            canonical_sha256(expected_mechanisms),
        )


if __name__ == "__main__":
    unittest.main()
