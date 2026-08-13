from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.state_proof import (
    EvmBlockStateAnchor,
    EvmStateProofEvidence,
    EvmStateSnapshot,
)

from f2_helpers import head_observation, proof_fixture, proof_observation, state_observation

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"


class F2SchemaContractTests(unittest.TestCase):
    def _schema(self, name: str) -> dict[str, object]:
        value = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
        self.assertIs(type(value), dict)
        return value

    def test_new_schemas_are_closed_and_parse(self) -> None:
        for name in (
            "evm-block-state-payload-v1.schema.json",
            "evm-state-proof-payload-v1.schema.json",
            "evm-state-proof-evidence-v1.schema.json",
            "evm-state-snapshot-v1.schema.json",
        ):
            with self.subTest(name=name):
                schema = self._schema(name)
                self.assertIs(schema["additionalProperties"], False)
                self.assertEqual(set(schema["properties"]), set(schema["required"]))

    def test_runtime_outputs_match_evidence_and_snapshot_schema_keys(self) -> None:
        fixture = proof_fixture()
        anchor = EvmBlockStateAnchor.from_observations(
            head_observation(fixture),
            state_observation(fixture),
        )
        evidence = EvmStateProofEvidence.verify(anchor, proof_observation(fixture))
        snapshot = EvmStateSnapshot(anchor, (evidence,))
        evidence_schema = self._schema("evm-state-proof-evidence-v1.schema.json")
        snapshot_schema = self._schema("evm-state-snapshot-v1.schema.json")
        self.assertEqual(set(evidence.to_json_value()), set(evidence_schema["properties"]))
        self.assertEqual(set(snapshot.to_json_value()), set(snapshot_schema["properties"]))
        anchor_schema = snapshot_schema["properties"]["anchor"]
        self.assertEqual(set(anchor.to_json_value()), set(anchor_schema["properties"]))

    def test_f2_schema_lock_binds_exact_canonical_digests(self) -> None:
        import hashlib

        lock = json.loads(
            (ROOT / "governance" / "f2-schemas.lock.json").read_text(
                encoding="utf-8"
            )
        )
        expected: dict[str, str] = {}
        for name in (
            "evm-block-state-payload-v1.schema.json",
            "evm-state-proof-payload-v1.schema.json",
            "evm-state-proof-evidence-v1.schema.json",
            "evm-state-snapshot-v1.schema.json",
            "observation-envelope-v1.schema.json",
            "source-contract-v1.schema.json",
        ):
            value = self._schema(name)
            payload = json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            expected[f"schemas/{name}"] = hashlib.sha256(payload).hexdigest()
        self.assertEqual(lock["schema"], "aladdin-mev-f2-schema-lock/v1")
        self.assertEqual(lock["files"], expected)

    def test_inherited_schemas_include_f2_event_kinds(self) -> None:
        observation = self._schema("observation-envelope-v1.schema.json")
        source = self._schema("source-contract-v1.schema.json")
        observation_kinds = set(observation["properties"]["kind"]["enum"])
        source_kinds = set(
            source["properties"]["allowed_events"]["items"]["properties"]["kind"]["enum"]
        )
        self.assertTrue({"evm-block-state", "evm-state-proof"}.issubset(observation_kinds))
        self.assertTrue({"evm-block-state", "evm-state-proof"}.issubset(source_kinds))

    def test_relative_schema_references_resolve_locally(self) -> None:
        snapshot = self._schema("evm-state-snapshot-v1.schema.json")
        reference = snapshot["properties"]["accounts"]["items"]["$ref"]
        self.assertTrue((SCHEMAS / reference).is_file())


if __name__ == "__main__":
    unittest.main()
