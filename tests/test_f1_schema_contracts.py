from __future__ import annotations

import json
from pathlib import Path
import unittest
from urllib.parse import urljoin

from aladdin_mev_engine.head_tracker import HeadTracker
from aladdin_mev_engine.ledger import ObservationLedgerBuilder
from aladdin_mev_engine.source_contracts import (
    Finality,
    ObservationKind,
    SOURCE_CONTRACTS,
)
from f1_helpers import make_observation

ROOT = Path(__file__).resolve().parents[1]


class F1SchemaContractTests(unittest.TestCase):
    def test_new_schemas_are_closed_and_parse(self) -> None:
        expected = {
            "source-contract-v1.schema.json",
            "observation-envelope-v1.schema.json",
            "observation-ledger-record-v1.schema.json",
            "observation-segment-manifest-v1.schema.json",
            "head-transition-v1.schema.json",
        }
        for name in expected:
            document = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertFalse(document["additionalProperties"])
            self.assertTrue(document["$id"])

    def test_local_and_absolute_schema_references_resolve(self) -> None:
        def refs(value: object):
            if type(value) is dict:
                reference = value.get("$ref")
                if type(reference) is str:
                    yield reference
                for child in value.values():
                    yield from refs(child)
            elif type(value) is list:
                for child in value:
                    yield from refs(child)

        schema_root = ROOT / "schemas"
        documents = {
            path: json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(schema_root.glob("*.json"))
        }
        identifiers = {document["$id"] for document in documents.values()}
        self.assertEqual(len(identifiers), len(documents))
        for path, document in documents.items():
            for reference in refs(document):
                if reference.startswith("#"):
                    continue
                target = reference.split("#", 1)[0]
                if target.startswith(("https://", "http://")):
                    self.assertIn(target, identifiers, msg=f"{path.name}: {reference}")
                    continue
                self.assertNotIn("/", target)
                self.assertTrue((schema_root / target).is_file(), reference)

    def test_source_contract_output_keys_match_schema(self) -> None:
        schema = json.loads((ROOT / "schemas" / "source-contract-v1.schema.json").read_text())
        expected = set(schema["required"])
        for contract in SOURCE_CONTRACTS.values():
            self.assertEqual(set(contract.to_json_value()), expected)

    def test_envelope_record_manifest_and_transition_keys_match_schemas(self) -> None:
        envelope = make_observation()
        builder = ObservationLedgerBuilder(segment_id="schema-segment", created_at_unix_ms=10_000)
        record = builder.append(envelope)
        segment = builder.seal()
        tracker = HeadTracker(
            chain=envelope.chain,
            source_id=envelope.source_id,
            observation_kind=ObservationKind.BLOCK_HEAD,
            finality=Finality.CONFIRMED,
        )
        transition = tracker.apply(envelope)
        cases = (
            ("observation-envelope-v1.schema.json", envelope.to_json_value()),
            ("observation-ledger-record-v1.schema.json", record.to_json_value()),
            ("observation-segment-manifest-v1.schema.json", segment.manifest.to_json_value()),
            ("head-transition-v1.schema.json", transition.to_json_value()),
        )
        for schema_name, value in cases:
            schema = json.loads((ROOT / "schemas" / schema_name).read_text())
            self.assertEqual(set(value), set(schema["required"]))

    def test_machine_readable_source_contract_set_matches_registry(self) -> None:
        document = json.loads((ROOT / "governance" / "source-contracts.json").read_text())
        self.assertEqual(document["schema"], "aladdin-mev-source-contract-set/v1")
        self.assertEqual(
            document["contracts"],
            [SOURCE_CONTRACTS[key].to_json_value() for key in sorted(SOURCE_CONTRACTS)],
        )


if __name__ == "__main__":
    unittest.main()
