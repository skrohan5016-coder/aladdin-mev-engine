from __future__ import annotations

import json
from pathlib import Path
import unittest
from urllib.parse import urljoin

from aladdin_mev_engine.canonical import canonical_sha256
from aladdin_mev_engine.historical_scoreboard import (
    CalibrationPolicy,
    HistoricalAttemptReference,
    HistoricalCalibrationReport,
    HistoricalCorpusSourceManifest,
    HistoricalEconomicScoreboard,
    HistoricalExpectedValueEvidence,
    HistoricalOutcomeCorpus,
    HistoricalValuationPolicy,
    ResearchPromotionDecision,
    ResearchPromotionPolicy,
)

from f8_helpers import historical_corpus, settled_record

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "calibration-bucket-v1.schema.json",
    "calibration-policy-v1.schema.json",
    "historical-attempt-reference-v1.schema.json",
    "historical-calibration-report-v1.schema.json",
    "historical-cohort-key-v1.schema.json",
    "historical-corpus-source-manifest-v1.schema.json",
    "historical-economic-scoreboard-v1.schema.json",
    "historical-execution-record-v1.schema.json",
    "historical-expected-value-v1.schema.json",
    "historical-outcome-corpus-v1.schema.json",
    "historical-valuation-policy-v1.schema.json",
    "research-promotion-decision-v1.schema.json",
    "research-promotion-policy-v1.schema.json",
)


def references(value: object) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref" and isinstance(child, str):
                found.append(child)
            else:
                found.extend(references(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(references(child))
    return found


def assert_closed_objects(test: unittest.TestCase, value: object, path: str = "#") -> None:
    if isinstance(value, dict):
        if value.get("type") == "object":
            test.assertIs(value.get("additionalProperties"), False, msg=path)
            test.assertEqual(
                set(value.get("properties", {})),
                set(value.get("required", [])),
                msg=path,
            )
        for key, child in value.items():
            assert_closed_objects(test, child, f"{path}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_closed_objects(test, child, f"{path}/{index}")


def runtime_objects():
    record = settled_record()
    corpus = historical_corpus((record,))
    scoreboard = HistoricalEconomicScoreboard(
        corpus, record.cohort, corpus.created_at_unix_ms + 1
    )
    calibration_policy = CalibrationPolicy("f8-calibration", (10, 100, 1000))
    calibration = HistoricalCalibrationReport(
        scoreboard, calibration_policy, scoreboard.created_at_unix_ms + 1
    )
    expected = HistoricalExpectedValueEvidence(
        scoreboard, calibration.created_at_unix_ms + 1
    )
    promotion_policy = ResearchPromotionPolicy(
        policy_id="f8-research-gate",
        minimum_attempts=1,
        minimum_scoreable_records=1,
        minimum_scoreable_rate_bps=0,
        minimum_execution_success_rate_bps=0,
        minimum_floor_preservation_rate_bps=0,
        minimum_cost_upper_bound_respect_rate_bps=0,
        minimum_positive_surplus_rate_bps=0,
        minimum_unique_inclusion_blocks=1,
        maximum_native_cost_overrun_rate_bps=10_000,
        maximum_mean_absolute_error_bps_of_capital=10_000,
        minimum_guarded_mean_surplus=-(1 << 255),
        minimum_scoreable_records_per_nonempty_bucket=1,
    )
    decision = ResearchPromotionDecision(
        scoreboard,
        calibration,
        expected,
        promotion_policy,
        expected.created_at_unix_ms + 1,
    )
    return (
        (
            "historical-valuation-policy-v1.schema.json",
            record.historical_valuation_policy.to_json_value(),
        ),
        (
            "historical-attempt-reference-v1.schema.json",
            HistoricalAttemptReference.from_record(record).to_json_value(),
        ),
        (
            "historical-corpus-source-manifest-v1.schema.json",
            corpus.source_manifest.to_json_value(),
        ),
        ("historical-cohort-key-v1.schema.json", record.cohort.to_json_value()),
        ("historical-execution-record-v1.schema.json", record.to_json_value()),
        ("historical-outcome-corpus-v1.schema.json", corpus.to_json_value()),
        ("historical-economic-scoreboard-v1.schema.json", scoreboard.to_json_value()),
        ("calibration-policy-v1.schema.json", calibration_policy.to_json_value()),
        ("calibration-bucket-v1.schema.json", calibration.buckets[-1].to_json_value()),
        ("historical-calibration-report-v1.schema.json", calibration.to_json_value()),
        ("historical-expected-value-v1.schema.json", expected.to_json_value()),
        ("research-promotion-policy-v1.schema.json", promotion_policy.to_json_value()),
        ("research-promotion-decision-v1.schema.json", decision.to_json_value()),
    )


class F8SchemaContractTests(unittest.TestCase):
    def test_schemas_are_closed_and_all_references_resolve_by_declared_id(self) -> None:
        schema_ids = {
            json.loads(path.read_text(encoding="utf-8"))["$id"]: path.name
            for path in (ROOT / "schemas").glob("*.json")
        }
        identifiers: set[str] = set()
        for name in REQUIRED:
            value = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(
                value["$schema"],
                "https://json-schema.org/draft/2020-12/schema",
            )
            self.assertEqual(value["$id"], f"https://schemas.aladdin-mev.dev/{name}")
            self.assertNotIn(value["$id"], identifiers)
            identifiers.add(value["$id"])
            assert_closed_objects(self, value)
            for reference in references(value):
                if reference.startswith("#"):
                    continue
                resolved = urljoin(value["$id"], reference).split("#", 1)[0]
                self.assertIn(resolved, schema_ids, msg=f"{reference} -> {resolved}")

    def test_f8_schema_lock_binds_exact_canonical_digests(self) -> None:
        lock = json.loads(
            (ROOT / "governance" / "f8-schemas.lock.json").read_text(encoding="utf-8")
        )
        expected = {
            f"schemas/{name}": canonical_sha256(
                json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            )
            for name in REQUIRED
        }
        self.assertEqual(
            lock,
            {
                "schema": "aladdin-mev-f8-schema-lock/v1",
                "files": dict(sorted(expected.items())),
            },
        )

    def test_runtime_output_keys_match_every_f8_schema(self) -> None:
        for name, value in runtime_objects():
            schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(set(value), set(schema["properties"]), msg=name)

    def test_scoreboard_metric_contract_is_exact_and_closed(self) -> None:
        scoreboard_schema = json.loads(
            (ROOT / "schemas" / "historical-economic-scoreboard-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        metrics = scoreboard_schema["properties"]["metrics"]
        runtime = dict(runtime_objects())["historical-economic-scoreboard-v1.schema.json"]
        self.assertEqual(set(metrics["properties"]), set(runtime["metrics"]))
        self.assertIs(metrics["additionalProperties"], False)
        self.assertEqual(set(metrics["properties"]), set(metrics["required"]))

    def test_nullable_economics_and_authority_denials_are_explicit(self) -> None:
        record = json.loads(
            (ROOT / "schemas" / "historical-execution-record-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        for name in (
            "outcome_sha256",
            "actual_external_cost_base_upper_bound",
            "historical_conservative_surplus",
            "prediction_error",
            "absolute_prediction_error",
            "native_cost_overrun",
        ):
            self.assertIn("oneOf", record["properties"][name])
        decision = json.loads(
            (ROOT / "schemas" / "research-promotion-decision-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(decision["properties"]["promotion_scope"]["const"], "offline-research-candidate-only")
        self.assertIs(decision["properties"]["confidence_guarantee"]["const"], False)
        self.assertIs(decision["properties"]["production_promotion_authority"]["const"], False)
        for key in ("signing_authority", "submission_authority", "execution_authority", "realized_profit_authority"):
            self.assertEqual(decision["properties"][key]["const"], "none")
        for name in (
            "historical-economic-scoreboard-v1.schema.json",
            "historical-calibration-report-v1.schema.json",
            "historical-expected-value-v1.schema.json",
            "research-promotion-decision-v1.schema.json",
        ):
            schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(
                schema["properties"]["source_completeness_scope"]["const"],
                "exact-declared-source-window-reference-set-only",
            )
            self.assertIs(
                schema["properties"]["global_completeness_guarantee"]["const"],
                False,
            )


if __name__ == "__main__":
    unittest.main()
