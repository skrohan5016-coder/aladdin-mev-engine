from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.canonical import canonical_sha256
from aladdin_mev_engine.opportunity import OpportunitySearchReport
from aladdin_mev_engine.optimizer import OptimizationLimits

from f3_helpers import (
    TOKEN_A,
    TOKEN_B,
    authenticated_universe,
    pool_fixture,
)

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "authenticated-constant-product-pool-v1.schema.json",
    "atomic-dex-opportunity-v1.schema.json",
    "constant-product-implementation-v1.schema.json",
    "constant-product-model-registry-v1.schema.json",
    "constant-product-pool-spec-v1.schema.json",
    "constant-product-pool-universe-v1.schema.json",
    "constant-product-route-v1.schema.json",
    "opportunity-search-report-v1.schema.json",
    "opportunity-v1.schema.json",
    "route-optimization-v1.schema.json",
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


def assert_closed_objects(
    test: unittest.TestCase,
    value: object,
    path: str = "#",
) -> None:
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


class F3SchemaContractTests(unittest.TestCase):
    def test_schemas_are_closed_and_relative_references_resolve(self) -> None:
        identifiers: set[str] = set()
        for name in REQUIRED:
            value = json.loads(
                (ROOT / "schemas" / name).read_text(encoding="utf-8")
            )
            self.assertEqual(
                value["$schema"],
                "https://json-schema.org/draft/2020-12/schema",
            )
            self.assertNotIn(value["$id"], identifiers)
            identifiers.add(value["$id"])
            assert_closed_objects(self, value)
            for reference in references(value):
                if reference.startswith(("https://", "#")):
                    continue
                relative = reference.split("#", 1)[0]
                self.assertTrue((ROOT / "schemas" / relative).is_file())

    def test_f3_schema_lock_binds_exact_canonical_digests(self) -> None:
        lock = json.loads(
            (ROOT / "governance" / "f3-schemas.lock.json").read_text(
                encoding="utf-8"
            )
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
                "schema": "aladdin-mev-f3-schema-lock/v1",
                "files": dict(sorted(expected.items())),
            },
        )

    def test_runtime_output_keys_match_governed_schemas(self) -> None:
        state = authenticated_universe(
            (
                pool_fixture(
                    address_byte=1,
                    token0=TOKEN_A,
                    token1=TOKEN_B,
                    reserve0=1000,
                    reserve1=2000,
                ),
                pool_fixture(
                    address_byte=2,
                    token0=TOKEN_A,
                    token1=TOKEN_B,
                    reserve0=1500,
                    reserve1=1000,
                ),
            )
        )
        report = OpportunitySearchReport(
            state,
            TOKEN_A,
            4,
            OptimizationLimits(10_000),
            state.observed_at_unix_ms + 1,
        )
        evidence = report.opportunities()[0]
        pairs = (
            (
                "constant-product-implementation-v1.schema.json",
                state.pools[0].spec.implementation.to_json_value(),
            ),
            (
                "constant-product-model-registry-v1.schema.json",
                state.model_registry.to_json_value(),
            ),
            (
                "constant-product-pool-spec-v1.schema.json",
                state.pools[0].spec.to_json_value(),
            ),
            (
                "authenticated-constant-product-pool-v1.schema.json",
                state.pools[0].to_json_value(),
            ),
            (
                "constant-product-pool-universe-v1.schema.json",
                state.to_json_value(),
            ),
            (
                "constant-product-route-v1.schema.json",
                evidence.route.to_json_value(),
            ),
            (
                "route-optimization-v1.schema.json",
                evidence.optimization.to_json_value(),
            ),
            (
                "atomic-dex-opportunity-v1.schema.json",
                evidence.to_json_value(),
            ),
            (
                "opportunity-search-report-v1.schema.json",
                report.to_json_value(),
            ),
        )
        for name, value in pairs:
            schema = json.loads(
                (ROOT / "schemas" / name).read_text(encoding="utf-8")
            )
            self.assertEqual(set(value), set(schema["properties"]), msg=name)

    def test_uint256_and_uint64_schema_widths_match_runtime_boundaries(self) -> None:
        optimization = json.loads(
            (ROOT / "schemas" / "route-optimization-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            optimization["properties"]["limits"]["properties"]["maximum_input"][
                "maxLength"
            ],
            78,
        )
        self.assertEqual(
            optimization["properties"]["continuous_upper_bound"]["maxLength"],
            78,
        )
        opportunity = json.loads(
            (ROOT / "schemas" / "atomic-dex-opportunity-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            opportunity["properties"]["created_at_unix_ms"]["maxLength"],
            20,
        )


if __name__ == "__main__":
    unittest.main()
