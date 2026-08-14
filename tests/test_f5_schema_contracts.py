from __future__ import annotations

import json
from pathlib import Path
import unittest

from aladdin_mev_engine.canonical import canonical_sha256
from aladdin_mev_engine.deployments import ExecutorDeploymentRegistry

from f5_helpers import (
    f5_bundle,
    f5_call,
    f5_deployment,
    f5_package,
    f5_transaction,
    transaction_simulations,
)

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "authenticated-executor-deployment-v1.schema.json",
    "execution-constraint-policy-v1.schema.json",
    "executor-deployment-registry-v1.schema.json",
    "executor-deployment-spec-v1.schema.json",
    "executor-interface-v1.schema.json",
    "governed-executor-call-v1.schema.json",
    "private-bundle-intent-v1.schema.json",
    "route-command-v1.schema.json",
    "sender-state-evidence-v1.schema.json",
    "transaction-simulation-result-v1.schema.json",
    "unsigned-eip1559-transaction-v1.schema.json",
    "unsigned-execution-package-v1.schema.json",
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


class F5SchemaContractTests(unittest.TestCase):
    def test_schemas_are_closed_and_relative_references_resolve(self) -> None:
        identifiers: set[str] = set()
        for name in REQUIRED:
            value = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
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
                self.assertTrue((ROOT / "schemas" / relative).is_file(), msg=reference)

    def test_f5_schema_lock_binds_exact_canonical_digests(self) -> None:
        lock = json.loads(
            (ROOT / "governance" / "f5-schemas.lock.json").read_text(
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
                "schema": "aladdin-mev-f5-schema-lock/v1",
                "files": dict(sorted(expected.items())),
            },
        )

    def test_runtime_output_keys_match_governed_schemas(self) -> None:
        deployment = f5_deployment()
        call = f5_call()
        transaction = f5_transaction()
        bundle = f5_bundle()
        pairs = (
            ("executor-interface-v1.schema.json", deployment.spec.interface.to_json_value()),
            ("executor-deployment-spec-v1.schema.json", deployment.spec.to_json_value()),
            ("authenticated-executor-deployment-v1.schema.json", deployment.to_json_value()),
            (
                "executor-deployment-registry-v1.schema.json",
                ExecutorDeploymentRegistry("f5-schema-registry", (deployment.spec,)).to_json_value(),
            ),
            ("execution-constraint-policy-v1.schema.json", call.constraints.to_json_value()),
            ("route-command-v1.schema.json", call.commands[0].to_json_value()),
            ("governed-executor-call-v1.schema.json", call.to_json_value()),
            ("sender-state-evidence-v1.schema.json", transaction.sender_state.to_json_value()),
            ("unsigned-eip1559-transaction-v1.schema.json", transaction.to_json_value()),
            ("private-bundle-intent-v1.schema.json", bundle.to_json_value()),
            (
                "transaction-simulation-result-v1.schema.json",
                transaction_simulations()[0].to_json_value(),
            ),
            ("unsigned-execution-package-v1.schema.json", f5_package().to_json_value()),
        )
        for name, value in pairs:
            schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(set(value), set(schema["properties"]), msg=name)

    def test_schema_widths_match_runtime_integer_and_binary_domains(self) -> None:
        transaction = json.loads(
            (ROOT / "schemas" / "unsigned-eip1559-transaction-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(transaction["properties"]["max_fee_per_gas"]["maxLength"], 78)
        self.assertEqual(transaction["properties"]["nonce"]["maxLength"], 20)
        command = json.loads(
            (ROOT / "schemas" / "route-command-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(command["properties"]["binary"]["pattern"], "^0x[0-9a-f]{378}$")
        self.assertEqual(command["properties"]["index"]["pattern"], "^[0-3]$")
        self.assertEqual(command["properties"]["amount_in"]["pattern"], "^[1-9][0-9]*$")
        self.assertEqual(
            command["properties"]["expected_amount_out"]["pattern"],
            "^[1-9][0-9]*$",
        )
        self.assertEqual(
            command["properties"]["quote_sha256"]["pattern"],
            "^(?!0{64}$)[0-9a-f]{64}$",
        )


if __name__ == "__main__":
    unittest.main()
