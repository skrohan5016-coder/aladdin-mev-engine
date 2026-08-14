from __future__ import annotations

from dataclasses import replace
import unittest

from aladdin_mev_engine.deployments import (
    AuthenticatedExecutorDeployment,
    ExecutorDeploymentRegistry,
    ExecutorDeploymentSpec,
    ExecutorInterfaceSpec,
    ROUTE_COMMAND_BINARY_BYTES,
)
from aladdin_mev_engine.state_proof import EMPTY_CODE_HASH

from f5_helpers import (
    EXECUTOR_CODE_HASH,
    executor_evidence_with_nonempty_storage,
    f5_deployment,
)


class DeploymentF5Tests(unittest.TestCase):
    def test_interface_selector_and_route_schema_are_exact(self) -> None:
        deployment = f5_deployment()
        self.assertEqual(deployment.spec.interface.function_selector.hex(), "2a4b1c55")
        self.assertEqual(
            deployment.spec.interface.function_signature,
            "execute(bytes32,address,uint256,uint256,uint64,bytes)",
        )
        self.assertEqual(len(deployment.spec.interface.route_command_schema_sha256), 64)
        self.assertEqual(ROUTE_COMMAND_BINARY_BYTES, 189)
        self.assertEqual(deployment.spec.interface.flash_loan_provider_id, "recorded-lender-f5")
        self.assertEqual(deployment.spec.interface.to_json_value()["funding_kind"], "flash-loan")
        self.assertEqual(
            deployment.spec.interface.to_json_value()["value_semantics"],
            "msg-value-conditional-coinbase-payment-upper-bound",
        )
        self.assertEqual(
            deployment.spec.interface.to_json_value()["beneficiary_semantics"],
            "msg-sender-receives-complete-base-token-residual",
        )
        self.assertEqual(
            deployment.spec.interface.to_json_value()["storage_semantics"],
            "empty-storage-root-stateless-runtime",
        )

    def test_authenticated_deployment_binds_address_chain_code_and_block(self) -> None:
        deployment = f5_deployment()
        self.assertEqual(deployment.evidence.code_hash, EXECUTOR_CODE_HASH)
        with self.assertRaisesRegex(ValueError, "code hash"):
            AuthenticatedExecutorDeployment(
                replace(
                    deployment.spec,
                    deployment_id="wrong-code",
                    runtime_code_hash=bytes.fromhex("ff" * 32),
                ),
                deployment.evidence,
                deployment.registry,
            )
        with self.assertRaisesRegex(ValueError, "address"):
            AuthenticatedExecutorDeployment(
                replace(
                    deployment.spec,
                    deployment_id="wrong-address",
                    address=bytes.fromhex("ee" * 20),
                ),
                deployment.evidence,
                deployment.registry,
            )
        with self.assertRaisesRegex(ValueError, "not valid"):
            AuthenticatedExecutorDeployment(
                replace(
                    deployment.spec,
                    deployment_id="wrong-block",
                    valid_from_block=deployment.evidence.block_number + 1,
                ),
                deployment.evidence,
                deployment.registry,
            )
        unregistered = replace(
            deployment.spec,
            deployment_id="unregistered",
            deployment_source_sha256="ab" * 32,
        )
        with self.assertRaisesRegex(ValueError, "registry authority"):
            AuthenticatedExecutorDeployment(
                unregistered,
                deployment.evidence,
                deployment.registry,
            )

    def test_executor_storage_root_must_be_canonical_empty_trie(self) -> None:
        evidence = executor_evidence_with_nonempty_storage()
        baseline = f5_deployment().spec
        spec = replace(
            baseline,
            deployment_id="stateful-executor",
            valid_from_block=evidence.block_number,
            valid_until_block=evidence.block_number + 8,
        )
        registry = ExecutorDeploymentRegistry("stateful-registry", (spec,))
        with self.assertRaisesRegex(ValueError, "empty storage root"):
            AuthenticatedExecutorDeployment(spec, evidence, registry)

    def test_empty_code_and_ambiguous_registry_fail_closed(self) -> None:
        deployment = f5_deployment()
        with self.assertRaisesRegex(ValueError, "empty runtime"):
            ExecutorDeploymentSpec(
                deployment_id="empty",
                chain=deployment.chain,
                address=deployment.address,
                runtime_code_hash=EMPTY_CODE_HASH,
                interface=deployment.spec.interface,
                valid_from_block=1,
                valid_until_block=2,
                deployment_source_sha256="11" * 32,
            )
        overlapping = replace(
            deployment.spec,
            deployment_id="overlap",
            valid_from_block=deployment.spec.valid_from_block + 1,
        )
        with self.assertRaisesRegex(ValueError, "overlapping"):
            ExecutorDeploymentRegistry("ambiguous", (deployment.spec, overlapping))

    def test_registry_resolution_is_exact(self) -> None:
        deployment = f5_deployment()
        registry = ExecutorDeploymentRegistry("f5-registry", (deployment.spec,))
        self.assertEqual(
            registry.resolve(
                deployment.chain,
                deployment.address,
                deployment.evidence.block_number,
            ).digest,
            deployment.spec.digest,
        )
        with self.assertRaisesRegex(ValueError, "exactly one"):
            registry.resolve(
                deployment.chain,
                bytes.fromhex("dd" * 20),
                deployment.evidence.block_number,
            )

    def test_interface_rejects_unbounded_or_drifted_contract(self) -> None:
        with self.assertRaisesRegex(ValueError, "signature"):
            ExecutorInterfaceSpec(
                interface_id="drifted",
                interface_source_sha256="22" * 32,
                flash_loan_provider_id="provider",
                flash_loan_source_sha256="23" * 32,
                function_signature="execute(bytes)",
            )
        with self.assertRaisesRegex(ValueError, "external flash-loan"):
            ExecutorInterfaceSpec(
                interface_id="self-funded",
                interface_source_sha256="22" * 32,
                flash_loan_provider_id="self",
                flash_loan_source_sha256="23" * 32,
            )
        with self.assertRaisesRegex(ValueError, "ceiling"):
            ExecutorInterfaceSpec(
                interface_id="oversized",
                interface_source_sha256="22" * 32,
                flash_loan_provider_id="provider",
                flash_loan_source_sha256="23" * 32,
                maximum_calldata_bytes=65_537,
            )


if __name__ == "__main__":
    unittest.main()
