from __future__ import annotations

from dataclasses import replace
import unittest

from aladdin_mev_engine.deployments import AuthenticatedExecutorDeployment, ExecutorDeploymentRegistry
from aladdin_mev_engine.evm_abi import ExecutionConstraintPolicy, GovernedExecutorCall
from aladdin_mev_engine.evm_transaction import (
    PrivateBundleIntent,
    SenderStateEvidence,
    UnsignedEip1559Transaction,
)

from aladdin_mev_engine.observation import ObservationEnvelope
from aladdin_mev_engine.rlp import rlp_decode
from aladdin_mev_engine.state_proof import EvmStateProofEvidence

from f5_helpers import (
    SENDER_BALANCE,
    SENDER_NONCE,
    authenticated_f5_state,
    f5_bundle,
    f5_call,
    f5_deployment,
    f5_net_evidence,
    f5_net_evidence_with_fee,
    f5_transaction,
)


class EvmTransactionF5Tests(unittest.TestCase):
    def test_sender_state_is_authenticated_eoa_nonce_and_balance(self) -> None:
        sender = SenderStateEvidence(authenticated_f5_state()[1])
        self.assertEqual(sender.nonce, SENDER_NONCE)
        self.assertEqual(sender.balance, SENDER_BALANCE)
        self.assertEqual(sender.anchor_sha256, f5_call().deployment.anchor_sha256)

    def test_eip1559_signing_payload_and_hash_are_deterministic(self) -> None:
        transaction = f5_transaction()
        self.assertEqual(transaction.signing_payload[0], 2)
        self.assertEqual(len(transaction.signing_hash), 32)
        decoded = rlp_decode(transaction.signing_payload[1:])
        self.assertEqual(len(decoded), 9)
        self.assertEqual(int.from_bytes(decoded[0], "big"), transaction.chain_id)
        self.assertEqual(int.from_bytes(decoded[1], "big"), transaction.nonce)
        self.assertEqual(int.from_bytes(decoded[2], "big"), transaction.max_priority_fee_per_gas)
        self.assertEqual(int.from_bytes(decoded[3], "big"), transaction.max_fee_per_gas)
        self.assertEqual(int.from_bytes(decoded[4], "big"), transaction.gas_limit)
        self.assertEqual(decoded[5], transaction.to)
        self.assertEqual(int.from_bytes(decoded[6], "big"), transaction.value)
        self.assertEqual(decoded[7], transaction.data)
        self.assertEqual(decoded[8], ())
        zero_bytes = transaction.data.count(0)
        nonzero_bytes = len(transaction.data) - zero_bytes
        self.assertEqual(
            transaction.intrinsic_gas,
            21_000 + 4 * zero_bytes + 16 * nonzero_bytes,
        )
        self.assertLessEqual(transaction.intrinsic_gas, transaction.gas_limit)
        self.assertEqual(
            transaction.inputs_valid_until_unix_ms,
            transaction.call.inputs_valid_until_unix_ms,
        )
        self.assertEqual(
            UnsignedEip1559Transaction(
                transaction.call,
                transaction.sender_state,
                transaction.created_at_unix_ms,
            ).signing_hash,
            transaction.signing_hash,
        )
        value = transaction.to_json_value()
        self.assertIsNone(value["signature"])
        self.assertFalse(value["signing_eligible"])
        self.assertFalse(value["submission_eligible"])

    def test_sender_balance_and_anchor_mismatch_fail_closed(self) -> None:
        transaction = f5_transaction()
        with self.assertRaisesRegex(ValueError, "externally owned"):
            SenderStateEvidence(authenticated_f5_state()[2])


    def test_transaction_rejects_gas_limit_below_intrinsic_requirement(self) -> None:
        base_call = f5_call()
        intrinsic = 21_000 + 4 * base_call.calldata.count(0) + 16 * (
            len(base_call.calldata) - base_call.calldata.count(0)
        )
        evidence = f5_net_evidence_with_fee(
            gas_units_upper_bound=intrinsic - 1,
            max_fee_per_gas=2,
            route_simulation_gas_units=intrinsic - 1,
        )
        deployment = f5_deployment()
        call = GovernedExecutorCall(
            evidence,
            deployment,
            ExecutionConstraintPolicy("f5-low-gas", 50, 30_000),
            max(evidence.created_at_unix_ms + 1, deployment.evidence.proof_observed_at_unix_ms),
        )
        sender = SenderStateEvidence(authenticated_f5_state()[1])
        with self.assertRaisesRegex(ValueError, "intrinsic gas"):
            UnsignedEip1559Transaction(
                call,
                sender,
                max(call.created_at_unix_ms + 1, sender.evidence.proof_observed_at_unix_ms),
            )

    def test_complete_bundle_balance_is_checked_not_each_transaction_only(self) -> None:
        evidence = f5_net_evidence_with_fee(
            gas_units_upper_bound=250_000,
            max_fee_per_gas=2_000_000_000_000,
            valuation_denominator=10**18,
        )
        self.assertTrue(evidence.decision.approved)
        deployment = f5_deployment()
        call = GovernedExecutorCall(
            evidence,
            deployment,
            ExecutionConstraintPolicy("f5-aggregate-balance", 50, 30_000),
            max(evidence.created_at_unix_ms + 1, deployment.evidence.proof_observed_at_unix_ms),
        )
        sender = SenderStateEvidence(authenticated_f5_state()[1])
        first = UnsignedEip1559Transaction(
            call,
            sender,
            max(call.created_at_unix_ms + 1, sender.evidence.proof_observed_at_unix_ms),
        )
        second = UnsignedEip1559Transaction(
            call,
            sender,
            first.created_at_unix_ms + 1,
            nonce_offset=1,
        )
        self.assertLessEqual(first.maximum_upfront_native, sender.balance)
        self.assertLessEqual(second.maximum_upfront_native, sender.balance)
        self.assertGreater(
            first.maximum_upfront_native + second.maximum_upfront_native,
            sender.balance,
        )
        anchor_block = sender.evidence.block_number
        with self.assertRaisesRegex(ValueError, "complete private bundle"):
            PrivateBundleIntent(
                (first, second),
                anchor_block + 1,
                anchor_block + 2,
                second.created_at_unix_ms + 1,
            )

    def test_call_and_transaction_cannot_predate_authenticated_proof_observation(self) -> None:
        evidence = f5_net_evidence()
        deployment = f5_deployment()
        with self.assertRaisesRegex(ValueError, "deployment proof observation"):
            GovernedExecutorCall(
                evidence,
                deployment,
                ExecutionConstraintPolicy("f5-causality", 50, 30_000),
                deployment.evidence.proof_observed_at_unix_ms - 1,
            )

        call = f5_call()
        original = authenticated_f5_state()[1]
        original_value = original.proof_observation.to_json_value()
        later_observation = ObservationEnvelope.create(
            source_id=original.proof_observation.source_id,
            source_sequence=16,
            source_event_id="f5-later-sender-proof",
            observed_at_unix_ms=call.created_at_unix_ms + 2,
            emitted_at_unix_ms=call.created_at_unix_ms + 2,
            kind=original.proof_observation.kind,
            finality=original.proof_observation.finality,
            visibility=original.proof_observation.visibility,
            payload=original_value["payload"],
        )
        later_sender = SenderStateEvidence(
            EvmStateProofEvidence.verify(original.anchor, later_observation)
        )
        with self.assertRaisesRegex(ValueError, "sender proof observation"):
            UnsignedEip1559Transaction(
                call,
                later_sender,
                call.created_at_unix_ms + 1,
            )

    def test_bundle_intent_binds_target_range_and_never_submits(self) -> None:
        bundle = f5_bundle()
        self.assertEqual(bundle.target_block_number + 1, bundle.maximum_block_number)
        self.assertEqual(bundle.to_json_value()["signed_transaction_count"], "0")
        self.assertEqual(
            bundle.anchor_fresh_until_unix_ms,
            bundle.transactions[0].sender_state.evidence.anchor.state_observed_at_unix_ms + 1_000,
        )
        self.assertLessEqual(bundle.inputs_valid_until_unix_ms, bundle.anchor_fresh_until_unix_ms)
        self.assertFalse(bundle.to_json_value()["submission_eligible"])
        anchor_block = bundle.transactions[0].sender_state.evidence.block_number
        with self.assertRaisesRegex(ValueError, "follow"):
            PrivateBundleIntent(
                bundle.transactions,
                anchor_block,
                anchor_block,
                bundle.created_at_unix_ms,
            )
        with self.assertRaisesRegex(ValueError, "distance"):
            PrivateBundleIntent(
                bundle.transactions,
                anchor_block + 9,
                anchor_block + 9,
                bundle.created_at_unix_ms,
            )
        with self.assertRaisesRegex(ValueError, "freshness window"):
            PrivateBundleIntent(
                bundle.transactions,
                anchor_block + 1,
                anchor_block + 2,
                bundle.transactions[0].sender_state.evidence.anchor.state_observed_at_unix_ms + 1_001,
            )


    def test_bundle_requires_executor_deployment_validity_through_maximum_block(self) -> None:
        evidence = f5_net_evidence()
        deployment = f5_deployment()
        anchor_block = deployment.evidence.block_number
        expiring_spec = replace(
            deployment.spec,
            deployment_id="expires-at-anchor",
            valid_until_block=anchor_block,
        )
        registry = ExecutorDeploymentRegistry("expiring-registry", (expiring_spec,))
        expiring_deployment = AuthenticatedExecutorDeployment(
            expiring_spec,
            deployment.evidence,
            registry,
        )
        call = GovernedExecutorCall(
            evidence,
            expiring_deployment,
            ExecutionConstraintPolicy("expiring-deployment", 50, 30_000),
            max(evidence.created_at_unix_ms + 1, deployment.evidence.proof_observed_at_unix_ms),
        )
        sender = SenderStateEvidence(authenticated_f5_state()[1])
        transaction = UnsignedEip1559Transaction(
            call,
            sender,
            max(call.created_at_unix_ms + 1, sender.evidence.proof_observed_at_unix_ms),
        )
        with self.assertRaisesRegex(ValueError, "complete bundle block horizon"):
            PrivateBundleIntent(
                (transaction,),
                anchor_block + 1,
                anchor_block + 2,
                transaction.created_at_unix_ms + 1,
            )

    def test_bundle_rejects_duplicate_or_noncontiguous_transaction(self) -> None:
        bundle = f5_bundle()
        transaction = bundle.transactions[0]
        with self.assertRaisesRegex(ValueError, "nonces"):
            PrivateBundleIntent(
                (transaction, transaction),
                bundle.target_block_number,
                bundle.maximum_block_number,
                bundle.created_at_unix_ms,
            )
        shifted = replace(transaction, nonce_offset=2)
        with self.assertRaisesRegex(ValueError, "nonces"):
            PrivateBundleIntent(
                (transaction, shifted),
                bundle.target_block_number,
                bundle.maximum_block_number,
                bundle.created_at_unix_ms,
            )
        shifted_first = replace(transaction, nonce_offset=1)
        with self.assertRaisesRegex(ValueError, "authenticated sender nonce"):
            PrivateBundleIntent(
                (shifted_first,),
                bundle.target_block_number,
                bundle.maximum_block_number,
                bundle.created_at_unix_ms,
            )
        anchor_block = transaction.sender_state.evidence.block_number
        with self.assertRaisesRegex(ValueError, "authenticated-state horizon"):
            PrivateBundleIntent(
                (transaction,),
                anchor_block + 1,
                anchor_block + 9,
                bundle.created_at_unix_ms,
            )


if __name__ == "__main__":
    unittest.main()
