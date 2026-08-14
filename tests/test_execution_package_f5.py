from __future__ import annotations

from dataclasses import replace
import unittest

from aladdin_mev_engine.execution_package import (
    TransactionSimulationResult,
    UnsignedExecutionPackageEvidence,
    transaction_simulations_agree,
)

from f5_helpers import (
    f5_bundle,
    f5_call,
    f5_net_evidence,
    f5_package,
    f5_transaction,
    transaction_simulations,
)


class ExecutionPackageF5Tests(unittest.TestCase):
    def test_final_package_recomputes_every_identity_and_remains_unsigned(self) -> None:
        package = f5_package()
        value = package.to_json_value()
        self.assertTrue(package.net_profit_evidence.decision.approved)
        self.assertEqual(package.transaction.call.digest, package.call.digest)
        self.assertEqual(package.bundle.transactions[0].digest, package.transaction.digest)
        self.assertFalse(value["signature_present"])
        self.assertFalse(value["signing_eligible"])
        self.assertFalse(value["submission_eligible"])
        self.assertFalse(value["execution_eligible"])
        self.assertFalse(value["inclusion_guarantee"])
        self.assertEqual(
            package.valid_until_unix_ms,
            min(
                package.call.inputs_valid_until_unix_ms,
                package.bundle.anchor_fresh_until_unix_ms,
                *(item.valid_until_unix_ms for item in package.simulations),
            ),
        )

    def test_operator_fee_simulation_is_explicit_and_bounded(self) -> None:
        transaction = f5_transaction()
        self.assertEqual(transaction.operator_fee_upper_bound, 0)
        self.assertEqual(transaction.to_json_value()["operator_fee_upper_bound"], "0")
        rows = transaction_simulations()
        self.assertEqual(rows[0].operator_fee_paid, 0)
        excessive = tuple(replace(item, operator_fee_paid=1) for item in rows)
        with self.assertRaisesRegex(ValueError, "operator fee"):
            UnsignedExecutionPackageEvidence(
                f5_net_evidence(),
                f5_call(),
                transaction,
                f5_bundle(),
                excessive,
                f5_bundle().created_at_unix_ms + 2,
            )

    def test_transaction_simulation_independence_and_exact_agreement(self) -> None:
        rows = transaction_simulations()
        self.assertTrue(transaction_simulations_agree(rows))
        self.assertFalse(transaction_simulations_agree((rows[0], replace(rows[1], engine_id=rows[0].engine_id))))
        self.assertFalse(
            transaction_simulations_agree(
                (rows[0], replace(rows[1], engine_implementation_sha256=rows[0].engine_implementation_sha256))
            )
        )
        self.assertFalse(
            transaction_simulations_agree(
                (rows[0], replace(rows[1], result_source_sha256=rows[0].result_source_sha256))
            )
        )

    def test_wrong_transaction_bundle_output_gas_or_payment_fails_closed(self) -> None:
        evidence = f5_net_evidence()
        call = f5_call()
        transaction = f5_transaction()
        bundle = f5_bundle()
        created = bundle.created_at_unix_ms + 2
        cases = (
            (replace(transaction_simulations()[0], transaction_sha256="ff" * 32), transaction_simulations()[1], "transaction"),
            (replace(transaction_simulations()[0], bundle_sha256="ff" * 32), transaction_simulations()[1], "bundle"),
            (
                replace(
                    transaction_simulations()[0],
                    output_amount=transaction_simulations()[0].output_amount + 1,
                    base_token_residual_before_external_costs=(
                        transaction_simulations()[0].base_token_residual_before_external_costs + 1
                    ),
                    base_token_beneficiary_delta=(
                        transaction_simulations()[0].base_token_beneficiary_delta + 1
                    ),
                ),
                transaction_simulations()[1],
                "agreement",
            ),
            (replace(transaction_simulations()[0], gas_used=transaction.gas_limit + 1), replace(transaction_simulations()[1], gas_used=transaction.gas_limit + 1), "gas"),
            (replace(transaction_simulations()[0], coinbase_payment=transaction.value + 1), replace(transaction_simulations()[1], coinbase_payment=transaction.value + 1), "coinbase"),
        )
        for left, right, message in cases:
            with self.subTest(message=message):
                with self.assertRaises(ValueError):
                    UnsignedExecutionPackageEvidence(
                        evidence,
                        call,
                        transaction,
                        bundle,
                        (left, right),
                        created,
                    )

    def test_stale_failed_or_mismatched_environment_simulations_fail_closed(self) -> None:
        rows = transaction_simulations()
        failed = replace(
            rows[0],
            success=False,
            gas_used=0,
            output_amount=0,
            flash_loan_principal_repaid=0,
            flash_loan_fee_paid=0,
            base_token_residual_before_external_costs=0,
            base_token_beneficiary_delta=0,
            coinbase_payment=0,
            error_code="revert",
        )
        self.assertFalse(transaction_simulations_agree((failed, rows[1])))
        self.assertFalse(
            transaction_simulations_agree(
                (rows[0], replace(rows[1], environment_sha256="fe" * 32))
            )
        )
        before_bundle = tuple(
            replace(item, observed_at_unix_ms=f5_bundle().created_at_unix_ms - 1)
            for item in rows
        )
        with self.assertRaisesRegex(ValueError, "cannot precede its bundle"):
            UnsignedExecutionPackageEvidence(
                f5_net_evidence(),
                f5_call(),
                f5_transaction(),
                f5_bundle(),
                before_bundle,
                f5_bundle().created_at_unix_ms + 2,
            )
        stale = tuple(replace(item, valid_until_unix_ms=item.observed_at_unix_ms) for item in rows)
        with self.assertRaisesRegex(ValueError, "not valid"):
            UnsignedExecutionPackageEvidence(
                f5_net_evidence(),
                f5_call(),
                f5_transaction(),
                f5_bundle(),
                stale,
                stale[0].valid_until_unix_ms + 1,
            )


    def test_flash_loan_repayment_and_residual_must_reconcile_exactly(self) -> None:
        rows = transaction_simulations()
        evidence = f5_net_evidence()
        self.assertEqual(rows[0].base_token, evidence.plan.base_asset.address)
        self.assertEqual(rows[0].flash_loan_principal_repaid, evidence.plan.funding.principal)
        self.assertEqual(rows[0].flash_loan_fee_paid, evidence.plan.funding.fee)
        self.assertEqual(
            rows[0].base_token_residual_before_external_costs,
            evidence.plan.residual_before_external_costs,
        )
        self.assertEqual(rows[0].base_token_beneficiary, f5_transaction().sender)
        self.assertEqual(
            rows[0].base_token_beneficiary_delta,
            evidence.plan.residual_before_external_costs,
        )
        principal_changed = tuple(
            replace(
                item,
                flash_loan_principal_repaid=item.flash_loan_principal_repaid - 1,
                base_token_residual_before_external_costs=(
                    item.base_token_residual_before_external_costs + 1
                ),
                base_token_beneficiary_delta=(
                    item.base_token_beneficiary_delta + 1
                ),
            )
            for item in rows
        )
        with self.assertRaisesRegex(ValueError, "principal repayment"):
            UnsignedExecutionPackageEvidence(
                evidence, f5_call(), f5_transaction(), f5_bundle(), principal_changed,
                f5_bundle().created_at_unix_ms + 2,
            )

        fee_changed = tuple(
            replace(
                item,
                flash_loan_fee_paid=item.flash_loan_fee_paid + 1,
                base_token_residual_before_external_costs=(
                    item.base_token_residual_before_external_costs - 1
                ),
                base_token_beneficiary_delta=(
                    item.base_token_beneficiary_delta - 1
                ),
            )
            for item in rows
        )
        with self.assertRaisesRegex(ValueError, "flash-loan fee"):
            UnsignedExecutionPackageEvidence(
                evidence, f5_call(), f5_transaction(), f5_bundle(), fee_changed,
                f5_bundle().created_at_unix_ms + 2,
            )

        with self.assertRaisesRegex(ValueError, "residual does not reconcile"):
            replace(
                rows[0],
                base_token_residual_before_external_costs=(
                    rows[0].base_token_residual_before_external_costs + 1
                ),
            )

    def test_simulated_block_timestamp_and_base_fee_are_explicitly_bounded(self) -> None:
        rows = transaction_simulations()
        bundle = f5_bundle()
        transaction = f5_transaction()
        outside = tuple(
            replace(item, simulated_block_number=bundle.target_block_number - 1)
            for item in rows
        )
        with self.assertRaisesRegex(ValueError, "outside the bundle target range"):
            UnsignedExecutionPackageEvidence(
                f5_net_evidence(), f5_call(), transaction, bundle, outside,
                bundle.created_at_unix_ms + 2,
            )
        anchor_timestamp = int(
            transaction.sender_state.evidence.anchor.head_observation.payload[
                "block_timestamp_unix_s"
            ]
        )
        noncausal_timestamp = tuple(
            replace(
                item,
                simulated_block_timestamp_unix_s=anchor_timestamp,
            )
            for item in rows
        )
        with self.assertRaisesRegex(ValueError, "follow the authenticated anchor block"):
            UnsignedExecutionPackageEvidence(
                f5_net_evidence(), f5_call(), transaction, bundle, noncausal_timestamp,
                bundle.created_at_unix_ms + 2,
            )
        after_deadline = tuple(
            replace(
                item,
                simulated_block_timestamp_unix_s=f5_call().deadline_unix_s + 1,
            )
            for item in rows
        )
        with self.assertRaisesRegex(ValueError, "exceeds the executor deadline"):
            UnsignedExecutionPackageEvidence(
                f5_net_evidence(), f5_call(), transaction, bundle, after_deadline,
                bundle.created_at_unix_ms + 2,
            )
        expensive = tuple(
            replace(
                item,
                simulated_base_fee_per_gas=transaction.max_fee_per_gas + 1,
            )
            for item in rows
        )
        with self.assertRaisesRegex(ValueError, "base fee exceeds"):
            UnsignedExecutionPackageEvidence(
                f5_net_evidence(), f5_call(), transaction, bundle, expensive,
                bundle.created_at_unix_ms + 2,
            )

    def test_base_token_residual_must_reach_the_authenticated_sender(self) -> None:
        rows = transaction_simulations()
        wrong_base_token = tuple(
            replace(item, base_token=bytes.fromhex("dd" * 20))
            for item in rows
        )
        with self.assertRaisesRegex(ValueError, "output asset is not the exact F4 base token"):
            UnsignedExecutionPackageEvidence(
                f5_net_evidence(),
                f5_call(),
                f5_transaction(),
                f5_bundle(),
                wrong_base_token,
                f5_bundle().created_at_unix_ms + 2,
            )
        wrong_beneficiary = tuple(
            replace(item, base_token_beneficiary=bytes.fromhex("ee" * 20))
            for item in rows
        )
        with self.assertRaisesRegex(ValueError, "beneficiary is not the authenticated sender"):
            UnsignedExecutionPackageEvidence(
                f5_net_evidence(),
                f5_call(),
                f5_transaction(),
                f5_bundle(),
                wrong_beneficiary,
                f5_bundle().created_at_unix_ms + 2,
            )
        with self.assertRaisesRegex(ValueError, "beneficiary delta"):
            replace(
                rows[0],
                base_token_beneficiary_delta=(
                    rows[0].base_token_beneficiary_delta - 1
                ),
            )

    def test_simulation_constructor_closes_hashes_times_and_success_semantics(self) -> None:
        row = transaction_simulations()[0]
        with self.assertRaisesRegex(ValueError, "lowercase"):
            replace(row, transaction_signing_hash="0x" + "AA" * 32)
        with self.assertRaisesRegex(ValueError, "error code"):
            replace(row, error_code="unexpected")
        with self.assertRaisesRegex(ValueError, "validity"):
            replace(row, valid_until_unix_ms=row.observed_at_unix_ms - 1)


    def test_transaction_simulation_gas_cannot_fall_below_intrinsic_floor(self) -> None:
        package = f5_package()
        impossible = tuple(
            replace(item, gas_used=package.transaction.intrinsic_gas - 1)
            for item in package.simulations
        )
        with self.assertRaisesRegex(ValueError, "intrinsic gas floor"):
            UnsignedExecutionPackageEvidence(
                package.net_profit_evidence,
                package.call,
                package.transaction,
                package.bundle,
                impossible,
                package.created_at_unix_ms,
            )



if __name__ == "__main__":
    unittest.main()
