from __future__ import annotations

from dataclasses import replace
import unittest

from aladdin_mev_engine.execution_outcome import (
    SETTLEMENT_EVENT_SIGNATURE,
    AuthenticatedExecutionBlockEvidence,
    AuthenticatedTransactionReceiptInclusionEvidence,
    ExecutionTrieKind,
    ExecutorSettlementEventRegistry,
    ExecutorSettlementEventSpec,
    RealizedExecutionOutcomeEvidence,
    RecordedRollupFeeEvidence,
)
from aladdin_mev_engine.evm_receipt import EvmLogEntry
from aladdin_mev_engine.keccak import keccak256
from aladdin_mev_engine.state_proof import EMPTY_CODE_HASH

from f7_helpers import (
    ROLLUP_FEE_SOURCE,
    f7_inclusion,
    f7_outcome,
    inclusion_fixture,
    settlement_log,
    settlement_spec,
)


def inclusion_from_fixture(fixture) -> AuthenticatedTransactionReceiptInclusionEvidence:
    return AuthenticatedTransactionReceiptInclusionEvidence(
        package=fixture.package,
        block=fixture.authenticated_block,
        executor_state=fixture.executor_state,
        transaction_proof=fixture.transaction_proof,
        receipt_proof=fixture.receipt_proof,
        previous_receipt_proof=fixture.previous_receipt_proof,
        created_at_unix_ms=fixture.receipt_proof.observed_at_unix_ms + 1,
    )


def outcome_from_inclusion(inclusion: AuthenticatedTransactionReceiptInclusionEvidence):
    package = inclusion.package
    spec = settlement_spec(package)
    registry = ExecutorSettlementEventRegistry("f7-synthetic-settlement-registry", (spec,))
    rollup = RecordedRollupFeeEvidence(
        chain=inclusion.block.chain,
        transaction_hash=package.signed_transaction.transaction_hash,
        l1_data_fee_paid=0,
        operator_fee_paid=0,
        observed_at_unix_ms=inclusion.created_at_unix_ms + 1,
        source_id="f7-recorded-rollup-fees",
        source_sha256=ROLLUP_FEE_SOURCE,
    )
    return RealizedExecutionOutcomeEvidence(
        package,
        inclusion,
        registry,
        spec,
        rollup,
        rollup.observed_at_unix_ms + 1,
    )


class ExecutionOutcomeF7Tests(unittest.TestCase):
    def test_block_header_hash_authenticates_all_execution_roots(self) -> None:
        inclusion = f7_inclusion()
        block = inclusion.block.block
        self.assertEqual(inclusion.block.state_anchor.block_hash, block.block_hash)
        with self.assertRaisesRegex(ValueError, "header hash"):
            replace(block, block_hash=bytes.fromhex("ee" * 32))
        with self.assertRaisesRegex(ValueError, "fields disagree"):
            replace(block, transactions_root=bytes.fromhex("ef" * 32))

    def test_receipt_bloom_must_be_contained_in_authenticated_block_bloom(self) -> None:
        fixture = inclusion_fixture(header_logs_bloom=bytes(256))
        with self.assertRaisesRegex(ValueError, "subset"):
            inclusion_from_fixture(fixture)

    def test_executor_runtime_and_stateless_storage_are_authenticated_at_inclusion(self) -> None:
        inclusion = f7_inclusion()
        deployment = inclusion.package.unsigned_package.call.deployment
        self.assertEqual(inclusion.executor_state.address, deployment.address)
        self.assertEqual(
            inclusion.executor_state.code_hash,
            deployment.spec.runtime_code_hash,
        )
        with self.assertRaisesRegex(ValueError, "runtime code hash changed"):
            inclusion_from_fixture(
                inclusion_fixture(executor_code_hash=bytes.fromhex("ee" * 32))
            )
        with self.assertRaisesRegex(ValueError, "storage root changed"):
            inclusion_from_fixture(
                inclusion_fixture(executor_storage_root=bytes.fromhex("ef" * 32))
            )

    def test_transaction_and_receipt_inclusion_derive_individual_gas(self) -> None:
        inclusion = f7_inclusion()
        self.assertEqual(inclusion.transaction_index, 1)
        self.assertEqual(inclusion.receipt.cumulative_gas_used, 250_000)
        self.assertEqual(inclusion.previous_receipt.cumulative_gas_used, 50_000)
        self.assertEqual(inclusion.gas_used, 200_000)
        self.assertEqual(inclusion.effective_gas_price, 2)
        self.assertEqual(inclusion.execution_gas_cost, 400_000)
        self.assertTrue(inclusion.receipt.success)

    def test_tampered_transaction_receipt_and_previous_proofs_fail_closed(self) -> None:
        fixture = inclusion_fixture()
        with self.assertRaises((ValueError, TypeError)):
            inclusion_from_fixture(
                type("Fixture", (), {
                    **fixture.__dict__,
                    "transaction_proof": replace(
                        fixture.transaction_proof,
                        raw_value=fixture.transaction_proof.raw_value + b"\x00",
                    ),
                })()
            )
        with self.assertRaisesRegex(ValueError, "immediately preceding"):
            inclusion_from_fixture(
                type("Fixture", (), {
                    **fixture.__dict__,
                    "previous_receipt_proof": replace(
                        fixture.previous_receipt_proof,
                        index=1,
                    ),
                })()
            )
        broken_node = bytearray(fixture.receipt_proof.proof_nodes[-1])
        broken_node[-1] ^= 1
        with self.assertRaises(ValueError):
            inclusion_from_fixture(
                type("Fixture", (), {
                    **fixture.__dict__,
                    "receipt_proof": replace(
                        fixture.receipt_proof,
                        proof_nodes=(*fixture.receipt_proof.proof_nodes[:-1], bytes(broken_node)),
                    ),
                })()
            )

    def test_nonzero_transaction_index_requires_previous_receipt_authority(self) -> None:
        fixture = inclusion_fixture()
        with self.assertRaisesRegex(ValueError, "requires a previous"):
            AuthenticatedTransactionReceiptInclusionEvidence(
                fixture.package,
                fixture.authenticated_block,
                fixture.executor_state,
                fixture.transaction_proof,
                fixture.receipt_proof,
                None,
                fixture.receipt_proof.observed_at_unix_ms + 1,
            )
        with self.assertRaisesRegex(ValueError, "wrong trie kind"):
            AuthenticatedTransactionReceiptInclusionEvidence(
                fixture.package,
                fixture.authenticated_block,
                fixture.executor_state,
                fixture.transaction_proof,
                fixture.receipt_proof,
                replace(
                    fixture.previous_receipt_proof,
                    kind=ExecutionTrieKind.RECEIPT,
                ),
                fixture.receipt_proof.observed_at_unix_ms + 1,
            )

    def test_reverted_receipt_is_authenticated_but_cannot_authorize_settlement(self) -> None:
        inclusion = inclusion_from_fixture(inclusion_fixture(receipt_status=0))
        self.assertFalse(inclusion.receipt.success)
        with self.assertRaisesRegex(ValueError, "successful authenticated receipt"):
            outcome_from_inclusion(inclusion)

    def test_realized_outcome_reconciles_event_fees_and_upper_bounds(self) -> None:
        outcome = f7_outcome()
        self.assertEqual(outcome.settlement_event.plan_sha256, outcome.package.unsigned_package.net_profit_evidence.plan.digest)
        self.assertEqual(outcome.actual_native_cost, 400_003)
        self.assertTrue(outcome.simulation_exact_match)
        self.assertTrue(outcome.simulation_economic_match)
        self.assertTrue(outcome.cost_upper_bounds_respected)
        self.assertTrue(outcome.conservative_shadow_floor_preserved)
        self.assertEqual(outcome.native_cost_overrun, 0)
        self.assertEqual(
            outcome.base_token_residual_shortfall_before_external_costs,
            0,
        )
        value = outcome.to_json_value()
        self.assertTrue(value["inclusion_observed"])
        self.assertTrue(value["execution_success"])
        self.assertTrue(value["settlement_observed"])
        self.assertFalse(value["realized_profit_claimed"])
        self.assertEqual(value["submission_authority"], "none")
        self.assertEqual(value["execution_authority"], "none")

    def test_receipt_must_contain_exactly_one_governed_settlement_event(self) -> None:
        package = f7_inclusion().package
        log = settlement_log(package)
        duplicate = inclusion_from_fixture(inclusion_fixture(settlement_logs=(log, log)))
        with self.assertRaisesRegex(ValueError, "exactly one"):
            outcome_from_inclusion(duplicate)
        unrelated = EvmLogEntry(
            address=bytes.fromhex("aa" * 20),
            topics=(bytes.fromhex("bb" * 32),),
            data=b"",
        )
        missing = inclusion_from_fixture(inclusion_fixture(settlement_logs=(unrelated,)))
        with self.assertRaisesRegex(ValueError, "exactly one"):
            outcome_from_inclusion(missing)

    def test_settlement_event_cannot_drift_plan_beneficiary_or_hard_payment_cap(self) -> None:
        package = f7_inclusion().package
        log = settlement_log(package)
        wrong_plan = replace(log, topics=(log.topics[0], bytes.fromhex("ee" * 32), *log.topics[2:]))
        with self.assertRaisesRegex(ValueError, "execution plan"):
            outcome_from_inclusion(inclusion_from_fixture(inclusion_fixture(settlement_logs=(wrong_plan,))))
        wrong_beneficiary = replace(
            log,
            topics=(log.topics[0], log.topics[1], bytes(12) + bytes.fromhex("ee" * 20), log.topics[3]),
        )
        with self.assertRaisesRegex(ValueError, "beneficiary"):
            outcome_from_inclusion(inclusion_from_fixture(inclusion_fixture(settlement_logs=(wrong_beneficiary,))))
        words = [int.from_bytes(log.data[i:i+32], "big") for i in range(0, len(log.data), 32)]
        words[4] += 1
        wrong_payment = replace(log, data=b"".join(item.to_bytes(32, "big") for item in words))
        with self.assertRaisesRegex(ValueError, "direct payment"):
            outcome_from_inclusion(inclusion_from_fixture(inclusion_fixture(settlement_logs=(wrong_payment,))))

    def test_successful_economic_drift_is_recorded_instead_of_dropped(self) -> None:
        package = f7_inclusion().package
        plan = package.unsigned_package.net_profit_evidence.plan
        actual_output = plan.opportunity.route_quote.amount_out - 100
        self.assertGreaterEqual(
            actual_output,
            package.unsigned_package.call.minimum_final_output,
        )
        drifted_log = settlement_log(
            package,
            gross_output=actual_output,
            direct_inclusion_payment=package.signed_transaction.unsigned_transaction.value - 1,
        )
        outcome = outcome_from_inclusion(
            inclusion_from_fixture(
                inclusion_fixture(settlement_logs=(drifted_log,))
            )
        )
        self.assertFalse(outcome.simulation_output_match)
        self.assertFalse(outcome.simulation_residual_match)
        self.assertFalse(outcome.simulation_direct_payment_match)
        self.assertFalse(outcome.simulation_economic_match)
        self.assertFalse(outcome.simulation_exact_match)
        self.assertTrue(outcome.cost_upper_bounds_respected)
        self.assertFalse(outcome.conservative_shadow_floor_preserved)
        self.assertEqual(
            outcome.base_token_residual_shortfall_before_external_costs,
            100,
        )
        value = outcome.to_json_value()
        self.assertFalse(value["conservative_shadow_floor_preserved"])
        self.assertEqual(
            value["planned_base_token_residual_before_external_costs"],
            str(plan.residual_before_external_costs),
        )
        self.assertEqual(
            value["realized_base_token_residual_before_external_costs"],
            str(plan.residual_before_external_costs - 100),
        )
        self.assertFalse(value["realized_profit_claimed"])

    def test_favorable_economic_drift_can_preserve_the_conservative_floor(self) -> None:
        package = f7_inclusion().package
        plan = package.unsigned_package.net_profit_evidence.plan
        favorable_log = settlement_log(
            package,
            gross_output=plan.opportunity.route_quote.amount_out + 100,
            direct_inclusion_payment=package.signed_transaction.unsigned_transaction.value - 1,
        )
        outcome = outcome_from_inclusion(
            inclusion_from_fixture(
                inclusion_fixture(settlement_logs=(favorable_log,))
            )
        )
        self.assertFalse(outcome.simulation_economic_match)
        self.assertFalse(outcome.simulation_exact_match)
        self.assertTrue(outcome.cost_upper_bounds_respected)
        self.assertTrue(outcome.conservative_shadow_floor_preserved)
        self.assertEqual(
            outcome.base_token_residual_shortfall_before_external_costs,
            0,
        )
        self.assertEqual(outcome.native_cost_overrun, 0)

    def test_settlement_spec_and_decoded_event_bind_value_semantics_and_exact_log(self) -> None:
        outcome = f7_outcome()
        with self.assertRaisesRegex(ValueError, "value semantics"):
            replace(outcome.settlement_spec, value_semantics="unmodeled-value-retention")
        with self.assertRaisesRegex(ValueError, "plan topic"):
            replace(
                outcome.settlement_event,
                plan_sha256="ee" * 32,
            )
        with self.assertRaisesRegex(ValueError, "topic0"):
            replace(
                outcome.settlement_event,
                log=replace(
                    outcome.settlement_event.log,
                    topics=(
                        bytes.fromhex("ee" * 32),
                        *outcome.settlement_event.log.topics[1:],
                    ),
                ),
            )
        self.assertEqual(
            outcome.settlement_event.log.topics[0],
            keccak256(SETTLEMENT_EVENT_SIGNATURE.encode("ascii")),
        )
        with self.assertRaisesRegex(ValueError, "log data"):
            replace(
                outcome.settlement_event,
                direct_inclusion_payment=0,
            )

    def test_actual_simulation_drift_is_reported_without_fabricating_profit(self) -> None:
        gas_drift = outcome_from_inclusion(
            inclusion_from_fixture(inclusion_fixture(target_gas_used=190_000))
        )
        self.assertFalse(gas_drift.simulation_gas_match)
        self.assertTrue(gas_drift.simulation_logs_match)
        self.assertFalse(gas_drift.simulation_exact_match)

        package = f7_inclusion().package
        extra = EvmLogEntry(
            address=bytes.fromhex("aa" * 20),
            topics=(bytes.fromhex("bb" * 32),),
            data=b"extra",
        )
        logs_drift = outcome_from_inclusion(
            inclusion_from_fixture(
                inclusion_fixture(settlement_logs=(settlement_log(package), extra))
            )
        )
        self.assertTrue(logs_drift.simulation_gas_match)
        self.assertFalse(logs_drift.simulation_logs_match)
        self.assertFalse(logs_drift.simulation_exact_match)

    def test_rollup_fee_and_settlement_registry_domains_fail_closed(self) -> None:
        inclusion = f7_inclusion()
        with self.assertRaisesRegex(ValueError, "Ethereum"):
            RecordedRollupFeeEvidence(
                inclusion.block.chain,
                inclusion.package.signed_transaction.transaction_hash,
                1,
                0,
                inclusion.created_at_unix_ms + 1,
                "bad-ethereum-fee",
                ROLLUP_FEE_SOURCE,
            )
        spec = settlement_spec(inclusion.package)
        overlap = replace(spec, spec_id="overlap")
        with self.assertRaisesRegex(ValueError, "overlapping"):
            ExecutorSettlementEventRegistry("bad", (spec, overlap))
        with self.assertRaisesRegex(ValueError, "empty-code"):
            replace(spec, spec_id="empty-code", runtime_code_hash=EMPTY_CODE_HASH)
        wrong_hash = replace(spec, spec_id="wrong-hash", runtime_code_hash=bytes.fromhex("ee" * 32))
        registry = ExecutorSettlementEventRegistry("wrong", (wrong_hash,))
        with self.assertRaisesRegex(ValueError, "does not resolve"):
            registry.resolve(spec.runtime_code_hash, inclusion.block.block_number)

    def test_outcome_identity_is_deterministic(self) -> None:
        first = f7_outcome()
        second = outcome_from_inclusion(f7_inclusion())
        self.assertEqual(first.digest, second.digest)
        self.assertEqual(first.outcome_id, second.outcome_id)


if __name__ == "__main__":
    unittest.main()
