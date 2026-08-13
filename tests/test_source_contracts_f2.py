from __future__ import annotations

import unittest

from aladdin_mev_engine.observation import ObservationEnvelope
from aladdin_mev_engine.source_contracts import (
    Finality,
    ObservationKind,
    Visibility,
    get_source_contract,
    source_contract_set_digest,
)
from aladdin_mev_engine.state_proof import STATE_PROOF_PAYLOAD_SCHEMA


class SourceContractF2Tests(unittest.TestCase):
    def test_ethereum_and_base_allow_confirmed_and_finalized_state_proofs(self) -> None:
        for source_id in ("ethereum-json-rpc", "base-json-rpc"):
            contract = get_source_contract(source_id)
            for finality in (Finality.CONFIRMED, Finality.FINALIZED):
                self.assertTrue(
                    contract.permits(
                        kind=ObservationKind.EVM_STATE_PROOF,
                        finality=finality,
                        visibility=Visibility.FULL,
                    )
                )

    def test_arbitrum_and_bnb_do_not_claim_authenticated_mpt_proof_support(self) -> None:
        for source_id in ("arbitrum-json-rpc", "bnb-json-rpc"):
            contract = get_source_contract(source_id)
            for finality in (Finality.CONFIRMED, Finality.FINALIZED):
                self.assertFalse(
                    contract.permits(
                        kind=ObservationKind.EVM_STATE_PROOF,
                        finality=finality,
                        visibility=Visibility.FULL,
                    )
                )

    def test_all_evm_rpc_sources_can_record_block_state_roots(self) -> None:
        for source_id in (
            "ethereum-json-rpc",
            "base-json-rpc",
            "arbitrum-json-rpc",
            "bnb-json-rpc",
        ):
            contract = get_source_contract(source_id)
            self.assertTrue(
                contract.permits(
                    kind=ObservationKind.EVM_BLOCK_STATE,
                    finality=Finality.CONFIRMED,
                    visibility=Visibility.FULL,
                )
            )

    def test_pending_or_partial_state_proof_is_not_a_cross_product(self) -> None:
        contract = get_source_contract("ethereum-json-rpc")
        for finality, visibility in (
            (Finality.PENDING, Visibility.FULL),
            (Finality.CONFIRMED, Visibility.PARTIAL),
            (Finality.FINALIZED, Visibility.HASH_ONLY),
        ):
            self.assertFalse(
                contract.permits(
                    kind=ObservationKind.EVM_STATE_PROOF,
                    finality=finality,
                    visibility=visibility,
                )
            )

    def test_unsupported_source_fails_before_proof_payload_is_accepted(self) -> None:
        with self.assertRaisesRegex(ValueError, "not permitted"):
            ObservationEnvelope.create(
                source_id="bnb-json-rpc",
                source_sequence=0,
                source_event_id="proof",
                observed_at_unix_ms=1,
                emitted_at_unix_ms=1,
                kind=ObservationKind.EVM_STATE_PROOF,
                finality=Finality.CONFIRMED,
                visibility=Visibility.FULL,
                payload={"schema": STATE_PROOF_PAYLOAD_SCHEMA},
            )

    def test_source_contract_set_digest_is_stable(self) -> None:
        digest = source_contract_set_digest()
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, source_contract_set_digest())


if __name__ == "__main__":
    unittest.main()
