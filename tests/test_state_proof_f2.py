from __future__ import annotations

import copy
import unittest

from aladdin_mev_engine.evm_hex import to_hex_data
from aladdin_mev_engine.keccak import keccak256
from aladdin_mev_engine.mpt import EMPTY_TRIE_ROOT
from aladdin_mev_engine.observation import ObservationEnvelope
from aladdin_mev_engine.rlp import rlp_encode
from aladdin_mev_engine.source_contracts import Finality, ObservationKind, Visibility
from aladdin_mev_engine.state_proof import (
    BLOCK_STATE_PAYLOAD_SCHEMA,
    EMPTY_CODE_HASH,
    EvmBlockStateAnchor,
    EvmStateProofEvidence,
    EvmStateSnapshot,
    VerifiedStorageValue,
)

from f2_helpers import (
    empty_account_payload,
    head_observation,
    proof_fixture,
    proof_observation,
    proof_payload,
    single_leaf_trie,
    state_observation,
    uint_bytes,
)


class StateProofTests(unittest.TestCase):
    def test_account_and_storage_inclusion_are_authenticated(self) -> None:
        fixture = proof_fixture()
        anchor = EvmBlockStateAnchor.from_observations(
            head_observation(fixture),
            state_observation(fixture),
        )
        evidence = EvmStateProofEvidence.verify(anchor, proof_observation(fixture))
        self.assertTrue(evidence.account_exists)
        self.assertEqual(evidence.nonce, fixture.nonce)
        self.assertEqual(evidence.balance, fixture.balance)
        self.assertEqual(evidence.storage_root, fixture.storage_root)
        self.assertEqual(len(evidence.storage_values), 1)
        self.assertTrue(evidence.storage_values[0].included)
        self.assertEqual(evidence.storage_values[0].value, fixture.storage_value)
        self.assertEqual(len(evidence.digest), 64)
        self.assertEqual(evidence.digest, EvmStateProofEvidence.verify(
            anchor, proof_observation(fixture)
        ).digest)

    def test_base_uses_the_same_offline_proof_authority(self) -> None:
        fixture = proof_fixture(source_id="base-json-rpc", finality=Finality.FINALIZED)
        anchor = EvmBlockStateAnchor.from_observations(
            head_observation(fixture),
            state_observation(fixture),
        )
        evidence = EvmStateProofEvidence.verify(anchor, proof_observation(fixture))
        self.assertEqual(evidence.chain.value, "base")
        self.assertEqual(evidence.finality, Finality.FINALIZED)

    def test_empty_account_and_storage_non_inclusion(self) -> None:
        fixture = proof_fixture()
        address = bytes.fromhex("44" * 20)
        storage_key = bytes.fromhex("00" * 31 + "02")
        empty_fixture = fixture.__class__(
            **{
                **fixture.__dict__,
                "address": address,
                "storage_key": storage_key,
                "nonce": 0,
                "balance": 0,
                "code_hash": EMPTY_CODE_HASH,
                "storage_root": EMPTY_TRIE_ROOT,
                "state_root": EMPTY_TRIE_ROOT,
                "account_node": b"",
                "storage_node": b"",
                "storage_value": 0,
            }
        )
        anchor = EvmBlockStateAnchor.from_observations(
            head_observation(empty_fixture),
            state_observation(empty_fixture),
        )
        payload = empty_account_payload(
            block_number=empty_fixture.block_number,
            block_hash=empty_fixture.block_hash,
            address=address,
            storage_key=storage_key,
        )
        evidence = EvmStateProofEvidence.verify(
            anchor,
            proof_observation(empty_fixture, payload=payload),
        )
        self.assertFalse(evidence.account_exists)
        self.assertFalse(evidence.storage_values[0].included)
        self.assertEqual(evidence.storage_values[0].value, 0)

    def test_nonempty_storage_trie_can_prove_an_absent_slot(self) -> None:
        fixture = proof_fixture()
        missing_key = bytes.fromhex("00" * 31 + "02")
        payload = proof_payload(fixture)
        payload["storage_proofs"] = [
            {
                "key": to_hex_data(missing_key),
                "value": "0",
                "proof": [to_hex_data(fixture.storage_node)],
            }
        ]
        anchor = EvmBlockStateAnchor.from_observations(
            head_observation(fixture),
            state_observation(fixture),
        )
        evidence = EvmStateProofEvidence.verify(
            anchor,
            proof_observation(fixture, payload=payload),
        )
        self.assertFalse(evidence.storage_values[0].included)
        self.assertEqual(evidence.storage_values[0].value, 0)

    def test_block_state_anchor_rejects_cross_stream_and_identity_mismatch(self) -> None:
        fixture = proof_fixture()
        head = head_observation(fixture)
        state = state_observation(fixture)
        wrong_payload = dict(state.payload)
        wrong_payload["block_hash"] = "0x" + "ef" * 32
        wrong_state = ObservationEnvelope.create(
            source_id=fixture.source_id,
            source_sequence=11,
            source_event_id="wrong-state",
            observed_at_unix_ms=1_800_000_000_010,
            emitted_at_unix_ms=1_800_000_000_010,
            kind=ObservationKind.EVM_BLOCK_STATE,
            finality=fixture.finality,
            visibility=Visibility.FULL,
            payload=wrong_payload,
        )
        with self.assertRaisesRegex(ValueError, "recorded head"):
            EvmBlockStateAnchor.from_observations(head, wrong_state)
        with self.assertRaisesRegex(ValueError, "follow"):
            EvmBlockStateAnchor.from_observations(
                head,
                state_observation(fixture, sequence=10),
            )

    def test_proof_must_bind_exact_anchor_and_follow_it(self) -> None:
        fixture = proof_fixture()
        anchor = EvmBlockStateAnchor.from_observations(
            head_observation(fixture),
            state_observation(fixture),
        )
        payload = proof_payload(fixture)
        payload["state_root"] = "0x" + "99" * 32
        with self.assertRaisesRegex(ValueError, "exact block-state anchor"):
            EvmStateProofEvidence.verify(
                anchor,
                proof_observation(fixture, payload=payload),
            )
        with self.assertRaisesRegex(ValueError, "follow"):
            EvmStateProofEvidence.verify(
                anchor,
                proof_observation(fixture, sequence=11),
            )

    def test_account_field_tampering_is_rejected(self) -> None:
        fixture = proof_fixture()
        anchor = EvmBlockStateAnchor.from_observations(
            head_observation(fixture),
            state_observation(fixture),
        )
        for field, value in (
            ("nonce", str(fixture.nonce + 1)),
            ("balance", str(fixture.balance + 1)),
            ("storage_root", "0x" + "11" * 32),
            ("code_hash", "0x" + "22" * 32),
        ):
            payload = proof_payload(fixture)
            payload[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "account fields"):
                    EvmStateProofEvidence.verify(
                        anchor,
                        proof_observation(fixture, payload=payload),
                    )

    def test_account_node_tampering_and_wrong_root_are_rejected(self) -> None:
        fixture = proof_fixture()
        anchor = EvmBlockStateAnchor.from_observations(
            head_observation(fixture),
            state_observation(fixture),
        )
        payload = proof_payload(fixture)
        tampered = fixture.account_node[:-1] + bytes((fixture.account_node[-1] ^ 1,))
        payload["account_proof"] = [to_hex_data(tampered)]
        with self.assertRaises(ValueError):
            EvmStateProofEvidence.verify(
                anchor,
                proof_observation(fixture, payload=payload),
            )

    def test_storage_value_tampering_is_rejected(self) -> None:
        fixture = proof_fixture()
        anchor = EvmBlockStateAnchor.from_observations(
            head_observation(fixture),
            state_observation(fixture),
        )
        payload = proof_payload(fixture)
        payload["storage_proofs"][0]["value"] = str(fixture.storage_value + 1)  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "storage value"):
            EvmStateProofEvidence.verify(
                anchor,
                proof_observation(fixture, payload=payload),
            )

    def test_zero_storage_value_must_be_non_inclusion(self) -> None:
        fixture = proof_fixture(storage_value=0)
        anchor = EvmBlockStateAnchor.from_observations(
            head_observation(fixture),
            state_observation(fixture),
        )
        with self.assertRaisesRegex(ValueError, "must not include a zero"):
            EvmStateProofEvidence.verify(anchor, proof_observation(fixture))

    def test_absent_account_cannot_claim_nonempty_fields(self) -> None:
        fixture = proof_fixture()
        empty_fixture = fixture.__class__(
            **{
                **fixture.__dict__,
                "state_root": EMPTY_TRIE_ROOT,
                "storage_root": EMPTY_TRIE_ROOT,
                "code_hash": EMPTY_CODE_HASH,
                "nonce": 0,
                "balance": 0,
                "account_node": b"",
                "storage_node": b"",
                "storage_value": 0,
            }
        )
        payload = empty_account_payload(
            block_number=empty_fixture.block_number,
            block_hash=empty_fixture.block_hash,
            address=empty_fixture.address,
            storage_key=empty_fixture.storage_key,
        )
        payload["balance"] = "1"
        anchor = EvmBlockStateAnchor.from_observations(
            head_observation(empty_fixture),
            state_observation(empty_fixture),
        )
        with self.assertRaisesRegex(ValueError, "absent account"):
            EvmStateProofEvidence.verify(
                anchor,
                proof_observation(empty_fixture, payload=payload),
            )

    def test_duplicate_storage_keys_fail_at_verification(self) -> None:
        fixture = proof_fixture()
        payload = proof_payload(fixture)
        first = copy.deepcopy(payload["storage_proofs"][0])  # type: ignore[index]
        payload["storage_proofs"] = [first, copy.deepcopy(first)]
        anchor = EvmBlockStateAnchor.from_observations(
            head_observation(fixture),
            state_observation(fixture),
        )
        with self.assertRaisesRegex(ValueError, "unique and sorted"):
            EvmStateProofEvidence.verify(
                anchor,
                proof_observation(fixture, payload=payload),
            )

    def test_unknown_fields_noncanonical_hex_and_decimals_fail(self) -> None:
        fixture = proof_fixture()
        anchor = EvmBlockStateAnchor.from_observations(
            head_observation(fixture),
            state_observation(fixture),
        )
        mutations = []
        extra = proof_payload(fixture)
        extra["unexpected"] = "x"
        mutations.append(extra)
        upper = proof_payload(fixture)
        upper["address"] = "0x" + "AB" * 20
        mutations.append(upper)
        leading = proof_payload(fixture)
        leading["nonce"] = "07"
        mutations.append(leading)
        for payload in mutations:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    EvmStateProofEvidence.verify(
                        anchor,
                        proof_observation(fixture, payload=payload),
                    )

    def test_evidence_constructor_recomputes_from_bound_inputs(self) -> None:
        fixture = proof_fixture()
        anchor = EvmBlockStateAnchor(
            head_observation=head_observation(fixture),
            state_observation=state_observation(fixture),
        )
        proof = proof_observation(fixture)
        evidence = EvmStateProofEvidence(anchor=anchor, proof_observation=proof)
        self.assertEqual(evidence, EvmStateProofEvidence.verify(anchor, proof))
        self.assertEqual(evidence.proof_source_sequence, proof.source_sequence)
        self.assertEqual(
            evidence.proof_observed_at_unix_ms,
            proof.observed_at_unix_ms,
        )

    def test_proof_time_must_not_precede_block_state_anchor(self) -> None:
        fixture = proof_fixture()
        anchor = EvmBlockStateAnchor.from_observations(
            head_observation(fixture),
            state_observation(fixture),
        )
        early = ObservationEnvelope.create(
            source_id=fixture.source_id,
            source_sequence=12,
            source_event_id="early-proof",
            observed_at_unix_ms=1_800_000_000_009,
            emitted_at_unix_ms=1_800_000_000_009,
            kind=ObservationKind.EVM_STATE_PROOF,
            finality=fixture.finality,
            visibility=Visibility.FULL,
            payload=proof_payload(fixture),
        )
        with self.assertRaisesRegex(ValueError, "time precedes"):
            EvmStateProofEvidence.verify(anchor, early)

    def test_zero_block_or_state_root_is_rejected_by_anchor(self) -> None:
        fixture = proof_fixture()
        head = head_observation(fixture)
        for field in ("block_hash", "state_root"):
            payload = dict(state_observation(fixture).payload)
            payload[field] = "0x" + "00" * 32
            state = ObservationEnvelope.create(
                source_id=fixture.source_id,
                source_sequence=11,
                source_event_id=f"zero-{field}",
                observed_at_unix_ms=1_800_000_000_010,
                emitted_at_unix_ms=1_800_000_000_010,
                kind=ObservationKind.EVM_BLOCK_STATE,
                finality=fixture.finality,
                visibility=Visibility.FULL,
                payload=payload,
            )
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "cannot be zero"):
                    EvmBlockStateAnchor.from_observations(head, state)

    def test_storage_terminal_semantics_fail_closed(self) -> None:
        from aladdin_mev_engine.mpt import MptTerminal

        with self.assertRaisesRegex(ValueError, "included/terminal"):
            VerifiedStorageValue(
                key=bytes(32),
                value=1,
                included=True,
                terminal=MptTerminal.ABSENT_BRANCH_CHILD,
                used_node_hashes=("1" * 64,),
            )

    def test_snapshot_is_deterministic_and_exact_anchor_bound(self) -> None:
        fixture = proof_fixture()
        anchor = EvmBlockStateAnchor.from_observations(
            head_observation(fixture),
            state_observation(fixture),
        )
        evidence = EvmStateProofEvidence.verify(anchor, proof_observation(fixture))
        snapshot = EvmStateSnapshot.create(anchor, (evidence,))
        self.assertEqual(len(snapshot.digest), 64)
        self.assertEqual(snapshot.digest, EvmStateSnapshot(anchor, (evidence,)).digest)

        other = proof_fixture()
        other_state_payload = dict(state_observation(other).payload)
        other_state_payload["state_root"] = to_hex_data(EMPTY_TRIE_ROOT)
        other_state = ObservationEnvelope.create(
            source_id=other.source_id,
            source_sequence=11,
            source_event_id="other-state",
            observed_at_unix_ms=1_800_000_000_010,
            emitted_at_unix_ms=1_800_000_000_010,
            kind=ObservationKind.EVM_BLOCK_STATE,
            finality=other.finality,
            visibility=Visibility.FULL,
            payload=other_state_payload,
        )
        other_anchor = EvmBlockStateAnchor.from_observations(
            head_observation(other),
            other_state,
        )
        with self.assertRaisesRegex(ValueError, "exact anchor"):
            EvmStateSnapshot(other_anchor, (evidence,))

    def test_snapshot_rejects_duplicate_account_evidence(self) -> None:
        fixture = proof_fixture()
        anchor = EvmBlockStateAnchor.from_observations(
            head_observation(fixture),
            state_observation(fixture),
        )
        evidence = EvmStateProofEvidence.verify(anchor, proof_observation(fixture))
        with self.assertRaisesRegex(ValueError, "unique and sorted"):
            EvmStateSnapshot(anchor, (evidence, evidence))


if __name__ == "__main__":
    unittest.main()
