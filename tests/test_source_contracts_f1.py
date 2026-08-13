from __future__ import annotations

import unittest

from aladdin_mev_engine.canonical import canonical_sha256
from aladdin_mev_engine.domain import Chain
from aladdin_mev_engine.source_contracts import (
    EventShape,
    Finality,
    ObservationKind,
    SOURCE_CONTRACTS,
    SourceContract,
    SourceKind,
    Transport,
    Visibility,
    get_source_contract,
    source_contract_set_digest,
)


def shape(
    kind: ObservationKind,
    finality: Finality,
    visibility: Visibility,
) -> EventShape:
    return EventShape(kind, finality, visibility)


def controls() -> tuple[EventShape, ...]:
    return (
        shape(ObservationKind.SOURCE_GAP, Finality.METADATA, Visibility.METADATA),
        shape(ObservationKind.SOURCE_HEARTBEAT, Finality.METADATA, Visibility.METADATA),
    )


class SourceContractTests(unittest.TestCase):
    def test_governed_registry_has_expected_evm_sources(self) -> None:
        self.assertEqual(
            set(SOURCE_CONTRACTS),
            {
                "ethereum-json-rpc",
                "ethereum-mev-share",
                "base-json-rpc",
                "base-flashblocks",
                "arbitrum-json-rpc",
                "arbitrum-sequencer-feed",
                "arbitrum-timeboost-auction",
                "bnb-json-rpc",
                "bnb-pbs-metadata",
            },
        )

    def test_contract_set_digest_is_sorted_and_deterministic(self) -> None:
        expected = canonical_sha256(
            [SOURCE_CONTRACTS[key].to_json_value() for key in sorted(SOURCE_CONTRACTS)]
        )
        self.assertEqual(source_contract_set_digest(), expected)
        self.assertEqual(len(expected), 64)

    def test_every_contract_is_recorded_input_only_and_has_controls(self) -> None:
        for contract in SOURCE_CONTRACTS.values():
            value = contract.to_json_value()
            self.assertEqual(value["network_authority"], "none-recorded-input-only")
            self.assertTrue(value["official_reference"].startswith("https://"))
            self.assertIn(ObservationKind.SOURCE_GAP, contract.event_kinds)
            self.assertIn(ObservationKind.SOURCE_HEARTBEAT, contract.event_kinds)

    def test_unknown_or_untyped_source_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            get_source_contract("unknown")
        with self.assertRaises(TypeError):
            get_source_contract(1)  # type: ignore[arg-type]

    def test_solana_has_no_accidental_f1_source_contract(self) -> None:
        self.assertNotIn(Chain.SOLANA, {contract.chain for contract in SOURCE_CONTRACTS.values()})

    def test_mev_share_models_exact_hint_shapes(self) -> None:
        contract = get_source_contract("ethereum-mev-share")
        for visibility in (Visibility.PARTIAL, Visibility.FULL, Visibility.HASH_ONLY):
            self.assertTrue(
                contract.permits(
                    kind=ObservationKind.TRANSACTION_HINT,
                    finality=Finality.PENDING,
                    visibility=visibility,
                )
            )
        self.assertFalse(
            contract.permits(
                kind=ObservationKind.BLOCK_HEAD,
                finality=Finality.CONFIRMED,
                visibility=Visibility.FULL,
            )
        )

    def test_event_shape_authority_is_not_a_cross_product(self) -> None:
        contract = get_source_contract("ethereum-json-rpc")
        self.assertTrue(
            contract.permits(
                kind=ObservationKind.BLOCK_HEAD,
                finality=Finality.CONFIRMED,
                visibility=Visibility.FULL,
            )
        )
        self.assertFalse(
            contract.permits(
                kind=ObservationKind.BLOCK_HEAD,
                finality=Finality.CONFIRMED,
                visibility=Visibility.HASH_ONLY,
            )
        )
        self.assertFalse(
            contract.permits(
                kind=ObservationKind.PENDING_TRANSACTION,
                finality=Finality.FINALIZED,
                visibility=Visibility.FULL,
            )
        )

    def test_base_flashblocks_are_preconfirmed_not_finalized(self) -> None:
        contract = get_source_contract("base-flashblocks")
        self.assertTrue(
            contract.permits(
                kind=ObservationKind.PRECONFIRMED_TRANSACTION,
                finality=Finality.PRECONFIRMED,
                visibility=Visibility.FULL,
            )
        )
        self.assertFalse(
            contract.permits(
                kind=ObservationKind.PRECONFIRMED_TRANSACTION,
                finality=Finality.FINALIZED,
                visibility=Visibility.FULL,
            )
        )

    def test_arbitrum_public_rpc_and_feed_have_distinct_authority(self) -> None:
        rpc = get_source_contract("arbitrum-json-rpc")
        feed = get_source_contract("arbitrum-sequencer-feed")
        self.assertIs(rpc.transport, Transport.JSON_RPC_HTTP)
        self.assertTrue(
            rpc.permits(
                kind=ObservationKind.BLOCK_HEAD,
                finality=Finality.CONFIRMED,
                visibility=Visibility.FULL,
            )
        )
        self.assertFalse(
            rpc.permits(
                kind=ObservationKind.PENDING_TRANSACTION,
                finality=Finality.PENDING,
                visibility=Visibility.FULL,
            )
        )
        self.assertTrue(
            feed.permits(
                kind=ObservationKind.SEQUENCER_BATCH,
                finality=Finality.PRECONFIRMED,
                visibility=Visibility.FULL,
            )
        )

    def test_allowed_event_shapes_must_be_sorted_unique_and_include_controls(self) -> None:
        common = dict(
            source_id="test-source",
            chain=Chain.ETHEREUM,
            source_kind=SourceKind.EVM_JSON_RPC,
            transport=Transport.JSON_RPC_WEBSOCKET,
            max_payload_bytes=100,
            max_future_clock_skew_ms=100,
            partial_payload_expected=False,
            official_reference="https://ethereum.org/",
        )
        unsorted = (
            *controls(),
            shape(ObservationKind.BLOCK_HEAD, Finality.CONFIRMED, Visibility.FULL),
        )
        with self.assertRaises(ValueError):
            SourceContract(allowed_events=unsorted, **common)
        duplicate = tuple(
            sorted(
                (*controls(), controls()[0]),
                key=lambda item: item.sort_key,
            )
        )
        with self.assertRaises(ValueError):
            SourceContract(allowed_events=duplicate, **common)
        missing_control = (
            shape(ObservationKind.BLOCK_HEAD, Finality.CONFIRMED, Visibility.FULL),
        )
        with self.assertRaises(ValueError):
            SourceContract(allowed_events=missing_control, **common)

    def test_contract_limits_and_partial_visibility_are_governed(self) -> None:
        allowed = tuple(
            sorted(
                (
                    *controls(),
                    shape(ObservationKind.BLOCK_HEAD, Finality.CONFIRMED, Visibility.FULL),
                ),
                key=lambda item: item.sort_key,
            )
        )
        common = dict(
            source_id="test-source",
            chain=Chain.ETHEREUM,
            source_kind=SourceKind.EVM_JSON_RPC,
            transport=Transport.JSON_RPC_WEBSOCKET,
            allowed_events=allowed,
            max_future_clock_skew_ms=100,
            official_reference="https://ethereum.org/",
        )
        with self.assertRaises(ValueError):
            SourceContract(max_payload_bytes=0, partial_payload_expected=False, **common)
        with self.assertRaises(ValueError):
            SourceContract(max_payload_bytes=100, partial_payload_expected=True, **common)

    def test_metadata_event_shapes_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            shape(ObservationKind.BLOCK_HEAD, Finality.METADATA, Visibility.METADATA)
        with self.assertRaises(ValueError):
            shape(ObservationKind.SOURCE_GAP, Finality.CONFIRMED, Visibility.FULL)
        with self.assertRaises(ValueError):
            shape(ObservationKind.TIMEBOOST_ROUND, Finality.METADATA, Visibility.FULL)

    def test_contract_digest_binds_semantics(self) -> None:
        contract = get_source_contract("arbitrum-timeboost-auction")
        changed = dict(contract.to_json_value())
        changed["max_future_clock_skew_ms"] = "1"
        self.assertNotEqual(contract.digest, canonical_sha256(changed))


if __name__ == "__main__":
    unittest.main()
