from __future__ import annotations

from dataclasses import replace
import random
import unittest

from aladdin_mev_engine.canonical import canonical_sha256
from aladdin_mev_engine.evm_receipt import (
    EvmLogEntry,
    EvmTransactionReceipt,
    canonical_logs_sha256,
    compute_logs_bloom,
)
from aladdin_mev_engine.rlp import rlp_encode

from f7_helpers import encode_receipt


class EvmReceiptF7Tests(unittest.TestCase):
    def test_typed_receipt_round_trip_bloom_and_log_digest_are_exact(self) -> None:
        log = EvmLogEntry(
            address=bytes.fromhex("11" * 20),
            topics=(bytes.fromhex("22" * 32), bytes.fromhex("33" * 32)),
            data=b"f7-settlement",
        )
        raw = encode_receipt(cumulative_gas_used=123_456, logs=(log,))
        receipt = EvmTransactionReceipt.decode(raw)
        self.assertEqual(receipt.transaction_type, 2)
        self.assertTrue(receipt.success)
        self.assertEqual(receipt.cumulative_gas_used, 123_456)
        self.assertEqual(receipt.logs_bloom, compute_logs_bloom((log,)))
        self.assertEqual(receipt.logs_sha256, canonical_logs_sha256((log,)))
        self.assertEqual(receipt.raw_receipt, raw)

    def test_legacy_receipt_is_decoded_without_claiming_type_two(self) -> None:
        bloom = bytes(256)
        raw = rlp_encode((b"\x01", b"\x52\x08", bloom, ()))
        receipt = EvmTransactionReceipt.decode(raw)
        self.assertIsNone(receipt.transaction_type)
        self.assertEqual(receipt.cumulative_gas_used, 21_000)

    def test_bloom_matches_independent_byte_index_reference(self) -> None:
        log = EvmLogEntry(
            address=bytes.fromhex("12" * 20),
            topics=(bytes.fromhex("34" * 32), bytes.fromhex("56" * 32)),
            data=b"independent-bloom-vector",
        )
        expected = bytearray(256)
        from aladdin_mev_engine.keccak import keccak256

        for value in (log.address, *log.topics):
            digest = keccak256(value)
            for offset in (0, 2, 4):
                bit = int.from_bytes(digest[offset : offset + 2], "big") & 2047
                expected[255 - bit // 8] |= 1 << (bit % 8)
        self.assertEqual(compute_logs_bloom((log,)), bytes(expected))

    def test_bloom_tampering_fails_closed(self) -> None:
        log = EvmLogEntry(
            address=bytes.fromhex("44" * 20),
            topics=(bytes.fromhex("55" * 32),),
            data=b"",
        )
        raw = encode_receipt(cumulative_gas_used=30_000, logs=(log,))
        receipt = EvmTransactionReceipt.decode(raw)
        with self.assertRaisesRegex(ValueError, "bloom"):
            replace(receipt, logs_bloom=bytes(256))

    def test_status_and_typed_envelope_domains_are_closed(self) -> None:
        bloom = bytes(256)
        with self.assertRaisesRegex(ValueError, "status"):
            EvmTransactionReceipt.decode(bytes((2,)) + rlp_encode((b"\x02", b"\x01", bloom, ())))
        with self.assertRaisesRegex(ValueError, "type zero"):
            EvmTransactionReceipt.decode(b"\x00" + rlp_encode((b"\x01", b"\x01", bloom, ())))
        with self.assertRaisesRegex(ValueError, "missing"):
            EvmTransactionReceipt.decode(b"\x02")

    def test_log_address_topic_and_data_contracts_fail_closed(self) -> None:
        # Consensus receipts encode a Bytes20 log address and do not impose the
        # non-zero identity rule used for governed deployments or tokens.
        self.assertEqual(EvmLogEntry(bytes(20), (), b"").address, bytes(20))
        with self.assertRaisesRegex(ValueError, "address"):
            EvmLogEntry(bytes(19), (), b"")
        with self.assertRaisesRegex(ValueError, "topic count"):
            EvmLogEntry(bytes.fromhex("11" * 20), (bytes(32),) * 5, b"")
        with self.assertRaisesRegex(ValueError, "topics"):
            EvmLogEntry(bytes.fromhex("11" * 20), (bytes(31),), b"")
        with self.assertRaisesRegex(ValueError, "byte ceiling"):
            EvmLogEntry(bytes.fromhex("11" * 20), (), bytes(262_145))

    def test_randomized_typed_receipts_round_trip_exactly(self) -> None:
        rng = random.Random(0xF7EC31)
        for _ in range(128):
            logs = tuple(
                EvmLogEntry(
                    address=rng.randbytes(20),
                    topics=tuple(rng.randbytes(32) for _ in range(rng.randrange(5))),
                    data=rng.randbytes(rng.randrange(65)),
                )
                for _ in range(rng.randrange(5))
            )
            status = rng.randrange(2)
            cumulative = rng.randrange(1, 10_000_000)
            raw = encode_receipt(
                cumulative_gas_used=cumulative,
                logs=logs,
                status=status,
            )
            receipt = EvmTransactionReceipt.decode(raw)
            self.assertEqual(receipt.transaction_type, 2)
            self.assertEqual(receipt.status, status)
            self.assertEqual(receipt.cumulative_gas_used, cumulative)
            self.assertEqual(receipt.logs, logs)
            self.assertEqual(receipt.logs_bloom, compute_logs_bloom(logs))
            self.assertEqual(receipt.raw_receipt, raw)

    def test_receipt_decoder_rejects_topic_count_before_materializing_entries(self) -> None:
        address = bytes.fromhex("11" * 20)
        topics = (bytes(32),) * 5
        bloom = bytes(256)
        raw = bytes((2,)) + rlp_encode((b"\x01", b"\x01", bloom, ((address, topics, b""),)))
        with self.assertRaisesRegex(ValueError, "topic count"):
            EvmTransactionReceipt.decode(raw)

    def test_canonical_log_digest_enforces_receipt_log_count_ceiling(self) -> None:
        log = EvmLogEntry(bytes(20), (), b"")
        with self.assertRaisesRegex(ValueError, "log count"):
            canonical_logs_sha256((log,) * 1025)

    def test_canonical_log_digest_is_exact_and_aggregate_byte_bounded(self) -> None:
        small = (
            EvmLogEntry(bytes.fromhex("11" * 20), (), b"one"),
            EvmLogEntry(bytes.fromhex("22" * 20), (bytes.fromhex("33" * 32),), b"two"),
        )
        self.assertEqual(
            canonical_logs_sha256(small),
            canonical_sha256([item.to_json_value() for item in small]),
        )
        large = EvmLogEntry(bytes(20), (), bytes(262_144))
        with self.assertRaisesRegex(ValueError, "canonical receipt log array"):
            canonical_logs_sha256((large, large))

    def test_raw_receipt_must_reencode_exactly(self) -> None:
        raw = encode_receipt(cumulative_gas_used=21_000, logs=())
        receipt = EvmTransactionReceipt.decode(raw)
        with self.assertRaisesRegex(ValueError, "canonical receipt fields"):
            replace(receipt, raw_receipt=raw + b"\x00")


if __name__ == "__main__":
    unittest.main()
