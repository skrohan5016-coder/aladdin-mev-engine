from __future__ import annotations

from dataclasses import replace
import unittest

from aladdin_mev_engine.keccak import keccak256
from aladdin_mev_engine.rlp import rlp_decode
from aladdin_mev_engine.secp256k1 import GROUP_ORDER, HALF_GROUP_ORDER
from aladdin_mev_engine.signed_transaction import (
    Eip1559Signature,
    SignedEip1559TransactionEvidence,
    SignedPrivateBundleEvidence,
)

from f5_helpers import f5_bundle, f5_transaction
from f6_helpers import (
    EXPECTED_SENDER,
    SIGNATURE_SOURCE,
    deterministic_signature,
    f6_signed_bundle,
    f6_signed_transaction,
)


class SignedTransactionF6Tests(unittest.TestCase):
    def test_signature_is_low_s_and_contains_no_private_key(self) -> None:
        signature = f6_signed_transaction().signature
        self.assertLessEqual(signature.s, HALF_GROUP_ORDER)
        self.assertEqual(len(signature.signature_bytes), 65)
        value = signature.to_json_value()
        self.assertFalse(value["private_key_present"])
        self.assertNotIn("private_key", value)
        with self.assertRaisesRegex(ValueError, "low-s"):
            Eip1559Signature(
                signature.y_parity,
                signature.r,
                GROUP_ORDER - signature.s,
                signature.observed_at_unix_ms,
                signature.source_id,
                signature.source_sha256,
            )

    def test_signed_type_two_transaction_encoding_is_exact(self) -> None:
        signed = f6_signed_transaction()
        unsigned = signed.unsigned_transaction
        self.assertEqual(signed.raw_transaction[:1], b"\x02")
        decoded = rlp_decode(signed.raw_transaction[1:])
        self.assertIsInstance(decoded, tuple)
        assert isinstance(decoded, tuple)
        self.assertEqual(len(decoded), 12)
        self.assertEqual(decoded[0], unsigned.chain_id.to_bytes(1, "big"))
        self.assertEqual(decoded[1], unsigned.nonce.to_bytes(1, "big"))
        self.assertEqual(decoded[5], unsigned.to)
        self.assertEqual(decoded[7], unsigned.data)
        self.assertEqual(decoded[8], ())
        self.assertEqual(int.from_bytes(decoded[9], "big"), signed.signature.y_parity)
        self.assertEqual(int.from_bytes(decoded[10], "big"), signed.signature.r)
        self.assertEqual(int.from_bytes(decoded[11], "big"), signed.signature.s)
        self.assertEqual(signed.transaction_hash, keccak256(signed.raw_transaction))
        self.assertEqual(signed.recovered_sender, EXPECTED_SENDER)
        self.assertFalse(signed.to_json_value()["submission_eligible"])

    def test_wrong_key_and_expired_signature_fail_closed(self) -> None:
        unsigned = f5_transaction()
        wrong_signature = deterministic_signature(
            unsigned.signing_hash,
            private_key=3,
            nonce=17,
            observed_at_unix_ms=unsigned.created_at_unix_ms + 1,
        )
        with self.assertRaisesRegex(ValueError, "authenticated sender"):
            SignedEip1559TransactionEvidence(
                unsigned,
                wrong_signature,
                wrong_signature.observed_at_unix_ms + 1,
            )
        good = deterministic_signature(
            unsigned.signing_hash,
            observed_at_unix_ms=unsigned.inputs_valid_until_unix_ms,
        )
        with self.assertRaisesRegex(ValueError, "expired"):
            SignedEip1559TransactionEvidence(
                unsigned,
                good,
                unsigned.inputs_valid_until_unix_ms + 1,
            )

    def test_source_digest_changes_evidence_but_not_raw_transaction(self) -> None:
        base = f6_signed_transaction()
        alternate_signature = deterministic_signature(
            base.unsigned_transaction.signing_hash,
            source_id="second-external-observer",
            source_sha256="bb" * 32,
            observed_at_unix_ms=base.signature.observed_at_unix_ms,
        )
        alternate = SignedEip1559TransactionEvidence(
            base.unsigned_transaction,
            alternate_signature,
            base.created_at_unix_ms,
        )
        self.assertEqual(base.raw_transaction, alternate.raw_transaction)
        self.assertEqual(base.transaction_hash, alternate.transaction_hash)
        self.assertNotEqual(base.digest, alternate.digest)

    def test_tampered_signature_scalar_is_rejected(self) -> None:
        base = f6_signed_transaction()
        signature = base.signature
        tampered = replace(signature, r=(signature.r + 1) % GROUP_ORDER or 1)
        with self.assertRaisesRegex(ValueError, "authenticated sender"):
            SignedEip1559TransactionEvidence(
                base.unsigned_transaction,
                tampered,
                base.created_at_unix_ms,
            )

    def test_signed_bundle_binds_exact_unsigned_order_and_identity(self) -> None:
        bundle = f6_signed_bundle()
        self.assertEqual(bundle.unsigned_bundle.digest, f5_bundle().digest)
        self.assertEqual(bundle.transaction_hashes, (f6_signed_transaction().transaction_hash_hex,))
        self.assertFalse(bundle.to_json_value()["network_dispatched"])
        with self.assertRaisesRegex(ValueError, "count"):
            SignedPrivateBundleEvidence(
                unsigned_bundle=f5_bundle(),
                signed_transactions=(
                    f6_signed_transaction(),
                    f6_signed_transaction(),
                ),
                created_at_unix_ms=bundle.created_at_unix_ms,
            )


if __name__ == "__main__":
    unittest.main()
