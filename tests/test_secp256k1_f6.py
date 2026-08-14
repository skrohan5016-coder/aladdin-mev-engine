from __future__ import annotations

import random
import unittest

from aladdin_mev_engine.keccak import keccak256
from aladdin_mev_engine.secp256k1 import (
    FIELD_MODULUS,
    GENERATOR,
    GROUP_ORDER,
    Secp256k1Point,
    lift_x,
    public_key_to_address,
    recover_addresses,
    recover_public_keys,
    scalar_multiply,
    verify_signature,
)

from f6_helpers import (
    EXPECTED_SENDER,
    deterministic_signature,
    expected_sender_from_private_key,
)


class Secp256k1F6Tests(unittest.TestCase):
    def test_known_private_key_one_ethereum_address_vector(self) -> None:
        point = scalar_multiply(1, GENERATOR)
        self.assertIsNotNone(point)
        assert point is not None
        self.assertEqual(
            public_key_to_address(point).hex(),
            "7e5f4552091a69125d5dfcb7b8c2659029395bdf",
        )
        self.assertEqual(expected_sender_from_private_key(), EXPECTED_SENDER)

    def test_group_order_maps_generator_to_infinity(self) -> None:
        self.assertIsNone(scalar_multiply(GROUP_ORDER, GENERATOR))
        self.assertIsNone(scalar_multiply(0, GENERATOR))

    def test_curve_validation_and_x_lift(self) -> None:
        self.assertEqual(lift_x(GENERATOR.x, GENERATOR.y & 1), GENERATOR)
        self.assertEqual(lift_x(GENERATOR.x, 1 - (GENERATOR.y & 1)).x, GENERATOR.x)
        with self.assertRaisesRegex(ValueError, "not on the curve"):
            Secp256k1Point(1, 1)
        with self.assertRaisesRegex(ValueError, "field"):
            lift_x(FIELD_MODULUS, 0)

    def test_deterministic_signature_verifies_and_recovers(self) -> None:
        message_hash = keccak256(b"f6 deterministic signature")
        signature = deterministic_signature(message_hash)
        public_key = scalar_multiply(2, GENERATOR)
        self.assertIsNotNone(public_key)
        assert public_key is not None
        self.assertTrue(verify_signature(message_hash, signature.r, signature.s, public_key))
        self.assertIn(public_key, recover_public_keys(message_hash, signature.r, signature.s, signature.y_parity))
        self.assertEqual(
            tuple(item for item in recover_addresses(message_hash, signature.r, signature.s, signature.y_parity) if item == EXPECTED_SENDER),
            (EXPECTED_SENDER,),
        )

    def test_wrong_hash_or_public_key_does_not_verify(self) -> None:
        message_hash = keccak256(b"f6 correct")
        signature = deterministic_signature(message_hash)
        public_key = scalar_multiply(2, GENERATOR)
        wrong_key = scalar_multiply(3, GENERATOR)
        assert public_key is not None and wrong_key is not None
        self.assertFalse(verify_signature(keccak256(b"f6 wrong"), signature.r, signature.s, public_key))
        self.assertFalse(verify_signature(message_hash, signature.r, signature.s, wrong_key))

    def test_randomized_test_only_signature_round_trips(self) -> None:
        rng = random.Random(0xF6ECDA)
        for index in range(24):
            private_key = rng.randrange(1, GROUP_ORDER)
            nonce = rng.randrange(1, GROUP_ORDER)
            message_hash = keccak256(index.to_bytes(4, "big") + rng.randbytes(32))
            signature = deterministic_signature(
                message_hash,
                private_key=private_key,
                nonce=nonce,
                source_id=f"test-signer-{index}",
                source_sha256=f"{index + 1:064x}",
                observed_at_unix_ms=1_800_000_000_000 + index,
            )
            public_key = scalar_multiply(private_key, GENERATOR)
            assert public_key is not None
            address = public_key_to_address(public_key)
            self.assertTrue(verify_signature(message_hash, signature.r, signature.s, public_key))
            self.assertIn(address, recover_addresses(message_hash, signature.r, signature.s, signature.y_parity))


if __name__ == "__main__":
    unittest.main()
