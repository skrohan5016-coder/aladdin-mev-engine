from __future__ import annotations

import hashlib
import unittest

from aladdin_mev_engine.keccak import KECCAK_256_RATE_BYTES, keccak256


class KeccakTests(unittest.TestCase):
    def test_official_empty_and_abc_vectors(self) -> None:
        self.assertEqual(
            keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        self.assertEqual(
            keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )

    def test_openssl_cross_checked_boundary_vectors(self) -> None:
        vectors = {
            135: "37842a4806a4a3d4eaa4a1789235a5b66b5d1901bf8388cfc1a599b2286cb56f",
            136: "317e60199b8b3851917e74926b7690d755cd27cd50c4a5abb3075fe252b6de55",
            137: "4f17b9c92046ceb9694fbe867db52a6d0672ce2c2c720803be77258c62107c54",
            272: "2fe8d923d96d25f4f3edf77eadcae30e130c0bbe5cfb7771c74306c5dc2bd7d3",
        }
        for length, expected in vectors.items():
            payload = bytes((index * 131 + 17) % 256 for index in range(length))
            with self.subTest(length=length):
                self.assertEqual(keccak256(payload).hex(), expected)

    def test_keccak_is_not_nist_sha3(self) -> None:
        self.assertNotEqual(keccak256(b""), hashlib.sha3_256(b"").digest())
        self.assertNotEqual(keccak256(b"abc"), hashlib.sha3_256(b"abc").digest())

    def test_rate_boundaries_are_deterministic_and_distinct(self) -> None:
        values = [
            keccak256(b"a" * (KECCAK_256_RATE_BYTES - 1)),
            keccak256(b"a" * KECCAK_256_RATE_BYTES),
            keccak256(b"a" * (KECCAK_256_RATE_BYTES + 1)),
            keccak256(b"a" * (2 * KECCAK_256_RATE_BYTES)),
        ]
        self.assertEqual(len(set(values)), len(values))
        self.assertEqual(values, [
            keccak256(b"a" * (KECCAK_256_RATE_BYTES - 1)),
            keccak256(b"a" * KECCAK_256_RATE_BYTES),
            keccak256(b"a" * (KECCAK_256_RATE_BYTES + 1)),
            keccak256(b"a" * (2 * KECCAK_256_RATE_BYTES)),
        ])

    def test_requires_exact_bytes(self) -> None:
        for value in (bytearray(b"x"), memoryview(b"x"), "x"):
            with self.assertRaises(TypeError):
                keccak256(value)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
