from __future__ import annotations

import unittest

from aladdin_mev_engine.keccak import keccak256
from aladdin_mev_engine.mpt import (
    EMPTY_TRIE_ROOT,
    MptTerminal,
    bytes_to_nibbles,
    hex_prefix_decode,
    hex_prefix_encode,
    verify_mpt_proof,
)
from aladdin_mev_engine.rlp import rlp_encode


class MptTests(unittest.TestCase):
    def test_hex_prefix_round_trip_even_odd_leaf_extension(self) -> None:
        for path in ((), (1,), (1, 2), tuple(range(16))):
            for is_leaf in (False, True):
                if not path and not is_leaf:
                    continue
                encoded = hex_prefix_encode(path, is_leaf=is_leaf)
                self.assertEqual(hex_prefix_decode(encoded), (is_leaf, path))

    def test_hex_prefix_rejects_bad_flags_and_even_padding(self) -> None:
        with self.assertRaises(ValueError):
            hex_prefix_decode(b"\x40")
        with self.assertRaises(ValueError):
            hex_prefix_decode(b"\x01")
        with self.assertRaises(ValueError):
            hex_prefix_decode(b"")

    def test_single_leaf_inclusion(self) -> None:
        key = bytes.fromhex("11" * 32)
        leaf = rlp_encode(
            (hex_prefix_encode(bytes_to_nibbles(key), is_leaf=True), b"value")
        )
        result = verify_mpt_proof(
            root_hash=keccak256(leaf),
            key=key,
            proof_nodes=(leaf,),
        )
        self.assertTrue(result.found)
        self.assertEqual(result.value, b"value")
        self.assertEqual(result.terminal, MptTerminal.FOUND_LEAF)

    def test_single_leaf_path_divergence_proves_absence(self) -> None:
        existing = bytes.fromhex("11" * 32)
        requested = bytes.fromhex("12" + "11" * 31)
        leaf = rlp_encode(
            (hex_prefix_encode(bytes_to_nibbles(existing), is_leaf=True), b"value")
        )
        result = verify_mpt_proof(
            root_hash=keccak256(leaf),
            key=requested,
            proof_nodes=(leaf,),
        )
        self.assertFalse(result.found)
        self.assertEqual(result.terminal, MptTerminal.ABSENT_PATH_DIVERGENCE)

    def test_empty_trie_is_exact_non_inclusion(self) -> None:
        result = verify_mpt_proof(
            root_hash=EMPTY_TRIE_ROOT,
            key=b"anything",
            proof_nodes=(),
        )
        self.assertFalse(result.found)
        self.assertEqual(result.terminal, MptTerminal.ABSENT_EMPTY_TRIE)
        with self.assertRaises(ValueError):
            verify_mpt_proof(
                root_hash=EMPTY_TRIE_ROOT,
                key=b"anything",
                proof_nodes=(rlp_encode(b""),),
            )

    def test_hashed_branch_and_leaf_traversal(self) -> None:
        key = bytes.fromhex("ab")
        nibbles = bytes_to_nibbles(key)
        leaf = rlp_encode(
            (hex_prefix_encode((nibbles[1],), is_leaf=True), b"payload" * 8)
        )
        branch = [b""] * 17
        branch[nibbles[0]] = keccak256(leaf)
        branch_node = rlp_encode(tuple(branch))
        result = verify_mpt_proof(
            root_hash=keccak256(branch_node),
            key=key,
            proof_nodes=(branch_node, leaf),
        )
        self.assertEqual(result.value, b"payload" * 8)
        self.assertEqual(len(result.used_node_hashes), 2)

    def test_embedded_child_is_bound_without_redundant_proof_node(self) -> None:
        key = bytes.fromhex("ab")
        nibbles = bytes_to_nibbles(key)
        leaf_value = (
            hex_prefix_encode((nibbles[1],), is_leaf=True),
            b"x",
        )
        leaf = rlp_encode(leaf_value)
        self.assertLess(len(leaf), 32)
        branch = [b""] * 17
        branch[nibbles[0]] = leaf_value
        branch_node = rlp_encode(tuple(branch))
        result = verify_mpt_proof(
            root_hash=keccak256(branch_node),
            key=key,
            proof_nodes=(branch_node,),
        )
        self.assertEqual(result.value, b"x")
        with self.assertRaisesRegex(ValueError, "canonical traversal"):
            verify_mpt_proof(
                root_hash=keccak256(branch_node),
                key=key,
                proof_nodes=(branch_node, leaf),
            )

    def test_short_byte_string_is_not_an_embedded_reference(self) -> None:
        key = bytes.fromhex("ab")
        nibbles = bytes_to_nibbles(key)
        leaf = rlp_encode(
            (hex_prefix_encode((nibbles[1],), is_leaf=True), b"x")
        )
        branch = [b""] * 17
        branch[nibbles[0]] = leaf
        branch_node = rlp_encode(tuple(branch))
        with self.assertRaisesRegex(ValueError, "embedded RLP list"):
            verify_mpt_proof(
                root_hash=keccak256(branch_node),
                key=key,
                proof_nodes=(branch_node,),
            )

    def test_oversized_nested_node_cannot_be_embedded(self) -> None:
        key = bytes.fromhex("ab")
        nibbles = bytes_to_nibbles(key)
        oversized_leaf = (
            hex_prefix_encode((nibbles[1],), is_leaf=True),
            b"z" * 40,
        )
        self.assertGreaterEqual(len(rlp_encode(oversized_leaf)), 32)
        branch = [b""] * 17
        branch[nibbles[0]] = oversized_leaf
        branch_node = rlp_encode(tuple(branch))
        with self.assertRaisesRegex(ValueError, "oversized embedded"):
            verify_mpt_proof(
                root_hash=keccak256(branch_node),
                key=key,
                proof_nodes=(branch_node,),
            )

    def test_extension_traversal_and_absence(self) -> None:
        key = bytes.fromhex("abcd")
        nibbles = bytes_to_nibbles(key)
        leaf = rlp_encode(
            (hex_prefix_encode(nibbles[2:], is_leaf=True), b"z" * 40)
        )
        extension = rlp_encode(
            (hex_prefix_encode(nibbles[:2], is_leaf=False), keccak256(leaf))
        )
        result = verify_mpt_proof(
            root_hash=keccak256(extension),
            key=key,
            proof_nodes=(extension, leaf),
        )
        self.assertEqual(result.value, b"z" * 40)
        missing = verify_mpt_proof(
            root_hash=keccak256(extension),
            key=bytes.fromhex("accd"),
            proof_nodes=(extension,),
        )
        self.assertFalse(missing.found)
        self.assertEqual(missing.terminal, MptTerminal.ABSENT_PATH_DIVERGENCE)

    def test_missing_reordered_duplicate_and_tampered_nodes_fail(self) -> None:
        key = bytes.fromhex("ab")
        nibbles = bytes_to_nibbles(key)
        leaf = rlp_encode(
            (hex_prefix_encode((nibbles[1],), is_leaf=True), b"payload" * 8)
        )
        branch = [b""] * 17
        branch[nibbles[0]] = keccak256(leaf)
        branch_node = rlp_encode(tuple(branch))
        root = keccak256(branch_node)
        with self.assertRaisesRegex(ValueError, "missing"):
            verify_mpt_proof(root_hash=root, key=key, proof_nodes=(branch_node,))
        with self.assertRaises(ValueError):
            verify_mpt_proof(root_hash=root, key=key, proof_nodes=(leaf, branch_node))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verify_mpt_proof(root_hash=root, key=key, proof_nodes=(branch_node, leaf, leaf))
        tampered = leaf[:-1] + bytes((leaf[-1] ^ 1,))
        with self.assertRaises(ValueError):
            verify_mpt_proof(root_hash=root, key=key, proof_nodes=(branch_node, tampered))

    def test_unused_malformed_embedded_sibling_is_rejected(self) -> None:
        key = bytes.fromhex("ab")
        nibbles = bytes_to_nibbles(key)
        leaf_value = (
            hex_prefix_encode((nibbles[1],), is_leaf=True),
            b"x",
        )
        branch = [b""] * 17
        branch[nibbles[0]] = leaf_value
        branch[(nibbles[0] + 1) % 16] = (b"",)
        malformed_root = rlp_encode(tuple(branch))
        with self.assertRaises(ValueError):
            verify_mpt_proof(
                root_hash=keccak256(malformed_root),
                key=key,
                proof_nodes=(malformed_root,),
            )

    def test_key_width_is_governed(self) -> None:
        leaf = rlp_encode((hex_prefix_encode((), is_leaf=True), b"x"))
        with self.assertRaisesRegex(ValueError, "key width"):
            verify_mpt_proof(
                root_hash=keccak256(leaf),
                key=b"k" * 65,
                proof_nodes=(leaf,),
            )

    def test_result_constructor_binds_terminal_semantics(self) -> None:
        from aladdin_mev_engine.mpt import MptProofResult

        with self.assertRaisesRegex(ValueError, "terminal"):
            MptProofResult(
                found=True,
                value=b"x",
                terminal=MptTerminal.ABSENT_BRANCH_CHILD,
                used_node_hashes=("1" * 64,),
            )

    def test_branch_missing_child_and_value_prove_absence(self) -> None:
        branch = tuple([b""] * 17)
        encoded = rlp_encode(branch)
        by_child = verify_mpt_proof(
            root_hash=keccak256(encoded),
            key=b"\x10",
            proof_nodes=(encoded,),
        )
        self.assertEqual(by_child.terminal, MptTerminal.ABSENT_BRANCH_CHILD)
        by_value = verify_mpt_proof(
            root_hash=keccak256(encoded),
            key=b"",
            proof_nodes=(encoded,),
        )
        self.assertEqual(by_value.terminal, MptTerminal.ABSENT_BRANCH_VALUE)


if __name__ == "__main__":
    unittest.main()
