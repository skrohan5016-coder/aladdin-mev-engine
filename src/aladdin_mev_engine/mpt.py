from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .keccak import keccak256
from .rlp import (
    RlpItem,
    require_rlp_bytes,
    require_rlp_list,
    rlp_decode,
    rlp_encode,
)

MAX_PROOF_NODES = 256
MAX_PROOF_NODE_BYTES = 65_536
MAX_PROOF_TOTAL_BYTES = 1_048_576
MAX_MPT_KEY_BYTES = 64
MAX_EMBEDDED_NODE_DEPTH = 32
EMPTY_TRIE_ROOT = keccak256(rlp_encode(b""))


class MptTerminal(StrEnum):
    FOUND_LEAF = "found-leaf"
    FOUND_BRANCH_VALUE = "found-branch-value"
    ABSENT_EMPTY_TRIE = "absent-empty-trie"
    ABSENT_BRANCH_CHILD = "absent-branch-child"
    ABSENT_BRANCH_VALUE = "absent-branch-value"
    ABSENT_PATH_DIVERGENCE = "absent-path-divergence"
    ABSENT_LEAF_REMAINDER = "absent-leaf-remainder"


FOUND_TERMINALS = frozenset(
    {MptTerminal.FOUND_LEAF, MptTerminal.FOUND_BRANCH_VALUE}
)
ABSENT_TERMINALS = frozenset(set(MptTerminal) - set(FOUND_TERMINALS))


@dataclass(frozen=True, slots=True)
class MptProofResult:
    found: bool
    value: bytes | None
    terminal: MptTerminal
    used_node_hashes: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.found) is not bool:
            raise TypeError("found must be an exact bool")
        if self.found != (self.value is not None):
            raise ValueError("found/value state is inconsistent")
        if type(self.value) not in {bytes, type(None)}:
            raise TypeError("value must be exact bytes or null")
        if type(self.terminal) is not MptTerminal:
            raise TypeError("terminal must be an exact MptTerminal")
        if self.found != (self.terminal in FOUND_TERMINALS):
            raise ValueError("found/terminal state is inconsistent")
        if type(self.used_node_hashes) is not tuple:
            raise TypeError("used_node_hashes must be an exact tuple")
        if any(
            type(value) is not str
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
            for value in self.used_node_hashes
        ):
            raise ValueError("used_node_hashes contains a non-canonical digest")
        if len(self.used_node_hashes) != len(set(self.used_node_hashes)):
            raise ValueError("used_node_hashes contains a duplicate")
        if self.terminal is MptTerminal.ABSENT_EMPTY_TRIE:
            if self.used_node_hashes:
                raise ValueError("empty-trie proof cannot use nodes")
        elif not self.used_node_hashes:
            raise ValueError("non-empty trie proof must authenticate at least the root node")


def bytes_to_nibbles(value: bytes) -> tuple[int, ...]:
    if type(value) is not bytes:
        raise TypeError("nibble input must be exact bytes")
    result: list[int] = []
    for byte in value:
        result.extend((byte >> 4, byte & 0x0F))
    return tuple(result)


def nibbles_to_bytes(nibbles: tuple[int, ...]) -> bytes:
    if type(nibbles) is not tuple or any(
        type(nibble) is not int or not 0 <= nibble <= 15 for nibble in nibbles
    ):
        raise ValueError("nibbles must be an exact tuple of values in [0, 15]")
    if len(nibbles) % 2:
        raise ValueError("nibble sequence must have even length")
    return bytes(
        (nibbles[index] << 4) | nibbles[index + 1]
        for index in range(0, len(nibbles), 2)
    )


def hex_prefix_encode(path: tuple[int, ...], *, is_leaf: bool) -> bytes:
    if type(path) is not tuple or any(
        type(nibble) is not int or not 0 <= nibble <= 15 for nibble in path
    ):
        raise ValueError("path must be an exact tuple of nibbles")
    if type(is_leaf) is not bool:
        raise TypeError("is_leaf must be an exact bool")
    odd = len(path) % 2
    flag = (2 if is_leaf else 0) + odd
    if odd:
        encoded_nibbles = (flag, path[0], *path[1:])
    else:
        encoded_nibbles = (flag, 0, *path)
    return nibbles_to_bytes(encoded_nibbles)


def hex_prefix_decode(encoded: bytes) -> tuple[bool, tuple[int, ...]]:
    if type(encoded) is not bytes or not encoded:
        raise ValueError("hex-prefix path must be non-empty exact bytes")
    nibbles = bytes_to_nibbles(encoded)
    flag = nibbles[0]
    if flag not in {0, 1, 2, 3}:
        raise ValueError("hex-prefix path has an invalid flag nibble")
    is_leaf = flag >= 2
    odd = flag & 1
    if odd:
        path = nibbles[1:]
    else:
        if len(nibbles) < 2 or nibbles[1] != 0:
            raise ValueError("even hex-prefix path lacks its zero padding nibble")
        path = nibbles[2:]
    if hex_prefix_encode(path, is_leaf=is_leaf) != encoded:
        raise ValueError("hex-prefix path is not canonical")
    return is_leaf, path


def _validate_child_reference(
    name: str,
    reference: RlpItem,
    *,
    depth: int,
) -> None:
    if type(reference) is bytes:
        if len(reference) in {0, 32}:
            return
        raise ValueError(
            f"{name} must be empty, a 32-byte hash, or an embedded RLP list"
        )
    if type(reference) is not tuple:
        raise TypeError(f"{name} is not a governed trie reference")
    encoded = rlp_encode(reference)
    if len(encoded) >= 32:
        raise ValueError(f"{name} is an oversized embedded trie node")
    _validate_decoded_node_shape(reference, depth=depth + 1)


def _validate_decoded_node_shape(
    node: RlpItem,
    *,
    depth: int,
) -> tuple[RlpItem, ...]:
    if depth > MAX_EMBEDDED_NODE_DEPTH:
        raise ValueError("embedded trie-node depth exceeds the governed ceiling")
    values = require_rlp_list("trie node", node)
    if len(values) == 17:
        for index, child in enumerate(values[:16]):
            _validate_child_reference(
                f"branch child {index}",
                child,
                depth=depth,
            )
        require_rlp_bytes("branch value", values[16])
        return values

    if len(values) == 2:
        encoded_path = require_rlp_bytes("compact path", values[0])
        is_leaf, path = hex_prefix_decode(encoded_path)
        if is_leaf:
            require_rlp_bytes("leaf value", values[1])
        else:
            if not path:
                raise ValueError("extension path must not be empty")
            child = values[1]
            if type(child) is bytes and not child:
                raise ValueError("extension child reference must not be empty")
            _validate_child_reference(
                "extension child reference",
                child,
                depth=depth,
            )
        return values

    raise ValueError("trie node must be a 17-item branch or 2-item leaf/extension")


def _validate_node_shape(encoded: bytes, *, depth: int = 0) -> tuple[RlpItem, ...]:
    if type(encoded) is not bytes:
        raise TypeError("proof node must be exact immutable bytes")
    if not encoded:
        raise ValueError("proof node must not be empty")
    if len(encoded) > MAX_PROOF_NODE_BYTES:
        raise ValueError("proof node exceeds the governed byte ceiling")
    node = rlp_decode(encoded)
    return _validate_decoded_node_shape(node, depth=depth)

def verify_mpt_proof(
    *,
    root_hash: bytes,
    key: bytes,
    proof_nodes: tuple[bytes, ...],
) -> MptProofResult:
    if type(root_hash) is not bytes or len(root_hash) != 32:
        raise ValueError("root_hash must be exact 32-byte data")
    if type(key) is not bytes:
        raise TypeError("key must be exact immutable bytes")
    if len(key) > MAX_MPT_KEY_BYTES:
        raise ValueError("key exceeds the governed MPT key width")
    if type(proof_nodes) is not tuple:
        raise TypeError("proof_nodes must be an exact tuple")
    if len(proof_nodes) > MAX_PROOF_NODES:
        raise ValueError("proof node count exceeds the governed ceiling")
    if any(type(node) is not bytes for node in proof_nodes):
        raise TypeError("proof_nodes contains a non-bytes value")
    if sum(len(node) for node in proof_nodes) > MAX_PROOF_TOTAL_BYTES:
        raise ValueError("proof payload exceeds the governed byte ceiling")

    if root_hash == EMPTY_TRIE_ROOT:
        if proof_nodes:
            raise ValueError("empty-trie proof must not contain nodes")
        return MptProofResult(
            found=False,
            value=None,
            terminal=MptTerminal.ABSENT_EMPTY_TRIE,
            used_node_hashes=(),
        )
    if not proof_nodes:
        raise ValueError("non-empty trie root requires proof nodes")

    by_hash: dict[bytes, tuple[bytes, RlpItem]] = {}
    ordered_hashes: list[bytes] = []
    for encoded in proof_nodes:
        decoded = _validate_node_shape(encoded)
        digest = keccak256(encoded)
        if digest in by_hash:
            raise ValueError("proof contains a duplicate node hash")
        by_hash[digest] = (encoded, decoded)
        ordered_hashes.append(digest)

    remaining = bytes_to_nibbles(key)
    reference = root_hash
    used_hashes: list[bytes] = []
    visited_references: set[bytes] = set()

    def resolve(ref: RlpItem) -> tuple[bytes, tuple[RlpItem, ...]]:
        if type(ref) is tuple:
            encoded = rlp_encode(ref)
            if len(encoded) >= 32:
                raise ValueError("embedded trie reference is oversized")
            return encoded, _validate_decoded_node_shape(ref, depth=1)
        if type(ref) is not bytes:
            raise TypeError("trie reference is not a governed RLP value")
        if not ref:
            raise ValueError("empty child reference cannot be resolved")
        if len(ref) != 32:
            raise ValueError(
                "trie byte-string reference must be empty or a 32-byte hash"
            )
        if ref in visited_references:
            raise ValueError("proof contains a reference cycle")
        visited_references.add(ref)
        try:
            encoded, decoded = by_hash[ref]
        except KeyError as error:
            raise ValueError("proof is missing a referenced node") from error
        used_hashes.append(ref)
        return encoded, require_rlp_list("trie node", decoded)

    terminal: MptProofResult | None = None
    while terminal is None:
        _encoded, values = resolve(reference)
        if len(values) == 17:
            if not remaining:
                branch_value = require_rlp_bytes("branch value", values[16])
                if branch_value:
                    terminal = MptProofResult(
                        found=True,
                        value=branch_value,
                        terminal=MptTerminal.FOUND_BRANCH_VALUE,
                        used_node_hashes=tuple(value.hex() for value in used_hashes),
                    )
                else:
                    terminal = MptProofResult(
                        found=False,
                        value=None,
                        terminal=MptTerminal.ABSENT_BRANCH_VALUE,
                        used_node_hashes=tuple(value.hex() for value in used_hashes),
                    )
                continue
            child = values[remaining[0]]
            remaining = remaining[1:]
            if type(child) is bytes and not child:
                terminal = MptProofResult(
                    found=False,
                    value=None,
                    terminal=MptTerminal.ABSENT_BRANCH_CHILD,
                    used_node_hashes=tuple(value.hex() for value in used_hashes),
                )
                continue
            reference = child
            continue

        is_leaf, path = hex_prefix_decode(
            require_rlp_bytes("compact path", values[0])
        )
        common = 0
        while (
            common < len(path)
            and common < len(remaining)
            and path[common] == remaining[common]
        ):
            common += 1
        if common != len(path):
            terminal = MptProofResult(
                found=False,
                value=None,
                terminal=MptTerminal.ABSENT_PATH_DIVERGENCE,
                used_node_hashes=tuple(value.hex() for value in used_hashes),
            )
            continue
        remaining = remaining[common:]
        child_or_value = values[1]
        if is_leaf:
            payload = require_rlp_bytes("leaf value", child_or_value)
            if remaining:
                terminal = MptProofResult(
                    found=False,
                    value=None,
                    terminal=MptTerminal.ABSENT_LEAF_REMAINDER,
                    used_node_hashes=tuple(value.hex() for value in used_hashes),
                )
            else:
                terminal = MptProofResult(
                    found=True,
                    value=payload,
                    terminal=MptTerminal.FOUND_LEAF,
                    used_node_hashes=tuple(value.hex() for value in used_hashes),
                )
            continue
        reference = child_or_value

    if tuple(used_hashes) != tuple(ordered_hashes):
        raise ValueError("proof nodes are not the exact canonical traversal sequence")
    return terminal
