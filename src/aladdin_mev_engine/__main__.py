from __future__ import annotations

import argparse
from pathlib import Path

from .canonical import canonical_json_bytes, canonical_sha256
from .io import read_stable_json


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Offline Aladdin MEV F7 conformance and canonical-evidence utility"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    digest_parser = subparsers.add_parser(
        "digest-json",
        help="validate and digest bounded canonical JSON",
    )
    digest_parser.add_argument("path", type=Path)
    canonical_parser = subparsers.add_parser(
        "canonicalize-json",
        help="emit canonical validated JSON",
    )
    canonical_parser.add_argument("path", type=Path)
    arguments = parser.parse_args()

    value = read_stable_json(arguments.path)
    if arguments.command == "digest-json":
        print(canonical_sha256(value))
        return 0
    if arguments.command == "canonicalize-json":
        print(canonical_json_bytes(value).decode("utf-8"))
        return 0
    raise AssertionError("unreachable command")


if __name__ == "__main__":
    raise SystemExit(main())
