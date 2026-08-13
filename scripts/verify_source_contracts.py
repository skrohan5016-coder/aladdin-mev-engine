from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from aladdin_mev_engine.canonical import strict_json_loads
from aladdin_mev_engine.source_contracts import SOURCE_CONTRACTS, source_contract_set_digest


def main() -> int:
    path = ROOT / "governance" / "source-contracts.json"
    document = strict_json_loads(path.read_bytes())
    expected_contracts = [
        SOURCE_CONTRACTS[source_id].to_json_value() for source_id in sorted(SOURCE_CONTRACTS)
    ]
    errors: list[str] = []
    if type(document) is not dict or set(document) != {"schema", "contracts", "contracts_sha256"}:
        errors.append("source-contract set is not a closed object")
    else:
        if document.get("schema") != "aladdin-mev-source-contract-set/v1":
            errors.append("source-contract set schema is not governed")
        if document.get("contracts") != expected_contracts:
            errors.append("source-contract file does not match the in-process registry")
        if document.get("contracts_sha256") != source_contract_set_digest():
            errors.append("source-contract set digest mismatch")
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "contracts": len(expected_contracts),
                "contracts_sha256": source_contract_set_digest(),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
