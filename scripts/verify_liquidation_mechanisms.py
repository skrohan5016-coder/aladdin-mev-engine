from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from aladdin_mev_engine.canonical import strict_json_loads
from aladdin_mev_engine.liquidation_contracts import (
    LIQUIDATION_MECHANISMS,
    liquidation_mechanism_set_digest,
)


def main() -> int:
    path = ROOT / "governance" / "liquidation-mechanisms.json"
    document = strict_json_loads(path.read_bytes())
    expected_mechanisms = [
        LIQUIDATION_MECHANISMS[protocol].to_json_value()
        for protocol in sorted(LIQUIDATION_MECHANISMS, key=lambda item: item.value)
    ]
    errors: list[str] = []
    if type(document) is not dict or set(document) != {
        "schema",
        "mechanisms",
        "mechanisms_sha256",
    }:
        errors.append("liquidation mechanism set is not a closed object")
    else:
        if document.get("schema") != "aladdin-mev-liquidation-mechanism-set/v1":
            errors.append("liquidation mechanism set schema is not governed")
        if document.get("mechanisms") != expected_mechanisms:
            errors.append("liquidation mechanism file does not match the in-process registry")
        if document.get("mechanisms_sha256") != liquidation_mechanism_set_digest():
            errors.append("liquidation mechanism set digest mismatch")
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "mechanisms": len(expected_mechanisms),
                "mechanisms_sha256": liquidation_mechanism_set_digest(),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
