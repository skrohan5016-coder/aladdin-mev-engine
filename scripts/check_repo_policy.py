from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

PINNED_ACTIONS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
}
EXPECTED_RUN_COMMANDS = {
    'test "$(git rev-parse HEAD)" = "${{ github.event.pull_request.head.sha || github.sha }}"': 1,
    'test "$(git rev-parse HEAD)" = "${{ github.sha }}"': 1,
    "python -m compileall -q src tests scripts": 2,
    "python -m unittest discover -s tests -v": 2,
    "python scripts/check_repo_policy.py": 2,
    "python scripts/verify_architecture_lock.py": 2,
    "python scripts/verify_source_contracts.py": 2,
    "python scripts/verify_liquidation_mechanisms.py": 2,
    "git diff --exit-code": 2,
}
SOURCE_IDS = (
    "arbitrum-json-rpc",
    "arbitrum-sequencer-feed",
    "arbitrum-timeboost-auction",
    "base-flashblocks",
    "base-json-rpc",
    "bnb-json-rpc",
    "bnb-pbs-metadata",
    "ethereum-json-rpc",
    "ethereum-mev-share",
)
PROTOCOL_IDS = ("aave-v3", "morpho-blue")
STACKED_PARENT = {
    "stacked_parent_architecture_id": "AMEV-F1-ARCH-v1-e0cc085585eb",
    "stacked_parent_head": "431298e013f941f9e8385abee3bc2789a14254d6",
    "stacked_parent_tree": "855a53af31cca7fdae064377309c756b048c0654",
    "stacked_parent_status": "ready-unmerged-ci-green",
}
REQUIRED_COMPONENTS = {
    "governed-source-contract-registry",
    "cross-segment-checkpoint-chain",
    "exact-stream-reorg-aware-head-tracker",
    "source-pinned-liquidation-mechanism-registry",
    "exact-liquidation-threshold-comparators",
    "provenance-bound-liquidation-snapshot",
    "deterministic-liquidation-candidate-discovery",
    "same-unit-gross-edge-authority",
    "candidate-to-profit-firewall-separation",
}
REQUIRED_INVARIANTS = {
    "event-kind-finality-visibility-authority-is-not-a-cartesian-product",
    "source-sequences-start-at-zero-and-remain-contiguous-across-segments",
    "head-tracker-rejections-do-not-consume-source-sequence-or-mutate-topology",
    "solana-observation-remains-unimplemented-and-fails-closed",
    "liquidation-mechanisms-are-bound-to-exact-upstream-source-commits",
    "aave-v3-is-liquidatable-only-when-health-factor-wad-is-strictly-below-one-wad",
    "morpho-blue-is-liquidatable-only-when-rounded-up-borrowed-assets-strictly-exceed-rounded-down-max-borrow-assets",
    "mechanism-specific-metric-denominators-fail-closed",
    "snapshot-chain-must-match-its-state-reference-chain",
    "observation-digests-are-nonempty-unique-and-canonically-sorted",
    "repay-and-seize-values-share-one-explicit-valuation-unit",
    "candidate-requires-positive-same-unit-gross-edge",
    "candidate-identity-binds-snapshot-and-mechanism-contract-digests",
    "candidate-discovery-never-grants-execution-authority",
    "liquidation-candidate-is-not-profit-simulation-or-risk-approval",
    "deployment-identities-remain-recorded-input-without-live-registry-authority",
}
REQUIRED_SCHEMAS = {
    "aladdin-mev-liquidation-mechanism/v1",
    "aladdin-mev-liquidation-mechanism-set/v1",
    "aladdin-mev-liquidation-snapshot/v1",
    "aladdin-mev-liquidation-candidate/v1",
    "aladdin-mev-liquidation-discovery-decision/v1",
}
REQUIRED_FILES = {
    "governance/F1_ACCEPTANCE.md",
    "governance/F1_OBSERVATION_LEDGER.md",
    "governance/F1_SOURCE_CONTRACTS.md",
    "governance/source-contracts.json",
    "scripts/verify_source_contracts.py",
    "src/aladdin_mev_engine/head_tracker.py",
    "src/aladdin_mev_engine/ledger.py",
    "src/aladdin_mev_engine/ledger_io.py",
    "src/aladdin_mev_engine/observation.py",
    "src/aladdin_mev_engine/source_contracts.py",
    "governance/F2_ACCEPTANCE.md",
    "governance/F2_BOUNTY_SURVEY.md",
    "governance/F2_LIQUIDATION_DISCOVERY.md",
    "governance/liquidation-mechanisms.json",
    "schemas/liquidation-mechanism-v1.schema.json",
    "schemas/liquidation-mechanism-set-v1.schema.json",
    "schemas/liquidation-snapshot-v1.schema.json",
    "schemas/liquidation-candidate-v1.schema.json",
    "schemas/liquidation-discovery-decision-v1.schema.json",
    "scripts/verify_liquidation_mechanisms.py",
    "src/aladdin_mev_engine/liquidation_contracts.py",
    "src/aladdin_mev_engine/liquidation.py",
    "tests/test_liquidation_contracts_f2.py",
    "tests/test_liquidation_discovery_f2.py",
    "tests/test_f2_schema_contracts.py",
    "tests/test_governance_f1.py",
    "tests/test_repository_policy_f2.py",
}

ACTION = re.compile(r"^\s*-?\s*uses:\s*([^@\s]+)@([^\s#]+)")
RUN_COMMAND = re.compile(r"^\s*-?\s*run:\s*(.*?)\s*$")
IMMUTABLE_ACTION = re.compile(r"^\s*-?\s*uses:\s*([^@\s]+)@([0-9a-fA-F]{40})\s*(?:#.*)?$")
SECRET = re.compile(r"\$\{\{\s*secrets\.", re.IGNORECASE)
WRITE_PERMISSION = re.compile(r"^\s+[A-Za-z][A-Za-z0-9_-]*:\s*write\s*$", re.MULTILINE)
FORBIDDEN_WORKFLOW = re.compile(
    r"\b(?:curl|wget|netcat|socat|ssh|scp|rsync)\b|"
    r"\bgit\s+(?:push|fetch|pull|clone)\b|/dev/tcp|/dev/udp",
    re.IGNORECASE,
)
FORBIDDEN_IMPORT = re.compile(
    r"^\s*(?:from|import)\s+(?:requests|httpx|aiohttp|web3|eth_account|websockets|socket|grpc|urllib\.request)\b",
    re.MULTILINE,
)
FORBIDDEN_CAPABILITY = re.compile(
    r"\b(?:eth_sendRawTransaction|send_raw_transaction|sign_transaction|broadcast_transaction|deploy_contract)\b",
    re.IGNORECASE,
)
FORBIDDEN_DYNAMIC = re.compile(r"\b(?:eval|exec)\s*\(")
PRIVATE_MATERIAL = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----|\b(?:mnemonic|seed[_ -]?phrase)\s*[:=]",
    re.IGNORECASE,
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _fail(errors: list[str], message: str) -> None:
    errors.append(message)


def _digest(value: object) -> str:
    data = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def workflow_policy_errors(text: str) -> list[str]:
    errors: list[str] = []
    if type(text) is not str:
        return ["workflow source must be an exact string"]
    contracts = {
        "validate-head:": "missing exact-head validation job",
        "name: F2 exact-head conformance": "missing F2 exact-head job identity",
        "ref: ${{ github.event.pull_request.head.sha || github.sha }}": (
            "exact-head checkout is not bound to the source SHA"
        ),
        'test "$(git rev-parse HEAD)" = "${{ github.event.pull_request.head.sha || github.sha }}"': (
            "exact-head identity assertion is missing"
        ),
        "validate-merge:": "missing merge-integration validation job",
        "name: F2 merge integration": "missing F2 merge-integration job identity",
        "if: github.event_name == 'pull_request'": "merge-integration job must be pull-request-only",
        'test "$(git rev-parse HEAD)" = "${{ github.sha }}"': (
            "merge-integration identity assertion is missing"
        ),
    }
    for token, message in contracts.items():
        if token not in text:
            _fail(errors, message)
    if "pull_request_target:" in text:
        _fail(errors, "pull_request_target is forbidden")
    if SECRET.search(text):
        _fail(errors, "workflow secret references are forbidden in F2")
    if len(re.findall(r"^permissions:\s*$", text, re.MULTILINE)) != 1:
        _fail(errors, "workflow must have exactly one top-level permissions block")
    if "permissions:\n  contents: read" not in text:
        _fail(errors, "workflow permissions must be contents: read")
    if "write-all" in text or WRITE_PERMISSION.search(text):
        _fail(errors, "workflow write permissions are forbidden")
    if text.count("persist-credentials: false") != 2:
        _fail(errors, "both governed checkout paths must disable persisted credentials")
    required_commands = {
        "python scripts/verify_architecture_lock.py": "architecture lock",
        "python scripts/verify_source_contracts.py": "source-contract registry",
        "python scripts/verify_liquidation_mechanisms.py": "liquidation-mechanism registry",
    }
    for command, label in required_commands.items():
        if text.count(command) != 2:
            _fail(errors, f"both validation jobs must verify the {label}")

    counts = {name: 0 for name in PINNED_ACTIONS}
    for line_number, line in enumerate(text.splitlines(), 1):
        match = ACTION.match(line)
        if match is None:
            continue
        immutable = IMMUTABLE_ACTION.match(line)
        if immutable is None:
            _fail(errors, f"workflow action is not pinned to a full SHA at line {line_number}")
            continue
        name, revision = immutable.groups()
        expected = PINNED_ACTIONS.get(name)
        if expected is None:
            _fail(errors, f"workflow action is not allowlisted at line {line_number}: {name}")
        elif revision.lower() != expected:
            _fail(errors, f"workflow action pin drift at line {line_number}: {name}")
        else:
            counts[name] += 1
    for name, count in counts.items():
        if count != 2:
            _fail(errors, f"workflow must use {name} exactly twice")
    if FORBIDDEN_WORKFLOW.search(text):
        _fail(errors, "workflow contains a forbidden network or publication command")

    run_counts = {command: 0 for command in EXPECTED_RUN_COMMANDS}
    for line_number, line in enumerate(text.splitlines(), 1):
        match = RUN_COMMAND.match(line)
        if match is None:
            continue
        command = match.group(1)
        if command not in run_counts:
            _fail(
                errors,
                f"workflow run command is not allowlisted at line {line_number}",
            )
            continue
        run_counts[command] += 1
    for command, expected_count in EXPECTED_RUN_COMMANDS.items():
        actual_count = run_counts[command]
        if actual_count != expected_count:
            _fail(
                errors,
                "workflow must use governed run command exactly "
                f"{expected_count} time(s): {command}",
            )
    return errors


def _load_json(path: Path, errors: list[str], label: str) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as error:
        _fail(errors, f"invalid or missing {label}: {error}")
        return None


def _check_registry(
    errors: list[str],
    *,
    path: str,
    label: str,
    schema: str,
    vector_key: str,
    digest_key: str,
    id_key: str,
    expected_ids: tuple[str, ...],
) -> dict[str, object] | None:
    document = _load_json(ROOT / path, errors, label)
    expected_keys = {"schema", vector_key, digest_key}
    if type(document) is not dict or set(document) != expected_keys:
        _fail(errors, f"{label} must be a closed object")
        return None
    if document["schema"] != schema:
        _fail(errors, f"{label} schema is not governed")
    vector = document[vector_key]
    if type(vector) is not list or len(vector) != len(expected_ids):
        _fail(errors, f"{label} has the wrong governed cardinality")
        return document
    identifiers = tuple(item.get(id_key) if type(item) is dict else None for item in vector)
    if identifiers != expected_ids:
        _fail(errors, f"{label} identifiers are not the governed sorted set")
    digest = document[digest_key]
    if type(digest) is not str or SHA256.fullmatch(digest) is None:
        _fail(errors, f"{label} digest is not canonical SHA-256")
    elif digest != _digest(vector):
        _fail(errors, f"{label} digest does not bind its vector")
    return document


def _check_metadata(errors: list[str]) -> None:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        document = tomllib.load(handle)
    project = document.get("project", {})
    if project.get("dependencies") != []:
        _fail(errors, "F2 runtime dependencies must be exactly empty")
    if project.get("version") != "0.3.0":
        _fail(errors, "F2 project version must be 0.3.0")
    aladdin = document.get("tool", {}).get("aladdin", {})
    expected = {
        "architecture_manifest": "governance/architecture.json",
        "architecture_lock": "governance/architecture.lock.json",
        "source_contracts": "governance/source-contracts.json",
        "liquidation_mechanisms": "governance/liquidation-mechanisms.json",
        "execution_authority": "none",
        "network_access": "none",
        "signing_authority": "none",
    }
    for key, value in expected.items():
        if aladdin.get(key) != value:
            _fail(errors, f"tool.aladdin.{key} is not governed")


def _check_files_and_source(errors: list[str]) -> None:
    for relative in sorted(REQUIRED_FILES):
        if not (ROOT / relative).is_file():
            _fail(errors, f"missing governed F2 file: {relative}")
    ignores = set((ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())
    missing_ignores = {".env", ".env.*", "*.pem", "*.key"} - ignores
    if missing_ignores:
        _fail(errors, "missing credential ignore rules: " + ", ".join(sorted(missing_ignores)))

    for path in sorted(ROOT.rglob("*")):
        if ".git" in path.parts or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        if path.is_symlink():
            _fail(errors, f"repository symlink is forbidden: {path.relative_to(ROOT)}")
            continue
        if not path.is_file():
            continue
        if path.stat().st_size > 1_048_576:
            _fail(errors, f"repository file exceeds 1 MiB: {path.relative_to(ROOT)}")
        data = path.read_bytes()
        if b"\x00" in data:
            _fail(errors, f"binary/NUL content is forbidden: {path.relative_to(ROOT)}")
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            _fail(errors, f"non-UTF-8 file is forbidden: {path.relative_to(ROOT)}")
            continue
        if PRIVATE_MATERIAL.search(text):
            _fail(errors, f"possible private material in {path.relative_to(ROOT)}")
        for line_number, line in enumerate(text.splitlines(), 1):
            if line.rstrip(" \t") != line:
                _fail(errors, f"trailing whitespace in {path.relative_to(ROOT)}:{line_number}")
        if path.suffix == ".py" and ("src" in path.parts or "scripts" in path.parts):
            if FORBIDDEN_IMPORT.search(text):
                _fail(errors, f"network or signing dependency in {path.relative_to(ROOT)}")
            if path.name != "check_repo_policy.py" and FORBIDDEN_CAPABILITY.search(text):
                _fail(errors, f"execution capability term in {path.relative_to(ROOT)}")
            if FORBIDDEN_DYNAMIC.search(text):
                _fail(errors, f"dynamic execution is forbidden in {path.relative_to(ROOT)}")

    for path in sorted((ROOT / "schemas").glob("*.json")):
        schema = _load_json(path, errors, f"JSON schema {path.name}")
        if type(schema) is not dict:
            continue
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            _fail(errors, f"schema draft is not governed in {path.name}")
        if not schema.get("$id"):
            _fail(errors, f"missing schema id in {path.name}")
        if schema.get("additionalProperties") is not False:
            _fail(errors, f"top-level additionalProperties must be false in {path.name}")


def _check_architecture(
    errors: list[str],
    source_registry: dict[str, object] | None,
    mechanism_registry: dict[str, object] | None,
) -> None:
    document = _load_json(ROOT / "governance" / "architecture.json", errors, "architecture manifest")
    if type(document) is not dict:
        return
    if document.get("milestone") != "F2":
        _fail(errors, "architecture milestone must be F2")
    for key, value in STACKED_PARENT.items():
        if document.get(key) != value:
            _fail(errors, f"architecture {key} does not bind the exact F1 stacked parent")
    expected_authorities = {
        "execution_authority": "none",
        "network_access": "none",
        "signing_authority": "none",
        "observation_authority": "recorded-input-only",
        "discovery_authority": "offline-recorded-input-only",
        "deployment_authority": "none-recorded-input-only",
    }
    for key, value in expected_authorities.items():
        if document.get(key) != value:
            _fail(errors, f"architecture {key} is not governed")
    if document.get("runtime_dependencies") != []:
        _fail(errors, "architecture runtime dependencies must be empty")
    if tuple(document.get("source_contract_ids", ())) != SOURCE_IDS:
        _fail(errors, "architecture source-contract identifiers do not match the registry")
    if tuple(document.get("liquidation_protocol_ids", ())) != PROTOCOL_IDS:
        _fail(errors, "architecture liquidation protocol identifiers do not match the registry")
    for key, required in (
        ("components", REQUIRED_COMPONENTS),
        ("invariants", REQUIRED_INVARIANTS),
        ("schemas", REQUIRED_SCHEMAS),
    ):
        values = document.get(key)
        if type(values) is not list or not required.issubset(set(values)):
            _fail(errors, f"architecture is missing required F2 {key}")
    if source_registry is not None and (
        document.get("source_contract_set_sha256") != source_registry.get("contracts_sha256")
    ):
        _fail(errors, "architecture source-contract digest does not match the governed registry")
    if mechanism_registry is not None and (
        document.get("liquidation_mechanism_set_sha256")
        != mechanism_registry.get("mechanisms_sha256")
    ):
        _fail(errors, "architecture liquidation-mechanism digest does not match the governed registry")


def main() -> int:
    errors = workflow_policy_errors(
        (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    _check_metadata(errors)
    _check_files_and_source(errors)
    source_registry = _check_registry(
        errors,
        path="governance/source-contracts.json",
        label="source-contract registry",
        schema="aladdin-mev-source-contract-set/v1",
        vector_key="contracts",
        digest_key="contracts_sha256",
        id_key="source_id",
        expected_ids=SOURCE_IDS,
    )
    mechanism_registry = _check_registry(
        errors,
        path="governance/liquidation-mechanisms.json",
        label="liquidation-mechanism registry",
        schema="aladdin-mev-liquidation-mechanism-set/v1",
        vector_key="mechanisms",
        digest_key="mechanisms_sha256",
        id_key="protocol",
        expected_ids=PROTOCOL_IDS,
    )
    _check_architecture(errors, source_registry, mechanism_registry)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("repository policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
