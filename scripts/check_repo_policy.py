from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]

PINNED_ACTIONS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
}
EXPECTED_SOURCE_IDS = (
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
EXPECTED_PARENT = {
    "accepted_parent_architecture_id": "AMEV-F0-ARCH-v1-5c494565cd12",
    "accepted_parent_head": "7190ef22f6a99c5044f434f8175c4909ef92763f",
    "accepted_parent_tree": "8d7eb3c22226a6abdee172f4ce21cc993faa3d66",
}
REQUIRED_F1_COMPONENTS = {
    "governed-source-contract-registry",
    "exact-event-shape-authority",
    "immutable-observation-envelope",
    "cross-segment-checkpoint-chain",
    "sealed-read-only-single-link-storage",
    "exact-stream-reorg-aware-head-tracker",
    "observation-bound-head-transitions",
    "source-contract-lock",
}
REQUIRED_F1_INVARIANTS = {
    "event-kind-finality-visibility-authority-is-not-a-cartesian-product",
    "source-sequences-start-at-zero-and-remain-contiguous-across-segments",
    "segment-manifest-binds-previous-segment-starting-and-ending-checkpoints",
    "segment-storage-is-write-once-read-only-single-link-and-no-follow",
    "head-trackers-are-bound-to-one-exact-source-kind-finality-full-visibility-stream",
    "head-transitions-bind-the-triggering-observation-digest-and-source-sequence",
    "head-tracker-rejections-do-not-consume-source-sequence-or-mutate-topology",
    "solana-observation-remains-unimplemented-and-fails-closed",
}
REQUIRED_F1_FILES = {
    "governance/F1_ACCEPTANCE.md",
    "governance/F1_OBSERVATION_LEDGER.md",
    "governance/F1_SOURCE_CONTRACTS.md",
    "governance/source-contracts.json",
    "schemas/head-transition-v1.schema.json",
    "schemas/observation-envelope-v1.schema.json",
    "schemas/observation-ledger-record-v1.schema.json",
    "schemas/observation-segment-manifest-v1.schema.json",
    "schemas/source-contract-v1.schema.json",
    "scripts/verify_source_contracts.py",
    "src/aladdin_mev_engine/head_tracker.py",
    "src/aladdin_mev_engine/ledger.py",
    "src/aladdin_mev_engine/ledger_io.py",
    "src/aladdin_mev_engine/observation.py",
    "src/aladdin_mev_engine/source_contracts.py",
}
ACTION_REF = re.compile(
    r"^\s*-?\s*uses:\s*([^@\s]+)@([0-9a-fA-F]{40})\s*(?:#.*)?$"
)
ANY_USES = re.compile(r"^\s*-?\s*uses:\s*([^@\s]+)@([^\s#]+)")
SECRET_PATTERN = re.compile(r"\$\{\{\s*secrets\.", re.IGNORECASE)
WRITE_PERMISSION = re.compile(r"^\s+[A-Za-z][A-Za-z0-9_-]*:\s*write\s*$", re.MULTILINE)
FORBIDDEN_WORKFLOW_COMMAND = re.compile(
    r"\b(?:curl|wget|netcat|socat|ssh|scp|rsync)\b|\bgit\s+(?:push|fetch|pull|clone)\b",
    re.IGNORECASE,
)
PRIVATE_MATERIAL = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----|\b(?:mnemonic|seed[_ -]?phrase)\s*[:=]",
    re.IGNORECASE,
)
FORBIDDEN_IMPORTS = re.compile(
    r"^\s*(?:from|import)\s+(?:requests|httpx|aiohttp|web3|eth_account|websockets|socket|grpc|urllib\.request)\b",
    re.MULTILINE,
)
FORBIDDEN_SOURCE_TERMS = re.compile(
    r"\b(?:eth_sendRawTransaction|send_raw_transaction|sign_transaction|broadcast_transaction|deploy_contract)\b",
    re.IGNORECASE,
)
FORBIDDEN_DYNAMIC_EXECUTION = re.compile(r"\b(?:eval|exec)\s*\(")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def workflow_policy_errors(text: str) -> list[str]:
    errors: list[str] = []
    if "pull_request_target:" in text:
        fail(errors, "pull_request_target is forbidden")
    if SECRET_PATTERN.search(text):
        fail(errors, "workflow secret references are forbidden in F1")
    if len(re.findall(r"^permissions:\s*$", text, flags=re.MULTILINE)) != 1:
        fail(errors, "workflow must have exactly one top-level permissions block")
    if "permissions:\n  contents: read" not in text:
        fail(errors, "workflow permissions must be contents: read")
    if "write-all" in text or WRITE_PERMISSION.search(text):
        fail(errors, "workflow write permissions are forbidden")
    if text.count("persist-credentials: false") != 2:
        fail(errors, "both governed checkout paths must disable persisted credentials")
    required_workflow_contracts = {
        "validate-head:": "missing exact-head validation job",
        "name: F1 exact-head conformance": "missing F1 exact-head job identity",
        "ref: ${{ github.event.pull_request.head.sha || github.sha }}": "exact-head checkout is not bound to the source SHA",
        'test "$(git rev-parse HEAD)" = "${{ github.event.pull_request.head.sha || github.sha }}"': "exact-head identity assertion is missing",
        "validate-merge:": "missing merge-integration validation job",
        "name: F1 merge integration": "missing F1 merge-integration job identity",
        "if: github.event_name == 'pull_request'": "merge-integration job must be pull-request-only",
        'test "$(git rev-parse HEAD)" = "${{ github.sha }}"': "merge-integration identity assertion is missing",
    }
    for contract, message in required_workflow_contracts.items():
        if contract not in text:
            fail(errors, message)
    if text.count("python scripts/verify_source_contracts.py") != 2:
        fail(errors, "both validation jobs must verify the source-contract registry")
    if text.count("python scripts/verify_architecture_lock.py") != 2:
        fail(errors, "both validation jobs must verify the architecture lock")

    action_counts = {action: 0 for action in PINNED_ACTIONS}
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = ANY_USES.match(line)
        if match is None:
            continue
        immutable = ACTION_REF.match(line)
        if immutable is None:
            fail(errors, f"workflow action is not pinned to a full SHA at line {line_number}")
            continue
        action, revision = immutable.groups()
        expected_revision = PINNED_ACTIONS.get(action)
        if expected_revision is None:
            fail(errors, f"workflow action is not allowlisted at line {line_number}: {action}")
            continue
        if revision.lower() != expected_revision:
            fail(errors, f"workflow action pin drift at line {line_number}: {action}")
            continue
        action_counts[action] += 1
    for action, count in action_counts.items():
        if count != 2:
            fail(errors, f"workflow must use {action} exactly twice")

    if FORBIDDEN_WORKFLOW_COMMAND.search(text):
        fail(errors, "workflow contains a forbidden network or publication command")
    return errors


def check_workflow(errors: list[str]) -> None:
    workflow = ROOT / ".github" / "workflows" / "ci.yml"
    if not workflow.is_file():
        fail(errors, "missing .github/workflows/ci.yml")
        return
    errors.extend(workflow_policy_errors(workflow.read_text(encoding="utf-8")))


def check_project_metadata(errors: list[str]) -> None:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        document = tomllib.load(handle)
    project = document.get("project", {})
    if project.get("dependencies") != []:
        fail(errors, "F1 runtime dependencies must be exactly empty")
    if project.get("version") != "0.2.0":
        fail(errors, "F1 project version must be 0.2.0")
    aladdin = document.get("tool", {}).get("aladdin", {})
    for key in ("execution_authority", "network_access", "signing_authority"):
        if aladdin.get(key) != "none":
            fail(errors, f"tool.aladdin.{key} must be none")
    if aladdin.get("source_contracts") != "governance/source-contracts.json":
        fail(errors, "tool.aladdin.source_contracts is not governed")
    if aladdin.get("architecture_manifest") != "governance/architecture.json":
        fail(errors, "tool.aladdin.architecture_manifest is not governed")
    if aladdin.get("architecture_lock") != "governance/architecture.lock.json":
        fail(errors, "tool.aladdin.architecture_lock is not governed")


def check_source(errors: list[str]) -> None:
    for base in (ROOT / "src", ROOT / "scripts"):
        for path in sorted(base.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            relative = path.relative_to(ROOT)
            if FORBIDDEN_IMPORTS.search(text):
                fail(errors, f"network or signing dependency in {relative}")
            if path.name != "check_repo_policy.py" and FORBIDDEN_SOURCE_TERMS.search(text):
                fail(errors, f"execution capability term in {relative}")
            if FORBIDDEN_DYNAMIC_EXECUTION.search(text):
                fail(errors, f"dynamic execution is forbidden in {relative}")


def check_repository_hygiene(errors: list[str]) -> None:
    required_ignores = {".env", ".env.*", "*.pem", "*.key"}
    ignores = set((ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())
    missing = required_ignores - ignores
    if missing:
        fail(errors, "missing credential ignore rules: " + ", ".join(sorted(missing)))

    for path in sorted(ROOT.rglob("*")):
        if ".git" in path.parts or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        if path.is_symlink():
            fail(errors, f"repository symlink is forbidden: {path.relative_to(ROOT)}")
            continue
        if path.is_file():
            if path.stat().st_size > 1_048_576:
                fail(errors, f"repository file exceeds 1 MiB: {path.relative_to(ROOT)}")
            data = path.read_bytes()
            if b"\x00" in data:
                fail(errors, f"binary/NUL content is forbidden: {path.relative_to(ROOT)}")
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                fail(errors, f"non-UTF-8 file is forbidden: {path.relative_to(ROOT)}")
                continue
            if PRIVATE_MATERIAL.search(text):
                fail(errors, f"possible private material in {path.relative_to(ROOT)}")
            for line_number, line in enumerate(text.splitlines(), start=1):
                if line.rstrip(" \t") != line:
                    fail(errors, f"trailing whitespace in {path.relative_to(ROOT)}:{line_number}")


def check_required_files(errors: list[str]) -> None:
    for relative in sorted(REQUIRED_F1_FILES):
        if not (ROOT / relative).is_file():
            fail(errors, f"missing governed F1 file: {relative}")


def check_schemas(errors: list[str]) -> None:
    for path in sorted((ROOT / "schemas").glob("*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            fail(errors, f"invalid JSON schema {path.name}: {error}")
            continue
        if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            fail(errors, f"schema draft is not governed in {path.name}")
        if not document.get("$id"):
            fail(errors, f"missing schema id in {path.name}")
        if document.get("additionalProperties") is not False:
            fail(errors, f"top-level additionalProperties must be false in {path.name}")


def load_source_contract_file(errors: list[str]) -> dict[str, object] | None:
    path = ROOT / "governance" / "source-contracts.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as error:
        fail(errors, f"invalid or missing source-contract registry: {error}")
        return None
    if type(document) is not dict or set(document) != {"schema", "contracts", "contracts_sha256"}:
        fail(errors, "source-contract registry must be a closed object")
        return None
    if document.get("schema") != "aladdin-mev-source-contract-set/v1":
        fail(errors, "source-contract registry schema is not governed")
    contracts = document.get("contracts")
    if type(contracts) is not list or len(contracts) != len(EXPECTED_SOURCE_IDS):
        fail(errors, "source-contract registry must contain exactly nine contracts")
        return document
    source_ids = [contract.get("source_id") if type(contract) is dict else None for contract in contracts]
    if tuple(source_ids) != EXPECTED_SOURCE_IDS:
        fail(errors, "source-contract registry identifiers are not the governed sorted set")
    digest = document.get("contracts_sha256")
    if type(digest) is not str or SHA256.fullmatch(digest) is None:
        fail(errors, "source-contract registry digest is not canonical SHA-256")
    elif digest != _canonical_sha256(contracts):
        fail(errors, "source-contract registry digest does not bind its contract vector")
    return document


def check_architecture(errors: list[str], source_contracts: dict[str, object] | None) -> None:
    path = ROOT / "governance" / "architecture.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as error:
        fail(errors, f"invalid or missing architecture manifest: {error}")
        return
    if document.get("milestone") != "F1":
        fail(errors, "architecture milestone must be F1")
    for key, expected in EXPECTED_PARENT.items():
        if document.get(key) != expected:
            fail(errors, f"architecture {key} does not bind the accepted F0 parent")
    for key in ("execution_authority", "network_access", "signing_authority"):
        if document.get(key) != "none":
            fail(errors, f"architecture {key} must be none")
    if document.get("observation_authority") != "recorded-input-only":
        fail(errors, "architecture observation_authority must be recorded-input-only")
    if document.get("runtime_dependencies") != []:
        fail(errors, "architecture runtime dependencies must be empty")
    if tuple(document.get("source_contract_ids", ())) != EXPECTED_SOURCE_IDS:
        fail(errors, "architecture source-contract identifiers do not match the registry")
    components = document.get("components")
    if type(components) is not list or not REQUIRED_F1_COMPONENTS.issubset(set(components)):
        fail(errors, "architecture is missing required F1 components")
    invariants = document.get("invariants")
    if type(invariants) is not list or not REQUIRED_F1_INVARIANTS.issubset(set(invariants)):
        fail(errors, "architecture is missing required F1 invariants")
    if source_contracts is not None and (
        document.get("source_contract_set_sha256") != source_contracts.get("contracts_sha256")
    ):
        fail(errors, "architecture source-contract digest does not match the governed registry")


def main() -> int:
    errors: list[str] = []
    check_workflow(errors)
    check_project_metadata(errors)
    check_source(errors)
    check_repository_hygiene(errors)
    check_required_files(errors)
    check_schemas(errors)
    source_contracts = load_source_contract_file(errors)
    check_architecture(errors, source_contracts)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("repository policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
