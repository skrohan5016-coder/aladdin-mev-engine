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
EXPECTED_RUN_COMMANDS = {
    'test "$(git rev-parse HEAD)" = "${{ github.event.pull_request.head.sha || github.sha }}"': 1,
    'test "$(git rev-parse HEAD)" = "${{ github.sha }}"': 1,
    "python -m compileall -q src tests scripts": 2,
    "python -m unittest discover -s tests -v": 2,
    "python scripts/check_repo_policy.py": 2,
    "python scripts/verify_architecture_lock.py": 2,
    "python scripts/verify_source_contracts.py": 2,
    "python scripts/verify_f2_schemas.py": 2,
    "python scripts/verify_f3_schemas.py": 2,
    "git diff --exit-code": 2,
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
    "accepted_parent_architecture_id": "AMEV-F2-ARCH-v1-bce8012e3ea7",
    "accepted_parent_head": "49b694f0e3034679b9e87f33b8008ad9fa83035c",
    "accepted_parent_tree": "79e0e4c8aab824aac895e81bbb452c5c0d0e73d2",
}
REQUIRED_COMPONENTS = {
    "explicit-code-hash-bound-constant-product-models",
    "one-code-hash-one-model-registry",
    "authenticated-token-and-packed-reserve-decoder",
    "checked-uint256-exact-input-quote",
    "packed-reserve-capacity-gate",
    "deterministic-simple-cycle-enumerator",
    "bounded-route-enumeration-work",
    "exact-per-hop-integer-floor-routing",
    "continuous-concave-upper-bound",
    "exact-branch-and-bound-optimizer",
    "bounded-optimizer-work",
    "aggregate-opportunity-search-work-gate",
    "deterministic-smaller-input-tie-break",
    "gross-only-opportunity-evidence-recomputation",
    "f3-schema-lock",
}
REQUIRED_INVARIANTS = {
    "explicit-model-registry-is-evidence-identity-not-production-approval",
    "one-runtime-code-hash-cannot-authorize-conflicting-constant-product-models",
    "empty-runtime-code-hash-cannot-authorize-a-constant-product-model",
    "optimization-result-cross-field-counts-bounds-and-status-authority-are-internally-consistent",
    "pool-code-hash-token-identities-and-reserves-bind-exact-authenticated-account-and-storage-evidence",
    "pool-model-storage-slots-are-exact-authenticated-inclusions",
    "state-freshness-uses-the-block-state-observation-time-not-later-proof-fetch-time",
    "fee-layout-and-transfer-semantics-are-explicit-model-assumptions",
    "exact-input-quotes-use-checked-uint256-and-floor-at-every-hop",
    "packed-reserve-capacity-is-enforced-before-quoting",
    "routes-are-two-to-four-hop-simple-cycles-without-pool-reuse-or-early-base-return",
    "route-enumeration-and-optimizer-work-are-deterministically-bounded",
    "aggregate-opportunity-report-work-is-bounded-before-route-optimization",
    "continuous-mathematics-may-only-upper-bound-and-prune-exact-search",
    "optimizer-ties-select-the-smallest-exact-input",
    "budget-exhaustion-is-incomplete-and-cannot-authorize-an-opportunity",
    "route-optimizer-requested-input-domains-are-closed-to-uint256",
    "incomplete-optimization-evidence-cannot-carry-a-winning-input-output-or-profit",
    "continuous-optimization-upper-bounds-are-closed-to-uint256",
    "nonpositive-exact-gross-profit-cannot-authorize-an-opportunity",
    "opportunity-evidence-recomputes-route-optimization-and-exact-quote-from-bound-inputs",
    "intermediate-route-quote-and-optimization-values-grant-no-standalone-opportunity-authority",
    "f3-opportunities-are-gross-only-cost-incomplete-and-never-execution-eligible",
    "f3-schema-lock-binds-all-new-schemas-and-the-transitive-opportunity-schema-dependency",
}
F3_SCHEMA_FILES = {
    "authenticated-constant-product-pool-v1.schema.json",
    "atomic-dex-opportunity-v1.schema.json",
    "constant-product-implementation-v1.schema.json",
    "constant-product-model-registry-v1.schema.json",
    "constant-product-pool-spec-v1.schema.json",
    "constant-product-pool-universe-v1.schema.json",
    "constant-product-route-v1.schema.json",
    "opportunity-search-report-v1.schema.json",
    "opportunity-v1.schema.json",
    "route-optimization-v1.schema.json",
}
REQUIRED_FILES = {
    # Inherited F1/F2 authority.
    "governance/F1_ACCEPTANCE.md",
    "governance/F1_OBSERVATION_LEDGER.md",
    "governance/F1_SOURCE_CONTRACTS.md",
    "governance/F2_ACCEPTANCE.md",
    "governance/F2_AUTHENTICATED_STATE.md",
    "governance/f2-schemas.lock.json",
    "governance/source-contracts.json",
    "scripts/verify_source_contracts.py",
    "scripts/verify_f2_schemas.py",
    "src/aladdin_mev_engine/head_tracker.py",
    "src/aladdin_mev_engine/ledger.py",
    "src/aladdin_mev_engine/ledger_io.py",
    "src/aladdin_mev_engine/observation.py",
    "src/aladdin_mev_engine/source_contracts.py",
    "src/aladdin_mev_engine/state_proof.py",
    # F3 authority.
    "governance/F3_ACCEPTANCE.md",
    "governance/F3_AUTHENTICATED_OPPORTUNITY_GRAPH.md",
    "governance/f3-schemas.lock.json",
    "scripts/verify_f3_schemas.py",
    "src/aladdin_mev_engine/constant_product.py",
    "src/aladdin_mev_engine/opportunity.py",
    "src/aladdin_mev_engine/opportunity_graph.py",
    "src/aladdin_mev_engine/optimizer.py",
    "tests/f3_helpers.py",
    "tests/test_constant_product_f3.py",
    "tests/test_f3_schema_contracts.py",
    "tests/test_opportunity_f3.py",
    "tests/test_opportunity_graph_f3.py",
    "tests/test_optimizer_f3.py",
    "tests/test_repository_policy_f3.py",
}

ACTION_REF = re.compile(
    r"^\s*-?\s*uses:\s*([^@\s]+)@([0-9a-fA-F]{40})\s*(?:#.*)?$"
)
ANY_USES = re.compile(r"^\s*-?\s*uses:\s*([^@\s]+)@([^\s#]+)")
RUN_COMMAND = re.compile(r"^\s*-?\s*run:\s*(.*?)\s*$")
SECRET_PATTERN = re.compile(r"\$\{\{\s*secrets\.", re.IGNORECASE)
WRITE_PERMISSION = re.compile(
    r"^\s+[A-Za-z][A-Za-z0-9_-]*:\s*write\s*$",
    re.MULTILINE,
)
FORBIDDEN_WORKFLOW_COMMAND = re.compile(
    r"\b(?:curl|wget|netcat|socat|ssh|scp|rsync)\b|"
    r"\bgit\s+(?:push|fetch|pull|clone)\b|/dev/tcp|/dev/udp",
    re.IGNORECASE,
)
PRIVATE_MATERIAL = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----|"
    r"\b(?:mnemonic|seed[_ -]?phrase)\s*[:=]",
    re.IGNORECASE,
)
FORBIDDEN_IMPORTS = re.compile(
    r"^\s*(?:from|import)\s+"
    r"(?:requests|httpx|aiohttp|web3|eth_account|websockets|socket|grpc|urllib\.request)\b",
    re.MULTILINE,
)
FORBIDDEN_SOURCE_TERMS = re.compile(
    r"\b(?:eth_sendRawTransaction|send_raw_transaction|sign_transaction|"
    r"broadcast_transaction|deploy_contract|send_bundle|private_key)\b",
    re.IGNORECASE,
)
FORBIDDEN_DYNAMIC_EXECUTION = re.compile(r"\b(?:eval|exec)\s*\(")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


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
    if type(text) is not str:
        return ["workflow source must be an exact string"]
    if "pull_request_target:" in text:
        errors.append("pull_request_target is forbidden")
    if SECRET_PATTERN.search(text):
        errors.append("workflow secret references are forbidden in F3")
    if len(re.findall(r"^permissions:\s*$", text, flags=re.MULTILINE)) != 1:
        errors.append("workflow must have exactly one top-level permissions block")
    if "permissions:\n  contents: read" not in text:
        errors.append("workflow permissions must be contents: read")
    if "write-all" in text or WRITE_PERMISSION.search(text):
        errors.append("workflow write permissions are forbidden")
    if text.count("persist-credentials: false") != 2:
        errors.append("both governed checkout paths must disable persisted credentials")

    required_contracts = {
        "validate-head:": "missing exact-head validation job",
        "name: F3 exact-head conformance": "missing F3 exact-head job identity",
        "ref: ${{ github.event.pull_request.head.sha || github.sha }}": (
            "exact-head checkout is not bound to the source SHA"
        ),
        "validate-merge:": "missing merge-integration validation job",
        "name: F3 merge integration": "missing F3 merge-integration job identity",
        "if: github.event_name == 'pull_request'": (
            "merge-integration job must be pull-request-only"
        ),
    }
    for contract, message in required_contracts.items():
        if contract not in text:
            errors.append(message)

    action_counts = {action: 0 for action in PINNED_ACTIONS}
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = ANY_USES.match(line)
        if match is None:
            continue
        immutable = ACTION_REF.match(line)
        if immutable is None:
            errors.append(
                f"workflow action is not pinned to a full SHA at line {line_number}"
            )
            continue
        action, revision = immutable.groups()
        expected = PINNED_ACTIONS.get(action)
        if expected is None:
            errors.append(
                f"workflow action is not allowlisted at line {line_number}: {action}"
            )
            continue
        if revision.lower() != expected:
            errors.append(f"workflow action pin drift at line {line_number}: {action}")
            continue
        action_counts[action] += 1
    for action, count in action_counts.items():
        if count != 2:
            errors.append(f"workflow must use {action} exactly twice")

    if FORBIDDEN_WORKFLOW_COMMAND.search(text):
        errors.append("workflow contains a forbidden network or publication command")

    run_counts = {command: 0 for command in EXPECTED_RUN_COMMANDS}
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = RUN_COMMAND.match(line)
        if match is None:
            continue
        command = match.group(1)
        if command not in run_counts:
            errors.append(
                f"workflow run command is not allowlisted at line {line_number}"
            )
            continue
        run_counts[command] += 1
    for command, expected_count in EXPECTED_RUN_COMMANDS.items():
        actual = run_counts[command]
        if actual != expected_count:
            errors.append(
                "workflow must use governed run command exactly "
                f"{expected_count} time(s): {command}"
            )
    return errors


def _check_workflow(errors: list[str]) -> None:
    path = ROOT / ".github" / "workflows" / "ci.yml"
    if not path.is_file():
        errors.append("missing .github/workflows/ci.yml")
        return
    errors.extend(workflow_policy_errors(path.read_text(encoding="utf-8")))


def _check_project_metadata(errors: list[str]) -> None:
    try:
        with (ROOT / "pyproject.toml").open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        errors.append(f"invalid or missing pyproject.toml: {error}")
        return
    project = document.get("project", {})
    if project.get("dependencies") != []:
        errors.append("F3 runtime dependencies must be exactly empty")
    if project.get("version") != "0.4.0":
        errors.append("F3 project version must be 0.4.0")
    aladdin = document.get("tool", {}).get("aladdin", {})
    expected = {
        "architecture_manifest": "governance/architecture.json",
        "architecture_lock": "governance/architecture.lock.json",
        "source_contracts": "governance/source-contracts.json",
        "f2_schema_lock": "governance/f2-schemas.lock.json",
        "f3_schema_lock": "governance/f3-schemas.lock.json",
        "observation_authority": "recorded-input-only",
        "state_proof_authority": "offline-recorded-input-only",
        "opportunity_authority": (
            "offline-authenticated-model-bound-gross-shadow-only"
        ),
        "production_model_lock": "none",
        "execution_authority": "none",
        "network_access": "none",
        "signing_authority": "none",
    }
    for key, value in expected.items():
        if aladdin.get(key) != value:
            errors.append(f"tool.aladdin.{key} is not governed")


def _check_source(errors: list[str]) -> None:
    for base in (ROOT / "src", ROOT / "scripts"):
        if not base.is_dir():
            errors.append(f"missing source directory: {base.relative_to(ROOT)}")
            continue
        for path in sorted(base.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            relative = path.relative_to(ROOT)
            if FORBIDDEN_IMPORTS.search(text):
                errors.append(f"network or signing dependency in {relative}")
            if path.name != "check_repo_policy.py" and FORBIDDEN_SOURCE_TERMS.search(text):
                errors.append(f"execution capability term in {relative}")
            if FORBIDDEN_DYNAMIC_EXECUTION.search(text):
                errors.append(f"dynamic execution is forbidden in {relative}")


def _check_repository_hygiene(errors: list[str]) -> None:
    ignore_path = ROOT / ".gitignore"
    if not ignore_path.is_file():
        errors.append("missing .gitignore")
        return
    required_ignores = {".env", ".env.*", "*.pem", "*.key"}
    ignores = set(ignore_path.read_text(encoding="utf-8").splitlines())
    missing = required_ignores - ignores
    if missing:
        errors.append("missing credential ignore rules: " + ", ".join(sorted(missing)))

    for path in sorted(ROOT.rglob("*")):
        if any(part in {".git", "__pycache__", ".staging"} for part in path.parts):
            continue
        if path.suffix == ".pyc":
            continue
        if path.is_symlink():
            errors.append(f"repository symlink is forbidden: {path.relative_to(ROOT)}")
            continue
        if not path.is_file():
            continue
        if path.stat().st_size > 1_048_576:
            errors.append(f"repository file exceeds 1 MiB: {path.relative_to(ROOT)}")
        data = path.read_bytes()
        if b"\x00" in data:
            errors.append(f"binary/NUL content is forbidden: {path.relative_to(ROOT)}")
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"non-UTF-8 file is forbidden: {path.relative_to(ROOT)}")
            continue
        if PRIVATE_MATERIAL.search(text):
            errors.append(f"possible private material in {path.relative_to(ROOT)}")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if line.rstrip(" \t") != line:
                errors.append(
                    f"trailing whitespace in {path.relative_to(ROOT)}:{line_number}"
                )


def _check_required_files(errors: list[str]) -> None:
    for relative in sorted(REQUIRED_FILES):
        if not (ROOT / relative).is_file():
            errors.append(f"missing governed F3 file: {relative}")


def _check_schemas(errors: list[str]) -> None:
    found: set[str] = set()
    for path in sorted((ROOT / "schemas").glob("*.json")):
        found.add(path.name)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            errors.append(f"invalid JSON schema {path.name}: {error}")
            continue
        if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            errors.append(f"schema draft is not governed in {path.name}")
        if not document.get("$id"):
            errors.append(f"missing schema id in {path.name}")
        if document.get("additionalProperties") is not False:
            errors.append(
                f"top-level additionalProperties must be false in {path.name}"
            )
    missing = F3_SCHEMA_FILES - found
    if missing:
        errors.append("missing F3 schemas: " + ", ".join(sorted(missing)))


def _load_json(relative: str, errors: list[str]) -> dict[str, object] | None:
    try:
        value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"invalid or missing {relative}: {error}")
        return None
    if type(value) is not dict:
        errors.append(f"{relative} must contain an object")
        return None
    return value


def _check_architecture(errors: list[str]) -> None:
    architecture = _load_json("governance/architecture.json", errors)
    lock = _load_json("governance/architecture.lock.json", errors)
    f2_lock = _load_json("governance/f2-schemas.lock.json", errors)
    f3_lock = _load_json("governance/f3-schemas.lock.json", errors)
    source_contracts = _load_json("governance/source-contracts.json", errors)
    if architecture is None:
        return
    if architecture.get("milestone") != "F3":
        errors.append("architecture milestone must be F3")
    for key, expected in EXPECTED_PARENT.items():
        if architecture.get(key) != expected:
            errors.append(f"architecture {key} does not bind the accepted F2 parent")
    expected_authority = {
        "network_access": "none",
        "signing_authority": "none",
        "execution_authority": "none",
        "observation_authority": "recorded-input-only",
        "state_proof_authority": "offline-recorded-input-only",
        "opportunity_authority": (
            "offline-authenticated-model-bound-gross-shadow-only"
        ),
        "production_model_lock": "none",
        "model_registry_authority": (
            "explicit-evidence-model-set-not-production-approval"
        ),
    }
    for key, expected in expected_authority.items():
        if architecture.get(key) != expected:
            errors.append(f"architecture {key} is not governed")
    if architecture.get("constant_product_opportunity_scope") != [
        "ethereum",
        "base",
    ]:
        errors.append("architecture constant-product opportunity scope is not governed")
    if architecture.get("runtime_dependencies") != []:
        errors.append("architecture runtime dependencies must be empty")
    if tuple(architecture.get("source_contract_ids", ())) != EXPECTED_SOURCE_IDS:
        errors.append("architecture source-contract identifiers are not governed")
    components = architecture.get("components")
    if type(components) is not list or not REQUIRED_COMPONENTS.issubset(set(components)):
        errors.append("architecture is missing required F3 components")
    invariants = architecture.get("invariants")
    if type(invariants) is not list or not REQUIRED_INVARIANTS.issubset(set(invariants)):
        errors.append("architecture is missing required F3 invariants")
    if f2_lock is not None and architecture.get("f2_schema_lock_sha256") != _canonical_sha256(f2_lock):
        errors.append("architecture F2 schema-lock digest does not match")
    if f3_lock is not None and architecture.get("f3_schema_lock_sha256") != _canonical_sha256(f3_lock):
        errors.append("architecture F3 schema-lock digest does not match")
    if source_contracts is not None and architecture.get("source_contract_set_sha256") != source_contracts.get("contracts_sha256"):
        errors.append("architecture source-contract digest does not match")

    digest = _canonical_sha256(architecture)
    if lock is None:
        return
    if set(lock) != {
        "schema",
        "architecture_id",
        "manifest_path",
        "manifest_sha256",
    }:
        errors.append("architecture lock must be a closed object")
    if lock.get("schema") != "aladdin-mev-architecture-lock/v1":
        errors.append("architecture lock schema is not governed")
    if lock.get("manifest_path") != "governance/architecture.json":
        errors.append("architecture lock path is not governed")
    if lock.get("manifest_sha256") != digest:
        errors.append("architecture lock does not bind the canonical manifest")
    if lock.get("architecture_id") != f"AMEV-F3-ARCH-v1-{digest[:12]}":
        errors.append("architecture id does not bind the canonical manifest")


def main() -> int:
    errors: list[str] = []
    _check_workflow(errors)
    _check_project_metadata(errors)
    _check_source(errors)
    _check_repository_hygiene(errors)
    _check_required_files(errors)
    _check_schemas(errors)
    _check_architecture(errors)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("repository policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
