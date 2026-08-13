from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]

ACTION_REF = re.compile(r"^\s*-?\s*uses:\s*[^@\s]+@([0-9a-fA-F]{40})\s*(?:#.*)?$")
ANY_USES = re.compile(r"^\s*-?\s*uses:\s*[^@\s]+@([^\s#]+)")
SECRET_PATTERN = re.compile(r"\$\{\{\s*secrets\.", re.IGNORECASE)
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


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def check_workflow(errors: list[str]) -> None:
    workflow = ROOT / ".github" / "workflows" / "ci.yml"
    if not workflow.is_file():
        fail(errors, "missing .github/workflows/ci.yml")
        return
    text = workflow.read_text(encoding="utf-8")
    if "pull_request_target:" in text:
        fail(errors, "pull_request_target is forbidden")
    if SECRET_PATTERN.search(text):
        fail(errors, "workflow secret references are forbidden in F0")
    if "permissions:\n  contents: read" not in text:
        fail(errors, "workflow permissions must be contents: read")
    if "persist-credentials: false" not in text:
        fail(errors, "checkout must disable persisted credentials")
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = ANY_USES.match(line)
        if match and ACTION_REF.match(line) is None:
            fail(errors, f"workflow action is not pinned to a full SHA at line {line_number}")


def check_project_metadata(errors: list[str]) -> None:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        document = tomllib.load(handle)
    dependencies = document.get("project", {}).get("dependencies", None)
    if dependencies != []:
        fail(errors, "F0 runtime dependencies must be exactly empty")
    aladdin = document.get("tool", {}).get("aladdin", {})
    for key in ("execution_authority", "network_access"):
        if aladdin.get(key) != "none":
            fail(errors, f"tool.aladdin.{key} must be none")


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


def main() -> int:
    errors: list[str] = []
    check_workflow(errors)
    check_project_metadata(errors)
    check_source(errors)
    check_repository_hygiene(errors)
    check_schemas(errors)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("repository policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
