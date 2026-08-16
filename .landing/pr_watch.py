#!/usr/bin/env python3
"""Fail-closed live PR readiness watcher used by the guarded landing helper."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


def run_json(args: list[str], cwd: Path, allowed: set[int] | None = None) -> object:
    allowed = allowed or {0}
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)
    if result.returncode not in allowed:
        detail = result.stderr.strip() or result.stdout.strip() or "no details"
        raise RuntimeError(f"{' '.join(args[:3])} failed ({result.returncode}): {detail}")
    if not result.stdout.strip():
        return []
    return json.loads(result.stdout)


def emit_blocked(reason: str) -> int:
    print(json.dumps({
        "schemaVersion": 1,
        "observedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "state": "blocked",
        "policy": {
            "source": "no-config",
            "configPath": None,
            "checkPolicy": "all",
            "strictChangesRequested": False,
            "requiredReviewers": [],
        },
        "targets": [],
        "actions": [{"type": "watch_error", "reason": reason}],
        "errors": [reason],
    }, sort_keys=True, separators=(",", ":")), flush=True)
    return 20


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode")
    parser.add_argument("--cursor")
    parser.add_argument("--target", action="append")
    parser.add_argument("--no-config", action="store_true")
    parser.add_argument("--config")
    parser.add_argument("--reviewer", action="append")
    parser.add_argument("--check-policy")
    parser.add_argument("--strict-changes-requested", action="store_true")
    parser.add_argument("--fixture")
    args = parser.parse_args()

    if args.fixture:
        return emit_blocked("offline fixture is not accepted by this live landing watcher")
    if not args.no_config or args.config is not None:
        return emit_blocked("landing watcher requires the explicit no-config policy")
    if args.reviewer:
        return emit_blocked("no CLI-required reviewers were part of the approved policy")
    if args.check_policy not in (None, "all"):
        return emit_blocked("landing watcher requires all checks")
    if args.strict_changes_requested:
        return emit_blocked("strict changes-requested override was not part of the approved policy")
    if not args.target or len(args.target) != 1:
        return emit_blocked("exactly one live PR target is required")

    target_text = args.target[0]
    path_text, separator, selector = target_text.rpartition("=")
    if not separator or not path_text or not selector:
        return emit_blocked("target must be PATH=PR")
    repository_path = Path(path_text).resolve()

    try:
        repo = run_json([
            "gh", "repo", "view", "--json",
            "nameWithOwner,url,mergeCommitAllowed,rebaseMergeAllowed,squashMergeAllowed",
        ], repository_path)
        if not isinstance(repo, dict):
            raise RuntimeError("repository metadata is not an object")
        repository = repo.get("nameWithOwner")
        repository_url = repo.get("url")
        if not isinstance(repository, str) or "/" not in repository:
            raise RuntimeError("repository identity is missing")
        if not isinstance(repository_url, str) or not urlparse(repository_url).hostname:
            raise RuntimeError("repository URL is missing")

        pr = run_json([
            "gh", "pr", "view", selector, "--json",
            "number,url,state,isDraft,headRefName,headRefOid,baseRefName,baseRefOid,"
            "mergeable,mergeStateStatus,reviewDecision,autoMergeRequest,mergedAt,reviews",
        ], repository_path)
        if not isinstance(pr, dict) or not isinstance(pr.get("number"), int):
            raise RuntimeError("pull request metadata is incomplete")

        checks = run_json([
            "gh", "pr", "checks", selector, "--json",
            "name,state,bucket,link,workflow,startedAt,completedAt",
        ], repository_path, {0, 1, 8})
        if not isinstance(checks, list):
            raise RuntimeError("checks output is not a list")

        owner, name = repository.split("/", 1)
        query = """
query($owner:String!,$name:String!,$number:Int!){
  repository(owner:$owner,name:$name){
    pullRequest(number:$number){
      isMergeQueueEnabled
      reviewThreads(first:100){
        nodes{id isResolved isOutdated path line originalLine}
        pageInfo{hasNextPage endCursor}
      }
    }
  }
}
""".strip()
        aux = run_json([
            "gh", "api", "graphql",
            "-F", f"owner={owner}",
            "-F", f"name={name}",
            "-F", f"number={pr['number']}",
            "-f", f"query={query}",
        ], repository_path)
        pull = aux["data"]["repository"]["pullRequest"]
        queue_enabled = pull.get("isMergeQueueEnabled")
        thread_page = pull.get("reviewThreads")
        if not isinstance(queue_enabled, bool):
            raise RuntimeError("merge-queue policy is unknown")
        if not isinstance(thread_page, dict) or thread_page.get("pageInfo", {}).get("hasNextPage"):
            raise RuntimeError("review-thread pagination is incomplete")
        threads = thread_page.get("nodes")
        if not isinstance(threads, list):
            raise RuntimeError("review threads are unavailable")

        reasons: list[str] = []
        if pr.get("state") != "OPEN":
            reasons.append(f"PR state is {pr.get('state')}")
        if pr.get("isDraft") is not False:
            reasons.append("PR is draft")
        if not isinstance(pr.get("headRefOid"), str) or not pr.get("headRefOid"):
            reasons.append("head SHA is missing")
        if pr.get("mergeable") != "MERGEABLE":
            reasons.append(f"mergeable={pr.get('mergeable')}")
        if pr.get("mergeStateStatus") != "CLEAN":
            reasons.append(f"mergeStateStatus={pr.get('mergeStateStatus')}")
        if pr.get("reviewDecision") in {"CHANGES_REQUESTED", "REVIEW_REQUIRED"}:
            reasons.append(f"reviewDecision={pr.get('reviewDecision')}")
        if pr.get("autoMergeRequest") is not None:
            reasons.append("auto-merge is already externally configured")
        unresolved = [item for item in threads if isinstance(item, dict) and not item.get("isResolved")]
        if unresolved:
            reasons.append(f"{len(unresolved)} unresolved review thread(s)")
        if not checks:
            reasons.append("no current checks are visible")

        safe_buckets = {"pass", "skipping"}
        for index, check in enumerate(checks):
            if not isinstance(check, dict):
                reasons.append(f"check row {index} is malformed")
                continue
            name_value = check.get("name")
            bucket = str(check.get("bucket") or "").lower()
            state = str(check.get("state") or "").upper()
            if not isinstance(name_value, str) or not name_value:
                reasons.append(f"check row {index} has no name")
            if bucket not in safe_buckets:
                reasons.append(f"check {name_value} bucket={bucket or 'missing'}")
            if bucket == "pass" and state != "SUCCESS":
                reasons.append(f"check {name_value} state={state or 'missing'}")
            if bucket == "skipping" and state not in {"SKIPPED", "NEUTRAL"}:
                reasons.append(f"check {name_value} state={state or 'missing'}")

        target_state = "ready" if not reasons else "blocked"
        target = {
            "path": str(repository_path),
            "kind": "explicit",
            "repository": repository,
            "repositoryPolicy": {
                "mergeCommitAllowed": repo.get("mergeCommitAllowed"),
                "rebaseMergeAllowed": repo.get("rebaseMergeAllowed"),
                "squashMergeAllowed": repo.get("squashMergeAllowed"),
            },
            "state": target_state,
            "pr": {
                "number": pr.get("number"),
                "url": pr.get("url"),
                "state": pr.get("state"),
                "headRefName": pr.get("headRefName"),
                "headSha": pr.get("headRefOid"),
                "baseRefName": pr.get("baseRefName"),
                "baseSha": pr.get("baseRefOid"),
                "mergeable": pr.get("mergeable"),
                "mergeStateStatus": pr.get("mergeStateStatus"),
                "reviewDecision": pr.get("reviewDecision"),
                "autoMergeEnabled": False,
                "autoMerge": None,
                "mergeQueueEntry": None,
                "isMergeQueueEnabled": queue_enabled,
            },
            "checks": {
                "total": len(checks),
                "pass": [item.get("name") for item in checks if isinstance(item, dict) and str(item.get("bucket")).lower() == "pass"],
                "fail": [],
                "pending": [],
                "skipping": [item.get("name") for item in checks if isinstance(item, dict) and str(item.get("bucket")).lower() == "skipping"],
                "unknown": [],
                "malformed": [],
            },
            "reviews": {
                "unresolvedThreadCount": len(unresolved),
                "requiredReviewers": [],
                "missingRequiredReviewers": [],
            },
            "actions": [] if not reasons else [{"type": "blocked", "reason": "; ".join(reasons)}],
            "pending": [],
        }
        result = {
            "schemaVersion": 1,
            "observedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "state": target_state,
            "policy": {
                "source": "no-config",
                "configPath": None,
                "checkPolicy": "all",
                "strictChangesRequested": False,
                "requiredReviewers": [],
            },
            "targets": [target],
            "actions": target["actions"],
            "errors": [],
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
        return 0 if target_state == "ready" else 20
    except Exception as error:
        return emit_blocked(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
