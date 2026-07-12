from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .execution import (
    ALLOWED_DOCKER_IMAGES,
    DEFAULT_DOCKER_IMAGE,
    TEST_ISOLATIONS,
    ExecutionPolicy,
    ExecutionSafetyError,
    TEST_PROFILES,
    WorkspaceExecutor,
)
from .models import Issue
from .runner import run_job


def build_plan_parser(prog: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, description="Plan a RepoSteward maintenance job")
    parser.add_argument("issue", type=Path, help="Path to a GitHub issue JSON fixture")
    parser.add_argument("--output", type=Path, help="Optional path for the durable run receipt")
    return parser


def build_execute_parser(prog: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, description="Execute an approved RepoSteward patch in a constrained workspace")
    parser.add_argument("issue", type=Path, help="Path to a GitHub issue JSON fixture")
    parser.add_argument("--repository", required=True, help="HTTPS GitHub URL or explicitly authorized local Git repository")
    parser.add_argument("--patch", required=True, type=Path, help="Candidate unified-diff file")
    parser.add_argument("--workspace-root", type=Path, default=Path("build/workspaces"))
    parser.add_argument("--test-profile", choices=sorted(TEST_PROFILES), default="python-unittest")
    parser.add_argument(
        "--test-isolation",
        choices=TEST_ISOLATIONS,
        default="process",
        help="Run tests in the trusted host process or a constrained Docker Linux container",
    )
    parser.add_argument(
        "--docker-image",
        choices=ALLOWED_DOCKER_IMAGES,
        default=DEFAULT_DOCKER_IMAGE,
        help="Pre-pulled Docker image to resolve to an immutable local image ID",
    )
    parser.add_argument("--allow-local-repository", action="store_true", help="Permit cloning a local disposable Git repository")
    parser.add_argument(
        "--allow-trusted-test-execution",
        action="store_true",
        help="Authorize process-mode tests; patched code is not OS- or network-sandboxed",
    )
    parser.add_argument("--output", type=Path, help="Optional path for the execution receipt")
    return parser


def _load_issue(path: Path) -> Issue:
    return Issue.from_dict(json.loads(path.read_text(encoding="utf-8")))


def _render(value: dict[str, object], output: Path | None) -> None:
    rendered = json.dumps(value, indent=2)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{rendered}\n", encoding="utf-8")
    print(rendered)


def run_plan(argv: list[str], prog: str | None = None) -> int:
    args = build_plan_parser(prog).parse_args(argv)
    _render(run_job(_load_issue(args.issue)).to_dict(), args.output)
    return 0


def run_execute(argv: list[str], prog: str | None = None) -> int:
    args = build_execute_parser(prog).parse_args(argv)
    issue = _load_issue(args.issue)
    plan = run_job(issue)
    if plan.final_decision["status"] != "PROCEED_TO_PATCH":
        _render({
            "contractVersion": "reposteward.execution.v1",
            "status": "BLOCKED_PLANNING_REVIEW",
            "planningRunId": plan.run_id,
            "planningDecision": plan.final_decision,
        }, args.output)
        return 2

    try:
        policy = ExecutionPolicy(
            allow_local_repository=args.allow_local_repository,
            allow_test_execution=args.allow_trusted_test_execution,
            test_isolation=args.test_isolation,
            docker_image=args.docker_image,
        )
        executor = WorkspaceExecutor(args.workspace_root, policy)
        receipt = executor.execute(
            issue,
            args.repository,
            args.patch.read_text(encoding="utf-8"),
            args.test_profile,
        )
    except ExecutionSafetyError as error:
        _render({
            "contractVersion": "reposteward.execution.v1",
            "status": "BLOCKED_SAFETY_POLICY",
            "planningRunId": plan.run_id,
            "error": str(error),
        }, args.output)
        return 2
    receipt["planningRunId"] = plan.run_id
    receipt["planningDecision"] = plan.final_decision
    _render(receipt, args.output)
    return 0 if receipt["status"] == "AWAITING_HUMAN_APPROVAL" else 1


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "execute":
        return run_execute(arguments[1:], "reposteward execute")
    if arguments and arguments[0] == "plan":
        return run_plan(arguments[1:], "reposteward plan")
    return run_plan(arguments, "reposteward")
