from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

from .approval import (
    APPROVAL_CONTRACT_VERSION,
    APPROVAL_KEY_ENV,
    DEFAULT_APPROVAL_TTL_MINUTES,
    MAX_APPROVAL_TTL_MINUTES,
    ApprovalSafetyError,
    create_approval,
    expected_confirmation,
    load_strict_json,
    validate_execution_for_publication,
)
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
from .publication import (
    GITHUB_TOKEN_ENV,
    PUBLICATION_CONTRACT_VERSION,
    GitHubRestTransport,
    GitHubTransportError,
    PublicationSafetyError,
    prepare_publication,
    publish_prepared,
    snapshot_workspace,
)
from .runner import run_job


MAX_ARTIFACT_BYTES = 2 * 1024 * 1024


class _ArtifactReservation:
    """Persist a reservation receipt, then atomically replace it with the final receipt."""

    def __init__(self, output: Path, *, publication_id: str, execution_id: str):
        self.output = output
        self._finalized = False
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(
                output,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError as error:
            raise PublicationSafetyError(f"Artifact output already exists: {output}") from error
        except OSError as error:
            raise PublicationSafetyError(f"Could not reserve publication artifact: {output}") from error
        sentinel = {
            "contractVersion": PUBLICATION_CONTRACT_VERSION,
            "publicationId": publication_id,
            "executionId": execution_id,
            "status": "PUBLICATION_IN_PROGRESS",
            "message": "The audit path was reserved before any GitHub mutation; reconcile before retrying.",
        }
        try:
            self._write_descriptor(descriptor, sentinel)
            os.close(descriptor)
            descriptor = -1
            self._fsync_parent()
        except OSError as error:
            try:
                output.unlink()
            except OSError:
                pass
            raise PublicationSafetyError("Could not durably reserve the publication artifact.") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _write_descriptor(descriptor: int, value: dict[str, object]) -> None:
        data = (json.dumps(value, indent=2) + "\n").encode("utf-8")
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written < 1:
                raise OSError("zero-byte artifact write")
            offset += written
        os.fsync(descriptor)

    def _fsync_parent(self) -> None:
        if os.name == "nt":
            return
        directory = os.open(
            self.output.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def write(self, value: dict[str, object]) -> None:
        if self._finalized:
            raise PublicationSafetyError("Publication artifact reservation is already finalized.")
        temporary = self.output.with_name(
            f".{self.output.name}.{secrets.token_hex(8)}.tmp"
        )
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
            self._write_descriptor(descriptor, value)
            os.close(descriptor)
            descriptor = None
            os.replace(temporary, self.output)
            self._fsync_parent()
        except OSError as error:
            raise PublicationSafetyError(
                "Could not durably replace the reserved publication artifact. "
                "The existing audit artifact was retained for reconciliation."
            ) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        self._finalized = True


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


def build_approve_parser(prog: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, description="Create a short-lived human approval artifact")
    parser.add_argument("receipt", type=Path, help="Successful Docker execution receipt")
    parser.add_argument("--workspace-root", required=True, type=Path, help="Root containing the execution workspace")
    parser.add_argument("--approver", required=True, help="GitHub login of the human approver")
    parser.add_argument(
        "--ttl-minutes",
        type=int,
        default=DEFAULT_APPROVAL_TTL_MINUTES,
        choices=range(1, MAX_APPROVAL_TTL_MINUTES + 1),
    )
    parser.add_argument("--output", required=True, type=Path, help="New approval artifact path")
    return parser


def build_publish_parser(prog: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, description="Publish one approval-bound GitHub draft pull request")
    parser.add_argument("--receipt", required=True, type=Path, help="Successful Docker execution receipt")
    parser.add_argument("--approval", required=True, type=Path, help="Short-lived approval artifact")
    parser.add_argument("--workspace-root", required=True, type=Path, help="Root containing the execution workspace")
    parser.add_argument("--output", required=True, type=Path, help="New publication receipt path")
    return parser


def _load_issue(path: Path) -> Issue:
    return Issue.from_dict(json.loads(path.read_text(encoding="utf-8")))


def _render(value: dict[str, object], output: Path | None) -> None:
    rendered = json.dumps(value, indent=2)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{rendered}\n", encoding="utf-8")
    print(rendered)


def _write_new_artifact(value: dict[str, object], output: Path) -> None:
    rendered = json.dumps(value, indent=2)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(f"{rendered}\n")
    except FileExistsError as error:
        raise ApprovalSafetyError(f"Artifact output already exists: {output}") from error
    if os.name != "nt":
        output.chmod(0o600)
    print(rendered)


def _load_artifact(path: Path) -> dict[str, object]:
    try:
        if path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ApprovalSafetyError(f"Artifact exceeds the {MAX_ARTIFACT_BYTES}-byte limit: {path}")
        return load_strict_json(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ApprovalSafetyError(f"Could not read artifact: {path}") from error


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


def run_approve(argv: list[str], prog: str | None = None) -> int:
    args = build_approve_parser(prog).parse_args(argv)
    try:
        if args.output.exists():
            raise ApprovalSafetyError(f"Artifact output already exists: {args.output}")
        execution = _load_artifact(args.receipt)
        binding = validate_execution_for_publication(execution)
        snapshot_workspace(execution, workspace_root=args.workspace_root)
        key = os.environ.get(APPROVAL_KEY_ENV, "")
        if not sys.stdin.isatty():
            raise ApprovalSafetyError("Human approval requires an interactive terminal.")
        challenge = expected_confirmation(execution)
        print("RepoSteward draft-PR approval", file=sys.stderr)
        print(f"Repository: {binding['repository']}", file=sys.stderr)
        print(f"Issue: #{binding['issueNumber']}", file=sys.stderr)
        print(f"Base: {binding['baseBranch']} @ {binding['baseCommit']}", file=sys.stderr)
        print(f"Applied diff: {binding['appliedDiffSha256']}", file=sys.stderr)
        print("Changed files:", file=sys.stderr)
        for path in binding["changedFiles"]:
            print(f"  - {path}", file=sys.stderr)
        try:
            confirmation = input(f'Type "{challenge}" to approve one draft PR: ')
        except EOFError as error:
            raise ApprovalSafetyError("Human approval input was cancelled.") from error
        approval = create_approval(
            execution,
            approver=args.approver,
            confirmation=confirmation,
            key=key,
            ttl_minutes=args.ttl_minutes,
        )
        _write_new_artifact(approval, args.output)
        return 0
    except (ApprovalSafetyError, PublicationSafetyError) as error:
        _render({
            "contractVersion": APPROVAL_CONTRACT_VERSION,
            "status": "BLOCKED_APPROVAL_POLICY",
            "error": str(error),
        }, None)
        return 2


def run_publish(argv: list[str], prog: str | None = None) -> int:
    args = build_publish_parser(prog).parse_args(argv)
    try:
        execution = _load_artifact(args.receipt)
        approval = _load_artifact(args.approval)
        prepared = prepare_publication(
            execution,
            approval,
            approval_key=os.environ.get(APPROVAL_KEY_ENV, ""),
            workspace_root=args.workspace_root,
        )
        reservation = _ArtifactReservation(
            args.output,
            publication_id=prepared.publication_id,
            execution_id=prepared.intent["executionId"],
        )
    except (ApprovalSafetyError, PublicationSafetyError) as error:
        _render({
            "contractVersion": PUBLICATION_CONTRACT_VERSION,
            "status": "BLOCKED_PUBLICATION_POLICY",
            "error": str(error),
        }, None)
        return 2

    try:
        token = os.environ.get(GITHUB_TOKEN_ENV, "")
        transport = GitHubRestTransport(token)
        receipt = publish_prepared(prepared, transport)
    except (ApprovalSafetyError, PublicationSafetyError, GitHubTransportError) as error:
        blocked = {
            "contractVersion": PUBLICATION_CONTRACT_VERSION,
            "status": (
                "BLOCKED_GITHUB_TRANSPORT"
                if isinstance(error, GitHubTransportError)
                else "BLOCKED_PUBLICATION_POLICY"
            ),
            "error": str(error),
        }
        try:
            reservation.write(blocked)
        except PublicationSafetyError as audit_error:
            print(
                json.dumps({
                    "contractVersion": PUBLICATION_CONTRACT_VERSION,
                    "status": "CRITICAL_AUDIT_WRITE_FAILED",
                    "publicationId": prepared.publication_id,
                    "error": str(audit_error),
                }, indent=2),
                file=sys.stderr,
            )
            return 3
        print(json.dumps(blocked, indent=2))
        return 2

    try:
        reservation.write(receipt)
    except PublicationSafetyError as audit_error:
        print(
            json.dumps({
                "contractVersion": PUBLICATION_CONTRACT_VERSION,
                "status": "CRITICAL_AUDIT_WRITE_FAILED",
                "publicationId": prepared.publication_id,
                "error": str(audit_error),
                "publicationOutcome": receipt,
            }, indent=2),
            file=sys.stderr,
        )
        return 3
    print(json.dumps(receipt, indent=2))
    if receipt["status"] in {"DRAFT_PR_CREATED", "DRAFT_PR_REUSED"}:
        return 0
    return 1


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "approve":
        return run_approve(arguments[1:], "reposteward approve")
    if arguments and arguments[0] == "publish":
        return run_publish(arguments[1:], "reposteward publish")
    if arguments and arguments[0] == "execute":
        return run_execute(arguments[1:], "reposteward execute")
    if arguments and arguments[0] == "plan":
        return run_plan(arguments[1:], "reposteward plan")
    return run_plan(arguments, "reposteward")
