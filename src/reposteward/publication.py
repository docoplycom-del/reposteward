from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import shutil
import subprocess
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import quote, urlencode

from .approval import (
    ApprovalSafetyError,
    build_publication_intent,
    canonical_sha256,
    validate_branch,
    validate_execution_for_publication,
    verify_approval,
)


PUBLICATION_CONTRACT_VERSION = "reposteward.publication.v1"
GITHUB_TOKEN_ENV = "REPOSTEWARD_GITHUB_TOKEN"
MAX_GITHUB_RESPONSE_BYTES = 1024 * 1024
MAX_PUBLISH_FILE_BYTES = 2 * 1024 * 1024
MIN_APPROVAL_REMAINING = timedelta(seconds=30)
GIT_SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$")
GITHUB_BLOB_SHA_PATTERN = GIT_SHA_PATTERN


class PublicationSafetyError(RuntimeError):
    """Raised before or during a fail-closed publication attempt."""


class GitHubTransportError(RuntimeError):
    def __init__(self, operation: str, message: str, status: int | None = None):
        self.operation = operation
        self.status = status
        super().__init__(f"GitHub {operation} failed: {message}")


@dataclass(frozen=True)
class IndexedFile:
    path: str
    mode: str
    blob_sha: str
    content: bytes


@dataclass(frozen=True)
class WorkspaceSnapshot:
    path: Path
    base_commit: str
    base_branch: str
    applied_diff_sha256: str
    tree_sha: str
    files: tuple[IndexedFile, ...]


@dataclass(frozen=True)
class PreparedPublication:
    execution: dict[str, Any]
    execution_binding: dict[str, Any]
    approval: dict[str, Any]
    approval_summary: dict[str, Any]
    intent: dict[str, Any]
    workspace_root: Path
    workspace: WorkspaceSnapshot
    publication_id: str


class GitHubTransport(Protocol):
    def authenticated_login(self) -> str: ...

    def repository(self, repository: str) -> dict[str, Any]: ...

    def ref(self, repository: str, branch: str) -> str | None: ...

    def git_commit(self, repository: str, sha: str) -> dict[str, Any]: ...

    def create_blob(self, repository: str, content: bytes) -> str: ...

    def create_tree(
        self,
        repository: str,
        base_tree: str,
        files: tuple[IndexedFile, ...],
        blob_shas: dict[str, str],
    ) -> str: ...

    def create_commit(
        self,
        repository: str,
        message: str,
        tree_sha: str,
        parent_sha: str,
    ) -> str: ...

    def create_ref(self, repository: str, branch: str, sha: str) -> None: ...

    def matching_pull_requests(
        self,
        repository: str,
        owner: str,
        head_branch: str,
        base_branch: str,
    ) -> list[dict[str, Any]]: ...

    def create_draft_pull_request(
        self,
        repository: str,
        title: str,
        body: str,
        head_branch: str,
        base_branch: str,
    ) -> dict[str, Any]: ...

    def pull_request(self, repository: str, number: int) -> dict[str, Any]: ...


def _strict_github_json(raw: bytes, operation: str) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite value: {value}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate key: {key}")
            value[key] = item
        return value

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise GitHubTransportError(operation, "response was not valid UTF-8 JSON") from error


def _github_error_message(raw: bytes, token: str) -> str:
    try:
        value = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return "unexpected response"
    message = value.get("message") if isinstance(value, dict) else None
    rendered = str(message)[:500] if message else "unexpected response"
    if token:
        rendered = rendered.replace(f"Bearer {token}", "Bearer [REDACTED]").replace(token, "[REDACTED]")
    return rendered


class GitHubRestTransport:
    """Fixed-host REST transport. It has no redirect, ref-update, delete, merge or ready operations."""

    def __init__(self, token: str, *, timeout_seconds: int = 20):
        if not token or any(character in token for character in "\r\n"):
            raise PublicationSafetyError(f"{GITHUB_TOKEN_ENV} is missing or invalid.")
        self._token = token
        self._timeout_seconds = timeout_seconds

    @staticmethod
    def _repo_path(repository: str) -> str:
        owner, name = repository.split("/", 1)
        return f"/repos/{quote(owner, safe='')}/{quote(name, safe='')}"

    def _request(
        self,
        method: str,
        path: str,
        *,
        operation: str,
        payload: dict[str, Any] | None = None,
        expected: tuple[int, ...] = (200,),
        allow_not_found: bool = False,
    ) -> Any:
        if not path.startswith("/") or "\r" in path or "\n" in path:
            raise PublicationSafetyError("GitHub request path is invalid.")
        body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8") if payload is not None else None
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "RepoSteward/0.1",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPSConnection("api.github.com", timeout=self._timeout_seconds)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(MAX_GITHUB_RESPONSE_BYTES + 1)
        except (OSError, http.client.HTTPException) as error:
            raise GitHubTransportError(operation, "network request did not complete") from error
        finally:
            connection.close()
        if len(raw) > MAX_GITHUB_RESPONSE_BYTES:
            raise GitHubTransportError(operation, "response exceeded the size limit", response.status)
        if allow_not_found and response.status == 404:
            return None
        if response.status not in expected:
            raise GitHubTransportError(operation, _github_error_message(raw, self._token), response.status)
        if response.status == 204 or not raw:
            return None
        return _strict_github_json(raw, operation)

    def authenticated_login(self) -> str:
        value = self._request("GET", "/user", operation="identity verification")
        login = value.get("login") if isinstance(value, dict) else None
        if not isinstance(login, str):
            raise GitHubTransportError("identity verification", "response omitted login")
        return login

    def repository(self, repository: str) -> dict[str, Any]:
        value = self._request("GET", self._repo_path(repository), operation="repository inspection")
        if not isinstance(value, dict):
            raise GitHubTransportError("repository inspection", "unexpected response")
        return value

    def ref(self, repository: str, branch: str) -> str | None:
        branch = validate_branch(branch, "GitHub branch")
        path = f"{self._repo_path(repository)}/git/ref/{quote(f'heads/{branch}', safe='/')}"
        value = self._request(
            "GET",
            path,
            operation="reference inspection",
            allow_not_found=True,
        )
        if value is None:
            return None
        sha = ((value.get("object") or {}).get("sha")) if isinstance(value, dict) else None
        if not isinstance(sha, str) or not GIT_SHA_PATTERN.fullmatch(sha):
            raise GitHubTransportError("reference inspection", "response omitted a valid commit SHA")
        return sha

    def git_commit(self, repository: str, sha: str) -> dict[str, Any]:
        if not GIT_SHA_PATTERN.fullmatch(sha):
            raise PublicationSafetyError("GitHub commit lookup received an invalid SHA.")
        value = self._request(
            "GET",
            f"{self._repo_path(repository)}/git/commits/{sha}",
            operation="commit inspection",
        )
        if not isinstance(value, dict):
            raise GitHubTransportError("commit inspection", "unexpected response")
        return value

    def create_blob(self, repository: str, content: bytes) -> str:
        value = self._request(
            "POST",
            f"{self._repo_path(repository)}/git/blobs",
            operation="blob creation",
            payload={"content": base64.b64encode(content).decode("ascii"), "encoding": "base64"},
            expected=(201,),
        )
        sha = value.get("sha") if isinstance(value, dict) else None
        if not isinstance(sha, str) or not GITHUB_BLOB_SHA_PATTERN.fullmatch(sha):
            raise GitHubTransportError("blob creation", "response omitted a valid blob SHA")
        return sha

    def create_tree(
        self,
        repository: str,
        base_tree: str,
        files: tuple[IndexedFile, ...],
        blob_shas: dict[str, str],
    ) -> str:
        value = self._request(
            "POST",
            f"{self._repo_path(repository)}/git/trees",
            operation="tree creation",
            payload={
                "base_tree": base_tree,
                "tree": [
                    {"path": item.path, "mode": item.mode, "type": "blob", "sha": blob_shas[item.path]}
                    for item in files
                ],
            },
            expected=(201,),
        )
        sha = value.get("sha") if isinstance(value, dict) else None
        if not isinstance(sha, str) or not GIT_SHA_PATTERN.fullmatch(sha):
            raise GitHubTransportError("tree creation", "response omitted a valid tree SHA")
        return sha

    def create_commit(self, repository: str, message: str, tree_sha: str, parent_sha: str) -> str:
        value = self._request(
            "POST",
            f"{self._repo_path(repository)}/git/commits",
            operation="commit creation",
            payload={"message": message, "tree": tree_sha, "parents": [parent_sha]},
            expected=(201,),
        )
        sha = value.get("sha") if isinstance(value, dict) else None
        if not isinstance(sha, str) or not GIT_SHA_PATTERN.fullmatch(sha):
            raise GitHubTransportError("commit creation", "response omitted a valid commit SHA")
        return sha

    def create_ref(self, repository: str, branch: str, sha: str) -> None:
        self._request(
            "POST",
            f"{self._repo_path(repository)}/git/refs",
            operation="reference creation",
            payload={"ref": f"refs/heads/{branch}", "sha": sha},
            expected=(201,),
        )

    def matching_pull_requests(
        self,
        repository: str,
        owner: str,
        head_branch: str,
        base_branch: str,
    ) -> list[dict[str, Any]]:
        query = urlencode({"state": "all", "head": f"{owner}:{head_branch}", "base": base_branch, "per_page": 10})
        value = self._request(
            "GET",
            f"{self._repo_path(repository)}/pulls?{query}",
            operation="pull request reconciliation",
        )
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise GitHubTransportError("pull request reconciliation", "unexpected response")
        return value

    def create_draft_pull_request(
        self,
        repository: str,
        title: str,
        body: str,
        head_branch: str,
        base_branch: str,
    ) -> dict[str, Any]:
        value = self._request(
            "POST",
            f"{self._repo_path(repository)}/pulls",
            operation="draft pull request creation",
            payload={"title": title, "body": body, "head": head_branch, "base": base_branch, "draft": True},
            expected=(201,),
        )
        if not isinstance(value, dict):
            raise GitHubTransportError("draft pull request creation", "unexpected response")
        return value

    def pull_request(self, repository: str, number: int) -> dict[str, Any]:
        value = self._request(
            "GET",
            f"{self._repo_path(repository)}/pulls/{number}",
            operation="pull request verification",
        )
        if not isinstance(value, dict):
            raise GitHubTransportError("pull request verification", "unexpected response")
        return value


def _git_environment() -> dict[str, str]:
    environment = {
        "PATH": os.defpath,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "TMP", "TEMP", "LANG", "LC_ALL"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def _run_git(git: str, repository: Path, *arguments: str, binary: bool = False) -> bytes | str:
    try:
        result = subprocess.run(
            [git, *arguments],
            cwd=repository,
            env=_git_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=not binary,
            encoding=None if binary else "utf-8",
            errors=None if binary else "replace",
            shell=False,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PublicationSafetyError("Git workspace verification did not complete.") from error
    if result.returncode != 0:
        detail_value = result.stderr
        detail = (
            detail_value.decode("utf-8", errors="replace")
            if isinstance(detail_value, bytes)
            else detail_value
        ).strip()[-1000:]
        raise PublicationSafetyError(f"Git workspace verification failed: {detail}")
    return result.stdout


def _parse_status(raw: str) -> list[str]:
    paths: list[str] = []
    for entry in (item for item in raw.split("\x00") if item):
        if len(entry) < 4 or entry[:2] != "M ":
            raise PublicationSafetyError("Workspace may contain only staged modifications to approved files.")
        paths.append(entry[3:])
    return sorted(paths)


def snapshot_workspace(
    execution: dict[str, Any],
    *,
    workspace_root: Path,
) -> WorkspaceSnapshot:
    binding = validate_execution_for_publication(execution)
    try:
        root = workspace_root.resolve(strict=True)
        raw_repository = Path(binding["workspacePath"])
        if raw_repository.is_symlink():
            raise PublicationSafetyError("Execution workspace path may not be a symlink.")
        repository = raw_repository.resolve(strict=True)
    except OSError as error:
        raise PublicationSafetyError("Workspace root and execution workspace must exist.") from error
    if not root.is_dir() or not repository.is_dir() or not repository.is_relative_to(root) or repository == root:
        raise PublicationSafetyError("Execution workspace must resolve strictly beneath workspace-root.")
    git_directory = repository / ".git"
    if not git_directory.is_dir() or git_directory.is_symlink():
        raise PublicationSafetyError("Execution workspace must contain a real, non-symlink .git directory.")
    git = shutil.which("git")
    if not git:
        raise PublicationSafetyError("Git is required for publication verification.")

    absolute_git_directory = Path(
        str(_run_git(git, repository, "rev-parse", "--absolute-git-dir")).strip()
    ).resolve(strict=True)
    common_git_directory = Path(
        str(_run_git(git, repository, "rev-parse", "--git-common-dir")).strip()
    )
    if not common_git_directory.is_absolute():
        common_git_directory = (repository / common_git_directory).resolve(strict=True)
    else:
        common_git_directory = common_git_directory.resolve(strict=True)
    if (
        not absolute_git_directory.is_relative_to(repository)
        or not common_git_directory.is_relative_to(repository)
        or absolute_git_directory != git_directory.resolve(strict=True)
        or common_git_directory != git_directory.resolve(strict=True)
    ):
        raise PublicationSafetyError("Git metadata must remain entirely inside the execution workspace.")

    head = str(_run_git(git, repository, "rev-parse", "HEAD")).strip()
    branch = str(_run_git(git, repository, "symbolic-ref", "--quiet", "--short", "HEAD")).strip()
    if head != binding["baseCommit"] or branch != binding["baseBranch"]:
        raise PublicationSafetyError("Workspace HEAD or base branch no longer matches the execution receipt.")
    if str(_run_git(git, repository, "remote")).strip():
        raise PublicationSafetyError("Execution workspace regained a Git remote.")
    status = _parse_status(str(_run_git(git, repository, "status", "--porcelain=v1", "-z", "--untracked-files=all")))
    if status != binding["changedFiles"]:
        raise PublicationSafetyError("Workspace status does not match the approved changed files.")
    _run_git(git, repository, "diff", "--cached", "--check", "--")
    diff = str(_run_git(git, repository, "diff", "--cached", "--no-ext-diff", "--binary", "--full-index", "--"))
    if diff != execution["patch"]["unifiedDiff"]:
        raise PublicationSafetyError("Workspace staged diff no longer equals the tested execution diff.")
    diff_sha256 = hashlib.sha256(diff.encode("utf-8")).hexdigest()
    if diff_sha256 != binding["appliedDiffSha256"]:
        raise PublicationSafetyError("Workspace staged diff digest no longer matches the execution receipt.")

    files: list[IndexedFile] = []
    for path in binding["changedFiles"]:
        entry = str(_run_git(git, repository, "ls-files", "--stage", "-z", "--", path))
        records = [item for item in entry.split("\x00") if item]
        if len(records) != 1:
            raise PublicationSafetyError(f"Approved index path is missing or ambiguous: {path}")
        metadata, separator, indexed_path = records[0].partition("\t")
        parts = metadata.split(" ")
        if not separator or indexed_path != path or len(parts) != 3:
            raise PublicationSafetyError(f"Could not parse approved index entry: {path}")
        mode, blob_sha, stage = parts
        if mode not in {"100644", "100755"} or stage != "0" or not GIT_SHA_PATTERN.fullmatch(blob_sha):
            raise PublicationSafetyError(f"Approved index entry has an unsafe mode or stage: {path}")
        content = _run_git(git, repository, "cat-file", "blob", blob_sha, binary=True)
        assert isinstance(content, bytes)
        if len(content) > MAX_PUBLISH_FILE_BYTES:
            raise PublicationSafetyError(f"Approved file exceeds the publication size limit: {path}")
        try:
            content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise PublicationSafetyError(f"Approved file is not UTF-8 text: {path}") from error
        files.append(IndexedFile(path=path, mode=mode, blob_sha=blob_sha, content=content))

    tree_sha = str(_run_git(git, repository, "write-tree")).strip()
    if not GIT_SHA_PATTERN.fullmatch(tree_sha):
        raise PublicationSafetyError("Git did not return a valid tested tree SHA.")
    repeated_status = _parse_status(str(_run_git(git, repository, "status", "--porcelain=v1", "-z", "--untracked-files=all")))
    repeated_diff = str(_run_git(git, repository, "diff", "--cached", "--no-ext-diff", "--binary", "--full-index", "--"))
    repeated_head = str(_run_git(git, repository, "rev-parse", "HEAD")).strip()
    if repeated_status != status or repeated_diff != diff or repeated_head != head:
        raise PublicationSafetyError("Execution workspace changed during publication capture.")
    return WorkspaceSnapshot(
        path=repository,
        base_commit=head,
        base_branch=branch,
        applied_diff_sha256=diff_sha256,
        tree_sha=tree_sha,
        files=tuple(files),
    )


class PublicationLock(AbstractContextManager["PublicationLock"]):
    def __init__(self, workspace_root: Path, publication_id: str):
        self.path = workspace_root.resolve() / f".{publication_id.lower()}.lock"
        self._handle: int | None = None

    def __enter__(self) -> "PublicationLock":
        try:
            self._handle = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(self._handle, b"RepoSteward publication lock\n")
        except FileExistsError as error:
            raise PublicationSafetyError("Another publication attempt holds the execution lock.") from error
        except OSError as error:
            raise PublicationSafetyError("Could not create the exclusive publication lock.") from error
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        if self._handle is not None:
            os.close(self._handle)
            self._handle = None
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def prepare_publication(
    execution: dict[str, Any],
    approval: dict[str, Any],
    *,
    approval_key: str | bytes,
    workspace_root: Path,
    now: Any = None,
) -> PreparedPublication:
    execution_binding = validate_execution_for_publication(execution)
    approval_summary = verify_approval(execution, approval, key=approval_key, now=now)
    intent = build_publication_intent(execution)
    workspace = snapshot_workspace(execution, workspace_root=workspace_root)
    publication_id = "RSP-" + canonical_sha256({
        "contractVersion": PUBLICATION_CONTRACT_VERSION,
        "repository": intent["repository"],
        "executionReceiptSha256": intent["receiptSha256"],
        "executionId": intent["executionId"],
        "baseCommit": intent["baseCommit"],
        "appliedDiffSha256": intent["appliedDiffSha256"],
    })[:24].upper()
    return PreparedPublication(
        execution=execution,
        execution_binding=execution_binding,
        approval=approval,
        approval_summary=approval_summary,
        intent=intent,
        workspace_root=workspace_root.resolve(),
        workspace=workspace,
        publication_id=publication_id,
    )


def _commit_message(prepared: PreparedPublication) -> str:
    return (
        f"RepoSteward proposal for issue #{prepared.intent['issueNumber']}\n\n"
        f"Execution: {prepared.intent['executionId']}\n"
        f"Publication: {prepared.publication_id}\n"
        f"Applied-Diff-SHA256: {prepared.intent['appliedDiffSha256']}"
    )


def _ensure_approval_current(prepared: PreparedPublication, current: datetime) -> None:
    expires_value = prepared.approval_summary.get("expiresAt")
    if not isinstance(expires_value, str) or not expires_value.endswith("Z"):
        raise PublicationSafetyError("Approval expiry is missing from the prepared publication.")
    try:
        expires_at = datetime.fromisoformat(expires_value[:-1] + "+00:00")
    except ValueError as error:
        raise PublicationSafetyError("Approval expiry is invalid.") from error
    now = current.astimezone(timezone.utc)
    if now + MIN_APPROVAL_REMAINING > expires_at:
        raise PublicationSafetyError(
            "Approval has expired or has less than 30 seconds remaining before remote mutation."
        )


def _verify_remote_commit(commit: dict[str, Any], prepared: PreparedPublication) -> bool:
    tree_sha = ((commit.get("tree") or {}).get("sha")) if isinstance(commit, dict) else None
    parents = commit.get("parents") if isinstance(commit, dict) else None
    parent_shas = [parent.get("sha") for parent in parents] if isinstance(parents, list) else []
    message = commit.get("message") if isinstance(commit, dict) else None
    return (
        tree_sha == prepared.workspace.tree_sha
        and parent_shas == [prepared.intent["baseCommit"]]
        and message == _commit_message(prepared)
    )


def _verify_pull_request(
    pull: dict[str, Any],
    prepared: PreparedPublication,
    commit_sha: str,
    repository_id: int,
    repository_full_name: str,
) -> dict[str, Any]:
    number = pull.get("number")
    url = pull.get("html_url")
    expected_url = (
        f"https://github.com/{repository_full_name}/pull/{number}"
        if isinstance(number, int) and not isinstance(number, bool)
        else ""
    )
    head = pull.get("head") or {}
    base = pull.get("base") or {}
    head_repository = head.get("repo") or {}
    base_repository = base.get("repo") or {}
    if (
        not isinstance(number, int)
        or isinstance(number, bool)
        or number < 1
        or url != expected_url
        or pull.get("state") != "open"
        or pull.get("draft") is not True
        or pull.get("merged_at") is not None
        or pull.get("title") != prepared.intent["title"]
        or pull.get("body") != prepared.intent["body"]
        or base.get("ref") != prepared.intent["baseBranch"]
        or head.get("ref") != prepared.intent["headBranch"]
        or head.get("sha") != commit_sha
        or base_repository.get("id") != repository_id
        or head_repository.get("id") != repository_id
        or base_repository.get("full_name") != repository_full_name
        or head_repository.get("full_name") != repository_full_name
    ):
        raise PublicationSafetyError("GitHub pull request postcondition verification failed.")
    return {"number": number, "url": url}


def _publication_receipt(
    prepared: PreparedPublication,
    *,
    status: str,
    repository_id: int,
    commit_sha: str | None,
    pull_request: dict[str, Any] | None,
    base_head_after: str | None,
    error: str | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "contractVersion": PUBLICATION_CONTRACT_VERSION,
        "publicationId": prepared.publication_id,
        "status": status,
        "executionId": prepared.intent["executionId"],
        "executionReceiptSha256": prepared.intent["receiptSha256"],
        "approvalId": prepared.approval_summary["approvalId"],
        "approvedBy": prepared.approval_summary["approvedBy"],
        "repository": {
            "fullName": prepared.intent["repository"],
            "id": repository_id,
            "baseBranch": prepared.intent["baseBranch"],
            "baseCommit": prepared.intent["baseCommit"],
            "baseHeadAfterPublication": base_head_after,
            "headBranch": prepared.intent["headBranch"],
            "publicationCommit": commit_sha,
        },
        "patch": {
            "candidateSha256": prepared.intent["candidateSha256"],
            "appliedDiffSha256": prepared.intent["appliedDiffSha256"],
            "treeSha": prepared.workspace.tree_sha,
            "changedFiles": prepared.intent["changedFiles"],
        },
        "pullRequest": pull_request,
        "controls": {
            "sourceWorkspaceRevalidated": True,
            "baseFastForwardRequired": True,
            "forceUpdateOperationExposed": False,
            "mergeOperationExposed": False,
            "readyForReviewOperationExposed": False,
            "draftOnly": True,
            "credentialsPersisted": False,
            "tokenIncludedInReceipt": False,
        },
    }
    if error:
        value["error"] = error[:1000]
    return value


def _best_effort_ref(
    transport: GitHubTransport,
    repository: str,
    branch: str,
) -> str | None:
    try:
        return transport.ref(repository, branch)
    except (GitHubTransportError, PublicationSafetyError):
        return None


def _reconcile_existing(
    prepared: PreparedPublication,
    transport: GitHubTransport,
    *,
    repository_id: int,
    repository_full_name: str,
    owner: str,
    head_sha: str,
    current_time: Callable[[], datetime],
) -> dict[str, Any]:
    commit = transport.git_commit(prepared.intent["repository"], head_sha)
    if not _verify_remote_commit(commit, prepared):
        raise PublicationSafetyError("Deterministic publication branch exists with different content.")
    try:
        pulls = transport.matching_pull_requests(
            prepared.intent["repository"],
            owner,
            prepared.intent["headBranch"],
            prepared.intent["baseBranch"],
        )
    except GitHubTransportError as error:
        return _publication_receipt(
            prepared,
            status="PARTIAL_UNVERIFIED_DRAFT",
            repository_id=repository_id,
            commit_sha=head_sha,
            pull_request=None,
            base_head_after=_best_effort_ref(
                transport,
                prepared.intent["repository"],
                prepared.intent["baseBranch"],
            ),
            error=str(error),
        )
    if len(pulls) > 1:
        raise PublicationSafetyError("Multiple pull requests match the deterministic publication branch.")
    if not pulls:
        current_base = transport.ref(prepared.intent["repository"], prepared.intent["baseBranch"])
        if current_base != prepared.intent["baseCommit"]:
            return _publication_receipt(
                prepared,
                status="PARTIAL_BRANCH_CREATED",
                repository_id=repository_id,
                commit_sha=head_sha,
                pull_request=None,
                base_head_after=current_base,
                error="The exact publication branch exists, but the base moved before draft creation.",
            )
        _ensure_approval_current(prepared, current_time())
        head_before_pull = _best_effort_ref(
            transport,
            prepared.intent["repository"],
            prepared.intent["headBranch"],
        )
        base_before_pull = _best_effort_ref(
            transport,
            prepared.intent["repository"],
            prepared.intent["baseBranch"],
        )
        if head_before_pull != head_sha:
            return _publication_receipt(
                prepared,
                status="PARTIAL_UNVERIFIED_BRANCH",
                repository_id=repository_id,
                commit_sha=head_sha,
                pull_request=None,
                base_head_after=base_before_pull,
                error="The deterministic publication branch moved before draft creation.",
            )
        if base_before_pull != prepared.intent["baseCommit"]:
            return _publication_receipt(
                prepared,
                status="PARTIAL_BRANCH_CREATED",
                repository_id=repository_id,
                commit_sha=head_sha,
                pull_request=None,
                base_head_after=base_before_pull,
                error="The base branch moved before draft creation.",
            )
        _ensure_approval_current(prepared, current_time())
        pull_candidate: dict[str, Any] | None = None
        try:
            pull = transport.create_draft_pull_request(
                prepared.intent["repository"],
                prepared.intent["title"],
                prepared.intent["body"],
                prepared.intent["headBranch"],
                prepared.intent["baseBranch"],
            )
            pull_candidate = pull if isinstance(pull, dict) else None
            pull_number = pull.get("number") if isinstance(pull, dict) else None
            if not isinstance(pull_number, int) or isinstance(pull_number, bool):
                raise PublicationSafetyError("Recovered draft pull request response omitted a valid number.")
            verified = _verify_pull_request(
                transport.pull_request(prepared.intent["repository"], pull_number),
                prepared,
                head_sha,
                repository_id,
                repository_full_name,
            )
        except (GitHubTransportError, PublicationSafetyError) as error:
            try:
                matching = transport.matching_pull_requests(
                    prepared.intent["repository"],
                    owner,
                    prepared.intent["headBranch"],
                    prepared.intent["baseBranch"],
                )
                if len(matching) == 1:
                    recovered_number = matching[0].get("number")
                    if isinstance(recovered_number, int) and not isinstance(recovered_number, bool):
                        verified = _verify_pull_request(
                            transport.pull_request(
                                prepared.intent["repository"],
                                recovered_number,
                            ),
                            prepared,
                            head_sha,
                            repository_id,
                            repository_full_name,
                        )
                        base_after = _best_effort_ref(
                            transport,
                            prepared.intent["repository"],
                            prepared.intent["baseBranch"],
                        )
                        status = (
                            "DRAFT_PR_CREATED"
                            if base_after == prepared.intent["baseCommit"]
                            else "DRAFT_PR_STALE_BASE"
                        )
                        return _publication_receipt(
                            prepared,
                            status=status,
                            repository_id=repository_id,
                            commit_sha=head_sha,
                            pull_request={**verified, "draft": True},
                            base_head_after=base_after,
                        )
            except (GitHubTransportError, PublicationSafetyError):
                pass
            candidate_receipt: dict[str, Any] | None = None
            if pull_candidate is not None:
                candidate_number = pull_candidate.get("number")
                candidate_url = pull_candidate.get("html_url")
                if (
                    isinstance(candidate_number, int)
                    and not isinstance(candidate_number, bool)
                    and isinstance(candidate_url, str)
                ):
                    candidate_receipt = {
                        "number": candidate_number,
                        "url": candidate_url,
                        "draft": None,
                        "verified": False,
                    }
            return _publication_receipt(
                prepared,
                status="PARTIAL_UNVERIFIED_DRAFT",
                repository_id=repository_id,
                commit_sha=head_sha,
                pull_request=candidate_receipt,
                base_head_after=_best_effort_ref(
                    transport,
                    prepared.intent["repository"],
                    prepared.intent["baseBranch"],
                ),
                error=str(error),
            )
        base_after = transport.ref(prepared.intent["repository"], prepared.intent["baseBranch"])
        status = "DRAFT_PR_CREATED" if base_after == prepared.intent["baseCommit"] else "DRAFT_PR_STALE_BASE"
        return _publication_receipt(
            prepared,
            status=status,
            repository_id=repository_id,
            commit_sha=head_sha,
            pull_request={**verified, "draft": True},
            base_head_after=base_after,
        )
    pull_number = pulls[0].get("number")
    if not isinstance(pull_number, int) or isinstance(pull_number, bool):
        raise PublicationSafetyError("Matching pull request has an invalid number.")
    verified = _verify_pull_request(
        transport.pull_request(prepared.intent["repository"], pull_number),
        prepared,
        head_sha,
        repository_id,
        repository_full_name,
    )
    base_after = transport.ref(prepared.intent["repository"], prepared.intent["baseBranch"])
    status = "DRAFT_PR_REUSED" if base_after == prepared.intent["baseCommit"] else "DRAFT_PR_STALE_BASE"
    return _publication_receipt(
        prepared,
        status=status,
        repository_id=repository_id,
        commit_sha=head_sha,
        pull_request={**verified, "draft": True},
        base_head_after=base_after,
    )


def publish_prepared(
    prepared: PreparedPublication,
    transport: GitHubTransport,
    *,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    current_time = clock or (lambda: datetime.now(timezone.utc))
    with PublicationLock(prepared.workspace_root, prepared.publication_id):
        repeated = snapshot_workspace(prepared.execution, workspace_root=prepared.workspace_root)
        if repeated != prepared.workspace:
            raise PublicationSafetyError("Execution workspace changed after local publication validation.")

        login = transport.authenticated_login()
        if login.casefold() != prepared.approval_summary["approvedBy"].casefold():
            raise PublicationSafetyError("GitHub token identity does not match the human approver.")
        repository = transport.repository(prepared.intent["repository"])
        repository_id = repository.get("id")
        full_name = repository.get("full_name")
        default_branch = repository.get("default_branch")
        if (
            not isinstance(repository_id, int)
            or isinstance(repository_id, bool)
            or repository_id < 1
            or not isinstance(full_name, str)
            or full_name.casefold() != prepared.intent["repository"].casefold()
            or default_branch != prepared.intent["baseBranch"]
        ):
            raise PublicationSafetyError("GitHub repository identity or default branch does not match the approval.")

        existing_head = transport.ref(prepared.intent["repository"], prepared.intent["headBranch"])
        if existing_head is not None:
            _ensure_approval_current(prepared, current_time())
            return _reconcile_existing(
                prepared,
                transport,
                repository_id=repository_id,
                repository_full_name=full_name,
                owner=full_name.split("/", 1)[0],
                head_sha=existing_head,
                current_time=current_time,
            )
        base_head = transport.ref(prepared.intent["repository"], prepared.intent["baseBranch"])
        if base_head != prepared.intent["baseCommit"]:
            raise PublicationSafetyError("GitHub base branch moved after execution; rerun RepoSteward.")
        base_commit = transport.git_commit(prepared.intent["repository"], prepared.intent["baseCommit"])
        base_tree = ((base_commit.get("tree") or {}).get("sha")) if isinstance(base_commit, dict) else None
        if not isinstance(base_tree, str) or not GIT_SHA_PATTERN.fullmatch(base_tree):
            raise PublicationSafetyError("GitHub base commit did not contain a valid tree SHA.")

        blob_shas: dict[str, str] = {}
        branch_creation_attempted = False
        branch_verified = False
        pull_creation_attempted = False
        pull_candidate: dict[str, Any] | None = None
        commit_sha: str | None = None
        try:
            _ensure_approval_current(prepared, current_time())
            for item in prepared.workspace.files:
                remote_sha = transport.create_blob(prepared.intent["repository"], item.content)
                if remote_sha != item.blob_sha:
                    raise PublicationSafetyError(f"GitHub blob SHA did not match the tested index: {item.path}")
                blob_shas[item.path] = remote_sha
            tree_sha = transport.create_tree(
                prepared.intent["repository"],
                base_tree,
                prepared.workspace.files,
                blob_shas,
            )
            if tree_sha != prepared.workspace.tree_sha:
                raise PublicationSafetyError("GitHub tree SHA did not match the exact tested Git index.")
            commit_sha = transport.create_commit(
                prepared.intent["repository"],
                _commit_message(prepared),
                tree_sha,
                prepared.intent["baseCommit"],
            )
            created_commit = transport.git_commit(prepared.intent["repository"], commit_sha)
            if not _verify_remote_commit(created_commit, prepared):
                raise PublicationSafetyError("GitHub publication commit did not match the approved tree and parent.")
            if transport.ref(prepared.intent["repository"], prepared.intent["baseBranch"]) != prepared.intent["baseCommit"]:
                raise PublicationSafetyError("GitHub base branch moved before publication branch creation.")
            _ensure_approval_current(prepared, current_time())
            branch_creation_attempted = True
            try:
                transport.create_ref(prepared.intent["repository"], prepared.intent["headBranch"], commit_sha)
            except GitHubTransportError:
                if _best_effort_ref(
                    transport,
                    prepared.intent["repository"],
                    prepared.intent["headBranch"],
                ) != commit_sha:
                    raise
            if transport.ref(prepared.intent["repository"], prepared.intent["headBranch"]) != commit_sha:
                raise PublicationSafetyError("GitHub publication branch did not resolve to the approved commit.")
            branch_verified = True
            _ensure_approval_current(prepared, current_time())
            head_before_pull = transport.ref(
                prepared.intent["repository"],
                prepared.intent["headBranch"],
            )
            base_before_pull = transport.ref(
                prepared.intent["repository"],
                prepared.intent["baseBranch"],
            )
            if head_before_pull != commit_sha:
                return _publication_receipt(
                    prepared,
                    status="PARTIAL_UNVERIFIED_BRANCH",
                    repository_id=repository_id,
                    commit_sha=commit_sha,
                    pull_request=None,
                    base_head_after=base_before_pull,
                    error="The deterministic publication branch moved before draft creation.",
                )
            if base_before_pull != prepared.intent["baseCommit"]:
                return _publication_receipt(
                    prepared,
                    status="PARTIAL_BRANCH_CREATED",
                    repository_id=repository_id,
                    commit_sha=commit_sha,
                    pull_request=None,
                    base_head_after=base_before_pull,
                    error="The base branch moved before draft creation.",
                )
            _ensure_approval_current(prepared, current_time())
            pull_creation_attempted = True
            pull = transport.create_draft_pull_request(
                prepared.intent["repository"],
                prepared.intent["title"],
                prepared.intent["body"],
                prepared.intent["headBranch"],
                prepared.intent["baseBranch"],
            )
            pull_candidate = pull if isinstance(pull, dict) else None
            number = pull.get("number") if isinstance(pull, dict) else None
            if not isinstance(number, int) or isinstance(number, bool):
                raise PublicationSafetyError("GitHub draft pull request response omitted a valid number.")
            verified = _verify_pull_request(
                transport.pull_request(prepared.intent["repository"], number),
                prepared,
                commit_sha,
                repository_id,
                full_name,
            )
            base_after = transport.ref(prepared.intent["repository"], prepared.intent["baseBranch"])
            status = "DRAFT_PR_CREATED" if base_after == prepared.intent["baseCommit"] else "DRAFT_PR_STALE_BASE"
            return _publication_receipt(
                prepared,
                status=status,
                repository_id=repository_id,
                commit_sha=commit_sha,
                pull_request={**verified, "draft": True},
                base_head_after=base_after,
            )
        except (GitHubTransportError, PublicationSafetyError) as error:
            if (branch_verified or branch_creation_attempted) and commit_sha:
                if pull_creation_attempted:
                    try:
                        matching = transport.matching_pull_requests(
                            prepared.intent["repository"],
                            full_name.split("/", 1)[0],
                            prepared.intent["headBranch"],
                            prepared.intent["baseBranch"],
                        )
                        if len(matching) == 1:
                            recovered_number = matching[0].get("number")
                            if isinstance(recovered_number, int) and not isinstance(recovered_number, bool):
                                verified = _verify_pull_request(
                                    transport.pull_request(
                                        prepared.intent["repository"],
                                        recovered_number,
                                    ),
                                    prepared,
                                    commit_sha,
                                    repository_id,
                                    full_name,
                                )
                                base_after = _best_effort_ref(
                                    transport,
                                    prepared.intent["repository"],
                                    prepared.intent["baseBranch"],
                                )
                                recovered_status = (
                                    "DRAFT_PR_CREATED"
                                    if base_after == prepared.intent["baseCommit"]
                                    else "DRAFT_PR_STALE_BASE"
                                )
                                return _publication_receipt(
                                    prepared,
                                    status=recovered_status,
                                    repository_id=repository_id,
                                    commit_sha=commit_sha,
                                    pull_request={**verified, "draft": True},
                                    base_head_after=base_after,
                                )
                    except (GitHubTransportError, PublicationSafetyError):
                        pass
                candidate_receipt: dict[str, Any] | None = None
                if pull_candidate is not None:
                    number = pull_candidate.get("number")
                    url = pull_candidate.get("html_url")
                    if isinstance(number, int) and not isinstance(number, bool) and isinstance(url, str):
                        candidate_receipt = {
                            "number": number,
                            "url": url,
                            "draft": None,
                            "verified": False,
                        }
                return _publication_receipt(
                    prepared,
                    status=(
                        "PARTIAL_UNVERIFIED_DRAFT"
                        if pull_creation_attempted
                        else (
                            "PARTIAL_BRANCH_CREATED"
                            if branch_verified
                            else "PARTIAL_UNVERIFIED_BRANCH"
                        )
                    ),
                    repository_id=repository_id,
                    commit_sha=commit_sha,
                    pull_request=candidate_receipt,
                    base_head_after=_best_effort_ref(
                        transport,
                        prepared.intent["repository"],
                        prepared.intent["baseBranch"],
                    ),
                    error=str(error),
                )
            if isinstance(error, PublicationSafetyError):
                raise
            raise PublicationSafetyError(str(error)) from error
