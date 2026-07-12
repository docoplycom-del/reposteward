from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from typing import Any, Callable
from urllib.parse import urlsplit

from .execution import (
    CONTAINER_TEST_PROFILES,
    DEFAULT_DOCKER_IMAGE,
    DOCKER_CPU_LIMIT,
    DOCKER_FILE_LIMIT,
    DOCKER_LOG_LIMIT,
    DOCKER_MEMORY_LIMIT,
    DOCKER_PID_LIMIT,
    DOCKER_TMPFS_SIZE,
)


APPROVAL_CONTRACT_VERSION = "reposteward.approval.v1"
EXECUTION_CONTRACT_VERSION = "reposteward.execution.v1"
APPROVAL_KEY_ENV = "REPOSTEWARD_APPROVAL_KEY"
DEFAULT_APPROVAL_TTL_MINUTES = 15
MAX_APPROVAL_TTL_MINUTES = 60
MAX_CHANGED_FILES = 25
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
COMMIT_PATTERN = re.compile(r"^[a-f0-9]{40}$")
EXECUTION_ID_PATTERN = re.compile(r"^RSX-[1-9][0-9]*-[A-F0-9]{10}$")
APPROVAL_ID_PATTERN = re.compile(r"^RSA-[A-F0-9]{16}$")
GITHUB_LOGIN_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
BRANCH_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,126}[A-Za-z0-9]$|^[A-Za-z0-9]$")


class ApprovalSafetyError(RuntimeError):
    """Raised when an execution or approval crosses the publication boundary."""


def _reject_constant(value: str) -> None:
    raise ValueError(f"Non-finite JSON value is not allowed: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Duplicate JSON key is not allowed: {key}")
        value[key] = item
    return value


def load_strict_json(text: str) -> dict[str, Any]:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise ApprovalSafetyError(f"Invalid JSON artifact: {error}") from error
    if not isinstance(value, dict):
        raise ApprovalSafetyError("JSON artifact must contain one object.")
    return value


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ApprovalSafetyError("Artifact cannot be represented as canonical JSON.") from error


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ApprovalSafetyError(f"{field} must be an RFC 3339 UTC timestamp.")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ApprovalSafetyError(f"{field} must be an RFC 3339 UTC timestamp.") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ApprovalSafetyError(f"{field} must use UTC.")
    return parsed


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _require_sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise ApprovalSafetyError(f"{field} must be a lowercase SHA-256 digest.")
    return value


def _validate_repo_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ApprovalSafetyError("Changed files must use non-empty POSIX paths.")
    if any(ord(character) < 32 for character in value):
        raise ApprovalSafetyError("Changed file paths may not contain control characters.")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or ".git" in path.parts:
        raise ApprovalSafetyError(f"Unsafe changed file path: {value}")
    if path.parts[:2] == (".github", "workflows") or path.name == ".gitmodules":
        raise ApprovalSafetyError(f"Protected path cannot be published: {value}")
    return path.as_posix()


def validate_branch(value: object, field: str = "baseBranch") -> str:
    if not isinstance(value, str) or not BRANCH_PATTERN.fullmatch(value):
        raise ApprovalSafetyError(f"{field} is not a conservative Git branch name.")
    if (
        ".." in value
        or "//" in value
        or "@{" in value
        or value.endswith(".")
        or value.endswith("/")
        or value.endswith(".lock")
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ApprovalSafetyError(f"{field} is not a conservative Git branch name.")
    return value


def _parse_github_source(reference: object) -> str:
    if not isinstance(reference, str):
        raise ApprovalSafetyError("Execution source reference is missing.")
    parsed = urlsplit(reference)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ApprovalSafetyError("Publication requires a credential-free HTTPS GitHub source.")
    try:
        if parsed.port is not None:
            raise ApprovalSafetyError("GitHub source may not include a port.")
    except ValueError as error:
        raise ApprovalSafetyError("GitHub source contains an invalid port.") from error
    path = parsed.path.removesuffix(".git").strip("/")
    if not REPOSITORY_PATTERN.fullmatch(path):
        raise ApprovalSafetyError("GitHub source must identify exactly one owner and repository.")
    return path


def _require_mapping(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ApprovalSafetyError(f"{field} must be an object.")
    return value


def validate_execution_for_publication(execution: dict[str, Any]) -> dict[str, Any]:
    if execution.get("contractVersion") != EXECUTION_CONTRACT_VERSION:
        raise ApprovalSafetyError("Unsupported execution receipt contract.")
    if execution.get("status") != "AWAITING_HUMAN_APPROVAL":
        raise ApprovalSafetyError("Execution is not awaiting human approval.")
    execution_id = execution.get("executionId")
    if not isinstance(execution_id, str) or not EXECUTION_ID_PATTERN.fullmatch(execution_id):
        raise ApprovalSafetyError("Execution receipt has an invalid executionId.")

    planning = _require_mapping(execution.get("planningDecision"), "planningDecision")
    if planning.get("status") != "PROCEED_TO_PATCH":
        raise ApprovalSafetyError("Planning decision does not authorize a patch.")

    issue = _require_mapping(execution.get("issue"), "issue")
    repository = issue.get("repository")
    if not isinstance(repository, str) or not REPOSITORY_PATTERN.fullmatch(repository):
        raise ApprovalSafetyError("Issue repository must use owner/repository form.")
    number = issue.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise ApprovalSafetyError("Issue number must be a positive integer.")
    title = issue.get("title")
    if not isinstance(title, str) or not title.strip() or len(title) > 500:
        raise ApprovalSafetyError("Issue title is missing or too long.")

    source = _require_mapping(execution.get("source"), "source")
    if source.get("type") != "https_git_repository":
        raise ApprovalSafetyError("Local execution receipts cannot be published to GitHub.")
    source_repository = _parse_github_source(source.get("reference"))
    if source_repository.casefold() != repository.casefold():
        raise ApprovalSafetyError("Issue repository does not match the executed GitHub source.")

    workspace = _require_mapping(execution.get("workspace"), "workspace")
    workspace_path = workspace.get("path")
    if not isinstance(workspace_path, str) or not workspace_path or "\x00" in workspace_path:
        raise ApprovalSafetyError("Execution workspace path is missing.")
    base_commit = workspace.get("baseCommit")
    if not isinstance(base_commit, str) or not COMMIT_PATTERN.fullmatch(base_commit):
        raise ApprovalSafetyError("Execution baseCommit must be a lowercase Git SHA-1.")
    base_branch = validate_branch(workspace.get("baseBranch"))
    if workspace.get("remoteRemoved") is not True:
        raise ApprovalSafetyError("Execution workspace must have its Git remote removed.")

    patch = _require_mapping(execution.get("patch"), "patch")
    candidate_sha256 = _require_sha256(patch.get("candidateSha256"), "candidateSha256")
    applied_sha256 = _require_sha256(patch.get("appliedDiffSha256"), "appliedDiffSha256")
    unified_diff = patch.get("unifiedDiff")
    if not isinstance(unified_diff, str) or hashlib.sha256(unified_diff.encode("utf-8")).hexdigest() != applied_sha256:
        raise ApprovalSafetyError("Execution unified diff does not match appliedDiffSha256.")
    changed = patch.get("changedFiles")
    if not isinstance(changed, list) or not 1 <= len(changed) <= MAX_CHANGED_FILES:
        raise ApprovalSafetyError(f"Publication requires 1 to {MAX_CHANGED_FILES} changed files.")
    changed_files = [_validate_repo_path(path) for path in changed]
    if len(changed_files) != len(set(changed_files)) or changed_files != sorted(changed_files):
        raise ApprovalSafetyError("Changed files must be unique and sorted.")

    tests = _require_mapping(execution.get("tests"), "tests")
    expected_test_command = [
        "python",
        "-E",
        "-s",
        "-B",
        *CONTAINER_TEST_PROFILES["python-unittest"],
    ]
    if (
        tests.get("profile") != "python-unittest"
        or tests.get("command") != expected_test_command
        or tests.get("passed") is not True
        or tests.get("return_code") != 0
        or tests.get("timed_out") is not False
        or tests.get("stdout_truncated") is not False
        or tests.get("stderr_truncated") is not False
        or tests.get("isolation_level") != "docker"
    ):
        raise ApprovalSafetyError("Only successful, complete Docker-isolated tests may be published.")
    isolation = _require_mapping(tests.get("isolation_details"), "tests.isolation_details")
    cleanup = _require_mapping(isolation.get("cleanup"), "tests.isolation_details.cleanup")
    resource_limits = _require_mapping(
        isolation.get("resourceLimits"),
        "tests.isolation_details.resourceLimits",
    )
    image_id = isolation.get("imageId")
    image_digests = isolation.get("imageRepoDigests")
    if not (
        isolation.get("containerConfigurationInspected") is True
        and isolation.get("engine") == "docker"
        and isolation.get("engineOs") == "linux"
        and isolation.get("engineEndpointType") in {"unix", "npipe"}
        and isolation.get("imageReference") == DEFAULT_DOCKER_IMAGE
        and isinstance(image_id, str)
        and re.fullmatch(r"^sha256:[a-f0-9]{64}$", image_id)
        and isinstance(image_digests, list)
        and any(
            isinstance(digest, str)
            and re.fullmatch(r"^(?:docker\.io/library/)?python@sha256:[a-f0-9]{64}$", digest)
            for digest in image_digests
        )
        and isolation.get("imageOs") == "linux"
        and isolation.get("imageArchitecture") == "amd64"
        and isolation.get("imagePullPolicy") == "never"
        and isolation.get("network") == "none"
        and isolation.get("rootFilesystem") == "read_only"
        and isolation.get("repositoryMount") == "read_only"
        and isolation.get("hostCredentialsMounted") is False
        and isolation.get("dockerSocketMounted") is False
        and isolation.get("user") == "65534:65534"
        and isolation.get("capabilitiesDropped") == ["ALL"]
        and isolation.get("noNewPrivileges") is True
        and isolation.get("seccompProfile") == "daemon_default"
        and isolation.get("oomKilled") is False
        and resource_limits.get("cpus") == DOCKER_CPU_LIMIT
        and resource_limits.get("memory") == DOCKER_MEMORY_LIMIT
        and resource_limits.get("memorySwap") == DOCKER_MEMORY_LIMIT
        and resource_limits.get("pids") == DOCKER_PID_LIMIT
        and resource_limits.get("openFiles") == DOCKER_FILE_LIMIT
        and resource_limits.get("tmpfs") == DOCKER_TMPFS_SIZE
        and resource_limits.get("retainedLogs") == DOCKER_LOG_LIMIT
        and cleanup.get("removed") is True
        and cleanup.get("verifiedByDaemon") is True
    ):
        raise ApprovalSafetyError("Docker isolation evidence is incomplete.")

    execution_approval = _require_mapping(execution.get("approval"), "approval")
    if not (
        execution_approval.get("required") is True
        and execution_approval.get("approved") is False
        and execution_approval.get("pushCapabilityPresent") is False
    ):
        raise ApprovalSafetyError("Execution approval boundary is invalid.")
    safety = _require_mapping(execution.get("safetyBoundary"), "safetyBoundary")
    if not (
        safety.get("testIsolation") == "docker"
        and safety.get("networkIsolation") is True
        and safety.get("repositoryReadOnly") is True
        and safety.get("rootFilesystemReadOnly") is True
        and safety.get("hostCredentialsMounted") is False
        and safety.get("dockerSocketMounted") is False
        and safety.get("sharedKernelContainerBoundary") is True
        and safety.get("trustedDisposableRepositoryRequired") is False
    ):
        raise ApprovalSafetyError("Execution safety boundary is not publication-eligible.")

    return {
        "executionId": execution_id,
        "receiptSha256": canonical_sha256(execution),
        "repository": repository,
        "issueNumber": number,
        "issueTitle": title.strip(),
        "workspacePath": workspace_path,
        "baseBranch": base_branch,
        "baseCommit": base_commit,
        "candidateSha256": candidate_sha256,
        "appliedDiffSha256": applied_sha256,
        "changedFiles": changed_files,
    }


def build_publication_intent(execution: dict[str, Any]) -> dict[str, Any]:
    binding = validate_execution_for_publication(execution)
    receipt_prefix = binding["receiptSha256"][:24]
    head_branch = validate_branch(
        f"reposteward/issue-{binding['issueNumber']}-{receipt_prefix}",
        "headBranch",
    )
    title = f"RepoSteward proposal for issue #{binding['issueNumber']}"
    files = "\n".join(f"- `{path}`" for path in binding["changedFiles"])
    body = (
        "## RepoSteward maintenance draft\n\n"
        f"Addresses issue #{binding['issueNumber']} after an explicit human approval.\n\n"
        f"- Execution: `{binding['executionId']}`\n"
        "- Tests: passed in the Docker isolation profile\n"
        f"- Base commit: `{binding['baseCommit']}`\n"
        f"- Applied diff SHA-256: `{binding['appliedDiffSha256']}`\n\n"
        "### Changed files\n\n"
        f"{files}\n\n"
        "This pull request is always created as a draft. RepoSteward cannot merge it or mark it ready for review."
    )
    return {
        "repository": binding["repository"],
        "issueNumber": binding["issueNumber"],
        "baseBranch": binding["baseBranch"],
        "baseCommit": binding["baseCommit"],
        "headBranch": head_branch,
        "draftOnly": True,
        "title": title,
        "titleSha256": hashlib.sha256(title.encode("utf-8")).hexdigest(),
        "body": body,
        "bodySha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "executionId": binding["executionId"],
        "receiptSha256": binding["receiptSha256"],
        "candidateSha256": binding["candidateSha256"],
        "appliedDiffSha256": binding["appliedDiffSha256"],
        "changedFiles": binding["changedFiles"],
    }


def expected_confirmation(execution: dict[str, Any]) -> str:
    binding = validate_execution_for_publication(execution)
    return (
        f"APPROVE {binding['executionId']} {binding['repository']}#{binding['issueNumber']} "
        f"{binding['baseCommit']} "
        f"{binding['appliedDiffSha256']}"
    )


def _approval_key(value: str | bytes) -> bytes:
    key = value if isinstance(value, bytes) else value.encode("utf-8")
    if len(key) < 32:
        raise ApprovalSafetyError("Approval key must contain at least 32 bytes.")
    return key


def create_approval(
    execution: dict[str, Any],
    *,
    approver: str,
    confirmation: str,
    key: str | bytes,
    ttl_minutes: int = DEFAULT_APPROVAL_TTL_MINUTES,
    now: datetime | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    intent = build_publication_intent(execution)
    if not GITHUB_LOGIN_PATTERN.fullmatch(approver):
        raise ApprovalSafetyError("Approver must be a conservative GitHub login.")
    if confirmation != expected_confirmation(execution):
        raise ApprovalSafetyError("Approval confirmation did not match the tested execution.")
    if not isinstance(ttl_minutes, int) or isinstance(ttl_minutes, bool) or not 1 <= ttl_minutes <= MAX_APPROVAL_TTL_MINUTES:
        raise ApprovalSafetyError(f"Approval TTL must be between 1 and {MAX_APPROVAL_TTL_MINUTES} minutes.")
    secret_key = _approval_key(key)
    approved_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires_at = approved_at + timedelta(minutes=ttl_minutes)
    approval_nonce = nonce or secrets.token_hex(16)
    if not re.fullmatch(r"^[a-f0-9]{32}$", approval_nonce):
        raise ApprovalSafetyError("Approval nonce must contain 32 lowercase hexadecimal characters.")
    binding = {
        "executionReceiptSha256": intent["receiptSha256"],
        "executionId": intent["executionId"],
        "repository": intent["repository"],
        "issueNumber": intent["issueNumber"],
        "baseBranch": intent["baseBranch"],
        "baseCommit": intent["baseCommit"],
        "headBranch": intent["headBranch"],
        "draftOnly": True,
        "titleSha256": intent["titleSha256"],
        "bodySha256": intent["bodySha256"],
        "candidateSha256": intent["candidateSha256"],
        "appliedDiffSha256": intent["appliedDiffSha256"],
        "changedFiles": intent["changedFiles"],
    }
    approval_id = "RSA-" + hashlib.sha256(
        canonical_json_bytes({"binding": binding, "nonce": approval_nonce})
    ).hexdigest()[:16].upper()
    unsigned = {
        "contractVersion": APPROVAL_CONTRACT_VERSION,
        "approvalId": approval_id,
        "status": "APPROVED_FOR_DRAFT_PR",
        "decision": "CREATE_DRAFT_PULL_REQUEST",
        "approvedBy": approver,
        "approvedAt": _format_time(approved_at),
        "expiresAt": _format_time(expires_at),
        "nonce": approval_nonce,
        "binding": binding,
        "bindingSha256": canonical_sha256(binding),
    }
    signature = hmac.new(secret_key, canonical_json_bytes(unsigned), hashlib.sha256).hexdigest()
    return {**unsigned, "signature": f"hmac-sha256:{signature}"}


def verify_approval(
    execution: dict[str, Any],
    approval: dict[str, Any],
    *,
    key: str | bytes,
    now: datetime | None = None,
) -> dict[str, Any]:
    intent = build_publication_intent(execution)
    secret_key = _approval_key(key)
    if approval.get("contractVersion") != APPROVAL_CONTRACT_VERSION:
        raise ApprovalSafetyError("Unsupported approval artifact contract.")
    approval_id = approval.get("approvalId")
    if not isinstance(approval_id, str) or not APPROVAL_ID_PATTERN.fullmatch(approval_id):
        raise ApprovalSafetyError("Approval artifact has an invalid approvalId.")
    if approval.get("status") != "APPROVED_FOR_DRAFT_PR" or approval.get("decision") != "CREATE_DRAFT_PULL_REQUEST":
        raise ApprovalSafetyError("Approval artifact does not authorize a draft pull request.")
    approver = approval.get("approvedBy")
    if not isinstance(approver, str) or not GITHUB_LOGIN_PATTERN.fullmatch(approver):
        raise ApprovalSafetyError("Approval artifact has an invalid approver.")
    signature = approval.get("signature")
    if not isinstance(signature, str) or not signature.startswith("hmac-sha256:"):
        raise ApprovalSafetyError("Approval artifact signature is missing.")
    unsigned = {key_name: value for key_name, value in approval.items() if key_name != "signature"}
    expected_signature = hmac.new(secret_key, canonical_json_bytes(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, f"hmac-sha256:{expected_signature}"):
        raise ApprovalSafetyError("Approval artifact signature is invalid.")

    approved_at = _parse_time(approval.get("approvedAt"), "approvedAt")
    expires_at = _parse_time(approval.get("expiresAt"), "expiresAt")
    if expires_at <= approved_at or expires_at - approved_at > timedelta(minutes=MAX_APPROVAL_TTL_MINUTES):
        raise ApprovalSafetyError("Approval artifact has an invalid validity window.")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if current < approved_at or current > expires_at:
        raise ApprovalSafetyError("Approval artifact is not currently valid.")

    expected_binding = {
        "executionReceiptSha256": intent["receiptSha256"],
        "executionId": intent["executionId"],
        "repository": intent["repository"],
        "issueNumber": intent["issueNumber"],
        "baseBranch": intent["baseBranch"],
        "baseCommit": intent["baseCommit"],
        "headBranch": intent["headBranch"],
        "draftOnly": True,
        "titleSha256": intent["titleSha256"],
        "bodySha256": intent["bodySha256"],
        "candidateSha256": intent["candidateSha256"],
        "appliedDiffSha256": intent["appliedDiffSha256"],
        "changedFiles": intent["changedFiles"],
    }
    binding = approval.get("binding")
    if binding != expected_binding or approval.get("bindingSha256") != canonical_sha256(expected_binding):
        raise ApprovalSafetyError("Approval artifact is not bound to this execution and publication intent.")
    nonce = approval.get("nonce")
    if not isinstance(nonce, str) or not re.fullmatch(r"^[a-f0-9]{32}$", nonce):
        raise ApprovalSafetyError("Approval artifact has an invalid nonce.")
    expected_id = "RSA-" + hashlib.sha256(
        canonical_json_bytes({"binding": expected_binding, "nonce": nonce})
    ).hexdigest()[:16].upper()
    if approval_id != expected_id:
        raise ApprovalSafetyError("Approval artifact identifier is invalid.")
    return {
        "approvalId": approval_id,
        "approvedBy": approver,
        "approvedAt": _format_time(approved_at),
        "expiresAt": _format_time(expires_at),
        "intent": intent,
    }
