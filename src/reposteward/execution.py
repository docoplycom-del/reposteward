from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from time import perf_counter
from typing import Any, Sequence
from urllib.parse import urlsplit

from .models import Issue


EXECUTION_CONTRACT_VERSION = "reposteward.execution.v1"
PATCH_LIMIT_BYTES = 256 * 1024
OUTPUT_LIMIT_CHARS = 20_000
REMOTE_REPOSITORY_PATTERN = re.compile(r"^/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?$")
DIFF_HEADER_PATTERN = re.compile(r"^diff --git a/([A-Za-z0-9._/+\-]+) b/([A-Za-z0-9._/+\-]+)$")


class ExecutionSafetyError(RuntimeError):
    """Raised when an execution request crosses a declared safety boundary."""


@dataclass(frozen=True)
class ExecutionPolicy:
    allowed_remote_hosts: tuple[str, ...] = ("github.com",)
    max_patch_bytes: int = PATCH_LIMIT_BYTES
    max_tracked_files: int = 5_000
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 20 * 1024 * 1024
    test_timeout_seconds: int = 60
    allow_local_repository: bool = False
    allow_test_execution: bool = False


@dataclass(frozen=True)
class TestResult:
    profile: str
    command: list[str]
    return_code: int | None
    passed: bool
    timed_out: bool
    duration_ms: float
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    isolation_level: str = "process_only"


TEST_PROFILES: dict[str, tuple[str, ...]] = {
    "python-unittest": (sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"),
}


def _safe_environment(home: Path) -> dict[str, str]:
    environment = {
        "PATH": os.defpath,
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "NO_PROXY": "*",
        "no_proxy": "*",
    }
    for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "TMP", "TEMP", "LANG", "LC_ALL"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def _run(
    command: Sequence[str],
    *,
    cwd: Path | None,
    environment: dict[str, str],
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        list(command),
        cwd=cwd,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=os.name != "nt",
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                check=False,
                shell=False,
            )
        else:
            os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        raise subprocess.TimeoutExpired(list(command), timeout, output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(list(command), process.returncode, stdout, stderr)


def _require_success(result: subprocess.CompletedProcess[str], action: str) -> str:
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-2_000:]
        raise ExecutionSafetyError(f"{action} failed: {detail}")
    return result.stdout


def _write_utf8_lf(path: Path, content: str) -> None:
    """Write protocol text without platform newline translation."""
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def _validate_repo_path(path: str) -> str:
    if not path or "\x00" in path or "\\" in path or any(ord(character) < 32 for character in path):
        raise ExecutionSafetyError("Repository paths must be non-empty POSIX paths without control characters.")
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or ".git" in pure.parts:
        raise ExecutionSafetyError(f"Unsafe repository path in patch: {path}")
    if pure.parts[:2] == (".github", "workflows") or pure.name == ".gitmodules":
        raise ExecutionSafetyError(f"Protected repository path cannot be changed in this slice: {path}")
    return pure.as_posix()


def validate_patch(patch_text: str, policy: ExecutionPolicy) -> list[str]:
    encoded = patch_text.encode("utf-8")
    if not encoded or len(encoded) > policy.max_patch_bytes:
        raise ExecutionSafetyError(f"Patch must contain 1 to {policy.max_patch_bytes} UTF-8 bytes.")
    if "\x00" in patch_text or "GIT binary patch" in patch_text or "Binary files " in patch_text:
        raise ExecutionSafetyError("Binary patches are not allowed.")
    forbidden_prefixes = (
        "new file mode ", "deleted file mode ", "old mode ", "new mode ",
        "rename from ", "rename to ", "copy from ", "copy to ", "similarity index ",
    )
    if any(line.startswith(forbidden_prefixes) for line in patch_text.splitlines()):
        raise ExecutionSafetyError("Adds, deletes, renames, copies and mode changes are not allowed in this slice.")

    changed_paths: list[str] = []
    for line in patch_text.splitlines():
        if not line.startswith("diff --git "):
            continue
        match = DIFF_HEADER_PATTERN.fullmatch(line)
        if not match:
            raise ExecutionSafetyError("Patch paths must use unquoted Git POSIX paths with conservative characters.")
        before = _validate_repo_path(match.group(1))
        after = _validate_repo_path(match.group(2))
        if before != after:
            raise ExecutionSafetyError("Renames are not allowed in the first execution slice.")
        changed_paths.append(after)

    if not changed_paths:
        raise ExecutionSafetyError("Patch does not contain a recognised Git diff header.")
    if len(changed_paths) != len(set(changed_paths)):
        raise ExecutionSafetyError("Patch contains duplicate file sections.")
    declared = set(changed_paths)
    for line in patch_text.splitlines():
        if not (line.startswith("--- ") or line.startswith("+++ ")):
            continue
        marker_path = line[4:]
        expected_prefix = "a/" if line.startswith("--- ") else "b/"
        if not marker_path.startswith(expected_prefix):
            raise ExecutionSafetyError("Patch may only modify existing files with matching a/ and b/ markers.")
        if _validate_repo_path(marker_path[2:]) not in declared:
            raise ExecutionSafetyError("Patch marker path does not match its declared diff header.")
    return changed_paths


def validate_repository_source(source: str, policy: ExecutionPolicy) -> tuple[str, bool]:
    candidate = Path(source).expanduser()
    if candidate.exists():
        if not policy.allow_local_repository:
            raise ExecutionSafetyError("Local repository cloning requires explicit policy authorization.")
        resolved = candidate.resolve()
        if not resolved.is_dir() or not (resolved / ".git").exists():
            raise ExecutionSafetyError("Local source must be a Git working tree.")
        return str(resolved), True

    parsed = urlsplit(source)
    if parsed.scheme != "https" or parsed.hostname not in policy.allowed_remote_hosts:
        raise ExecutionSafetyError("Remote source must be HTTPS on an allowlisted host.")
    try:
        port = parsed.port
    except ValueError as error:
        raise ExecutionSafetyError("Repository URL contains an invalid port.") from error
    if parsed.username or parsed.password or port or parsed.query or parsed.fragment:
        raise ExecutionSafetyError("Repository URL may not include credentials, ports, queries or fragments.")
    if not REMOTE_REPOSITORY_PATTERN.fullmatch(parsed.path):
        raise ExecutionSafetyError("Repository URL must identify exactly one owner and repository.")
    return source, False


class WorkspaceExecutor:
    def __init__(self, workspace_root: Path, policy: ExecutionPolicy | None = None):
        self.workspace_root = workspace_root.resolve()
        self.policy = policy or ExecutionPolicy()
        self.git = shutil.which("git")
        if not self.git:
            raise ExecutionSafetyError("Git is required for repository execution.")

    def execute(self, issue: Issue, repository_source: str, patch_text: str, test_profile: str) -> dict[str, Any]:
        started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        declared_paths = validate_patch(patch_text, self.policy)
        planned_paths = {_validate_repo_path(path) for path in issue.files}
        if planned_paths and not set(declared_paths).issubset(planned_paths):
            unplanned = sorted(set(declared_paths) - planned_paths)
            raise ExecutionSafetyError(f"Patch changes files outside the reviewed issue scope: {', '.join(unplanned)}")
        source, is_local = validate_repository_source(repository_source, self.policy)
        if test_profile not in TEST_PROFILES:
            raise ExecutionSafetyError(f"Unknown test profile: {test_profile}")
        if not self.policy.allow_test_execution:
            raise ExecutionSafetyError("Test execution requires explicit authorization for a trusted disposable repository.")

        self.workspace_root.mkdir(parents=True, exist_ok=True)
        execution_id = self._execution_id(issue, source, patch_text)
        execution_dir = Path(tempfile.mkdtemp(prefix=f"{execution_id}-", dir=self.workspace_root))
        repository_dir = execution_dir / "repository"
        home_dir = execution_dir / "home"
        home_dir.mkdir()
        environment = _safe_environment(home_dir)

        clone_command = [self.git, "-c", f"protocol.file.allow={'always' if is_local else 'never'}", "clone"]
        if not is_local:
            clone_command.extend(["--depth", "1", "--no-tags", "--single-branch"])
        else:
            clone_command.append("--no-local")
        clone_command.extend(["--", source, str(repository_dir)])
        _require_success(_run(clone_command, cwd=None, environment=environment), "Repository clone")

        base_commit = _require_success(
            _run([self.git, "rev-parse", "HEAD"], cwd=repository_dir, environment=environment),
            "Base commit inspection",
        ).strip()
        inventory = self._inventory(repository_dir, environment)
        if not set(declared_paths).issubset(inventory):
            missing = sorted(set(declared_paths) - set(inventory))
            raise ExecutionSafetyError(f"Patch may modify existing tracked files only: {', '.join(missing)}")
        clean_status = _require_success(
            _run([self.git, "status", "--porcelain=v1", "-z", "--untracked-files=all"], cwd=repository_dir, environment=environment),
            "Clean-clone verification",
        )
        if clean_status:
            raise ExecutionSafetyError("Fresh clone is not clean; execution stopped.")
        _require_success(
            _run([self.git, "remote", "remove", "origin"], cwd=repository_dir, environment=environment),
            "Remote removal",
        )

        patch_path = execution_dir / "candidate.patch"
        _write_utf8_lf(patch_path, patch_text)
        apply_base = [self.git, "apply", "--whitespace=error-all", "--index"]
        _require_success(
            _run([*apply_base, "--check", str(patch_path)], cwd=repository_dir, environment=environment),
            "Patch validation",
        )
        _require_success(
            _run([*apply_base, str(patch_path)], cwd=repository_dir, environment=environment),
            "Patch application",
        )

        changed_paths = self._changed_paths(repository_dir, environment)
        if sorted(changed_paths) != sorted(declared_paths):
            raise ExecutionSafetyError("Applied change paths do not match the patch declaration.")
        status_paths = self._status_paths(repository_dir, environment)
        if status_paths != sorted(declared_paths):
            raise ExecutionSafetyError("Working tree contains changes outside the validated patch.")
        current_head = _require_success(
            _run([self.git, "rev-parse", "HEAD"], cwd=repository_dir, environment=environment),
            "Post-apply HEAD verification",
        ).strip()
        if current_head != base_commit:
            raise ExecutionSafetyError("Patch execution changed the repository commit; execution stopped.")
        generated_patch = _require_success(
            _run([self.git, "diff", "--cached", "--no-ext-diff", "--binary", "--full-index", "--"], cwd=repository_dir, environment=environment),
            "Patch export",
        )
        candidate_sha256 = hashlib.sha256(patch_text.encode("utf-8")).hexdigest()
        patch_sha256 = hashlib.sha256(generated_patch.encode("utf-8")).hexdigest()
        test_result = self._run_tests(repository_dir, environment, test_profile)
        status = "AWAITING_HUMAN_APPROVAL" if test_result.passed else "BLOCKED_TEST_FAILURE"
        completed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        return {
            "contractVersion": EXECUTION_CONTRACT_VERSION,
            "executionId": execution_id,
            "issue": {"repository": issue.repository, "number": issue.number, "title": issue.title},
            "source": {
                "type": "local_disposable_repository" if is_local else "https_git_repository",
                "reference": (
                    f"local-sha256:{hashlib.sha256(source.encode('utf-8')).hexdigest()}"
                    if is_local else source
                ),
            },
            "workspace": {
                "path": str(repository_dir),
                "baseCommit": base_commit,
                "remoteRemoved": True,
                "trackedFileCount": len(inventory),
                "trackedFiles": inventory,
            },
            "patch": {
                "candidateSha256": candidate_sha256,
                "appliedDiffSha256": patch_sha256,
                "bytes": len(generated_patch.encode("utf-8")),
                "changedFiles": changed_paths,
                "unifiedDiff": generated_patch,
            },
            "tests": asdict(test_result),
            "status": status,
            "startedAt": started_at,
            "completedAt": completed_at,
            "approval": {
                "required": True,
                "approved": False,
                "pushCapabilityPresent": False,
                "nextAction": "human_review" if test_result.passed else "remediate_and_rerun",
            },
            "safetyBoundary": {
                "testIsolation": "process_only",
                "networkIsolation": False,
                "trustedDisposableRepositoryRequired": True,
            },
        }

    def _inventory(self, repository_dir: Path, environment: dict[str, str]) -> list[str]:
        raw = _require_success(
            _run([self.git, "ls-files", "--stage", "-z"], cwd=repository_dir, environment=environment),
            "Tracked-file inventory",
        )
        entries = [entry for entry in raw.split("\x00") if entry]
        paths: list[str] = []
        modes: dict[str, str] = {}
        for entry in entries:
            metadata, separator, path = entry.partition("\t")
            if not separator:
                raise ExecutionSafetyError("Could not parse tracked-file inventory.")
            mode = metadata.split(" ", 1)[0]
            paths.append(path)
            modes[path] = mode
        if len(paths) > self.policy.max_tracked_files:
            raise ExecutionSafetyError(f"Repository exceeds the {self.policy.max_tracked_files}-file policy limit.")
        casefolded: set[str] = set()
        total_bytes = 0
        for path in paths:
            safe_path = _validate_repo_path(path)
            folded = safe_path.casefold()
            if folded in casefolded:
                raise ExecutionSafetyError(f"Repository contains a case-fold path collision: {path}")
            casefolded.add(folded)
            if modes[path] not in {"100644", "100755"}:
                raise ExecutionSafetyError(f"Tracked symlinks, submodules and special entries are not allowed: {path}")
            resolved = (repository_dir / safe_path).resolve()
            if not resolved.is_relative_to(repository_dir.resolve()):
                raise ExecutionSafetyError(f"Tracked path escapes the repository: {path}")
            candidate = repository_dir / safe_path
            if candidate.is_symlink() or not candidate.is_file():
                raise ExecutionSafetyError(f"Tracked symlinks and special entries are not allowed: {path}")
            size = candidate.stat().st_size
            if size > self.policy.max_file_bytes:
                raise ExecutionSafetyError(f"Tracked file exceeds the per-file policy limit: {path}")
            total_bytes += size
            if total_bytes > self.policy.max_total_bytes:
                raise ExecutionSafetyError("Repository exceeds the total tracked-byte policy limit.")
        return sorted(paths)

    def _changed_paths(self, repository_dir: Path, environment: dict[str, str]) -> list[str]:
        raw = _require_success(
            _run([self.git, "diff", "--cached", "--name-only", "-z", "--"], cwd=repository_dir, environment=environment),
            "Changed-file inspection",
        )
        return sorted(_validate_repo_path(path) for path in raw.split("\x00") if path)

    def _status_paths(self, repository_dir: Path, environment: dict[str, str]) -> list[str]:
        raw = _require_success(
            _run([self.git, "status", "--porcelain=v1", "-z", "--untracked-files=all"], cwd=repository_dir, environment=environment),
            "Working-tree verification",
        )
        paths: list[str] = []
        for entry in (item for item in raw.split("\x00") if item):
            if len(entry) < 4 or entry[:2] != "M ":
                raise ExecutionSafetyError("Only staged modifications to existing files are allowed.")
            paths.append(_validate_repo_path(entry[3:]))
        return sorted(paths)

    def _run_tests(self, repository_dir: Path, environment: dict[str, str], profile: str) -> TestResult:
        command = TEST_PROFILES[profile]
        started = perf_counter()
        try:
            result = _run(
                command,
                cwd=repository_dir,
                environment=environment,
                timeout=self.policy.test_timeout_seconds,
            )
            duration_ms = round((perf_counter() - started) * 1000, 3)
            stdout_truncated = len(result.stdout) > OUTPUT_LIMIT_CHARS
            stderr_truncated = len(result.stderr) > OUTPUT_LIMIT_CHARS
            return TestResult(
                profile=profile,
                command=list(command),
                return_code=result.returncode,
                passed=result.returncode == 0,
                timed_out=False,
                duration_ms=duration_ms,
                stdout=result.stdout[-OUTPUT_LIMIT_CHARS:],
                stderr=result.stderr[-OUTPUT_LIMIT_CHARS:],
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
            )
        except subprocess.TimeoutExpired as error:
            duration_ms = round((perf_counter() - started) * 1000, 3)
            stdout = error.stdout or ""
            stderr = error.stderr or ""
            return TestResult(
                profile=profile,
                command=list(command),
                return_code=None,
                passed=False,
                timed_out=True,
                duration_ms=duration_ms,
                stdout=stdout[-OUTPUT_LIMIT_CHARS:],
                stderr=stderr[-OUTPUT_LIMIT_CHARS:],
                stdout_truncated=len(stdout) > OUTPUT_LIMIT_CHARS,
                stderr_truncated=len(stderr) > OUTPUT_LIMIT_CHARS,
            )

    @staticmethod
    def _execution_id(issue: Issue, source: str, patch_text: str) -> str:
        payload = json.dumps(
            {"issue": issue.to_dict(), "source": source, "patch": patch_text},
            sort_keys=True,
        ).encode("utf-8")
        return f"RSX-{issue.number}-{hashlib.sha256(payload).hexdigest()[:10].upper()}"
