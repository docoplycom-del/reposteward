from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import signal
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from time import perf_counter
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit

from .models import Issue


EXECUTION_CONTRACT_VERSION = "reposteward.execution.v1"
PATCH_LIMIT_BYTES = 256 * 1024
OUTPUT_LIMIT_CHARS = 20_000
REMOTE_REPOSITORY_PATTERN = re.compile(r"^/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?$")
DIFF_HEADER_PATTERN = re.compile(r"^diff --git a/([A-Za-z0-9._/+\-]+) b/([A-Za-z0-9._/+\-]+)$")
DOCKER_IMAGE_REFERENCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+:@-]{0,254}$")
DOCKER_IMAGE_ID_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
DOCKER_CONTAINER_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
DEFAULT_DOCKER_IMAGE = "python:3.11.15-slim-bookworm"
ALLOWED_DOCKER_IMAGES = (DEFAULT_DOCKER_IMAGE,)
TEST_ISOLATIONS = ("process", "docker")
DOCKER_MEMORY_LIMIT = "512m"
DOCKER_CPU_LIMIT = "1.0"
DOCKER_PID_LIMIT = 64
DOCKER_TMPFS_SIZE = "64m"
DOCKER_FILE_LIMIT = 256
DOCKER_LOG_LIMIT = "64k"
DOCKER_MEMORY_BYTES = 512 * 1024 * 1024
DOCKER_NANO_CPUS = 1_000_000_000
DOCKER_CONTAINER_ID_PATTERN = re.compile(r"^[a-f0-9]{12,64}$")
DOCKER_CONTEXT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
DOCKER_PYTHON_REPO_DIGEST_PATTERN = re.compile(
    r"^(?:docker\.io/library/)?python@sha256:[a-f0-9]{64}$"
)


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
    test_isolation: str = "process"
    docker_image: str = DEFAULT_DOCKER_IMAGE


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
    isolation_details: dict[str, Any] = field(default_factory=dict)


TEST_PROFILES: dict[str, tuple[str, ...]] = {
    "python-unittest": (sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"),
}

CONTAINER_TEST_PROFILES: dict[str, tuple[str, ...]] = {
    "python-unittest": ("-m", "unittest", "discover", "-s", "tests", "-v"),
}

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


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
    if os.name == "nt":
        home_drive, home_path = os.path.splitdrive(str(home))
        environment["USERPROFILE"] = str(home)
        environment["HOMEDRIVE"] = home_drive
        environment["HOMEPATH"] = home_path
    return environment


def _docker_control_environment() -> dict[str, str]:
    """Keep only local-engine discovery values; none are forwarded into a container."""
    environment = {"PATH": os.defpath}
    for name in (
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TMP",
        "TEMP",
        "LANG",
        "LC_ALL",
        "HOME",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "XDG_RUNTIME_DIR",
        "DOCKER_CONFIG",
        "DOCKER_CONTEXT",
    ):
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
        encoding="utf-8",
        errors="replace",
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


def _validate_docker_image_reference(reference: str) -> str:
    if not DOCKER_IMAGE_REFERENCE_PATTERN.fullmatch(reference):
        raise ExecutionSafetyError(
            "Docker image references must use conservative registry, repository, tag or digest characters."
        )
    return reference


def _docker_bind_mount(repository_dir: Path) -> str:
    raw_source = str(repository_dir)
    if (
        not raw_source
        or "," in raw_source
        or "\x00" in raw_source
        or any(ord(character) < 32 for character in raw_source)
        or (os.name == "nt" and raw_source.startswith("\\\\"))
    ):
        raise ExecutionSafetyError("Docker bind source contains characters unsafe for Docker's mount grammar.")
    try:
        source = str(repository_dir.resolve(strict=True))
    except OSError as error:
        raise ExecutionSafetyError("Docker bind source must be an existing local directory.") from error
    if not repository_dir.is_dir():
        raise ExecutionSafetyError("Docker bind source must be an existing local directory.")
    return f"type=bind,source={source},target=/workspace,readonly"


def _build_docker_create_command(
    docker_command: Sequence[str],
    image_id: str,
    repository_dir: Path,
    container_name: str,
    execution_id: str,
    profile: str,
) -> list[str]:
    if not DOCKER_IMAGE_ID_PATTERN.fullmatch(image_id):
        raise ExecutionSafetyError("Docker image inspection did not return an immutable SHA-256 image ID.")
    if not DOCKER_CONTAINER_NAME_PATTERN.fullmatch(container_name):
        raise ExecutionSafetyError("Generated Docker container name is invalid.")
    if profile not in CONTAINER_TEST_PROFILES:
        raise ExecutionSafetyError(f"Unknown container test profile: {profile}")
    return [
        *docker_command,
        "create",
        "--pull",
        "never",
        "--platform",
        "linux/amd64",
        "--name",
        container_name,
        "--label",
        f"com.docoply.reposteward.execution-id={execution_id}",
        "--hostname",
        "reposteward",
        "--network",
        "none",
        "--ipc",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--user",
        "65534:65534",
        "--pids-limit",
        str(DOCKER_PID_LIMIT),
        "--memory",
        DOCKER_MEMORY_LIMIT,
        "--memory-swap",
        DOCKER_MEMORY_LIMIT,
        "--cpus",
        DOCKER_CPU_LIMIT,
        "--ulimit",
        f"nofile={DOCKER_FILE_LIMIT}:{DOCKER_FILE_LIMIT}",
        "--ulimit",
        "core=0:0",
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,nodev,size={DOCKER_TMPFS_SIZE},mode=1777",
        "--mount",
        _docker_bind_mount(repository_dir),
        "--workdir",
        "/workspace",
        "--env",
        "HOME=/tmp",
        "--env",
        "TMPDIR=/tmp",
        "--env",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--env",
        "PYTHONNOUSERSITE=1",
        "--env",
        "PYTHONHASHSEED=0",
        "--env",
        "PIP_NO_INDEX=1",
        "--restart",
        "no",
        "--stop-timeout",
        "1",
        "--no-healthcheck",
        "--log-driver",
        "local",
        "--log-opt",
        f"max-size={DOCKER_LOG_LIMIT}",
        "--log-opt",
        "max-file=1",
        "--log-opt",
        "compress=false",
        "--init",
        "--entrypoint",
        "python",
        image_id,
        "-E",
        "-s",
        "-B",
        *CONTAINER_TEST_PROFILES[profile],
    ]


def _docker_isolation_details(
    image_reference: str,
    image: dict[str, Any],
    server: dict[str, Any],
    context: dict[str, str],
    container_id: str,
    repository_dir: Path,
) -> dict[str, Any]:
    return {
        "engine": "docker",
        "engineVersion": server.get("ServerVersion"),
        "engineOs": server.get("OSType"),
        "engineArchitecture": server.get("Architecture"),
        "engineContext": context["name"],
        "engineEndpointType": context["endpointType"],
        "imageReference": image_reference,
        "imageId": image["Id"],
        "imageRepoDigests": image.get("RepoDigests") or [],
        "imageOs": image.get("Os"),
        "imageArchitecture": image.get("Architecture"),
        "imagePullPolicy": "never",
        "containerIdSha256": hashlib.sha256(container_id.encode("ascii")).hexdigest(),
        "containerConfigurationInspected": True,
        "containerLifecycle": "create_verify_start_wait_remove",
        "network": "none",
        "rootFilesystem": "read_only",
        "repositoryMount": "read_only",
        "repositorySourceSha256": hashlib.sha256(str(repository_dir.resolve()).encode("utf-8")).hexdigest(),
        "declaredWritableScratch": ["tmpfs:/tmp"],
        "hostCredentialsMounted": False,
        "dockerSocketMounted": False,
        "user": "65534:65534",
        "capabilitiesDropped": ["ALL"],
        "noNewPrivileges": True,
        "seccompProfile": "daemon_default",
        "resourceLimits": {
            "cpus": DOCKER_CPU_LIMIT,
            "memory": DOCKER_MEMORY_LIMIT,
            "memorySwap": DOCKER_MEMORY_LIMIT,
            "pids": DOCKER_PID_LIMIT,
            "openFiles": DOCKER_FILE_LIMIT,
            "tmpfs": DOCKER_TMPFS_SIZE,
            "retainedLogs": DOCKER_LOG_LIMIT,
        },
        "cleanup": {"removed": True, "verifiedByDaemon": True},
    }


def _parse_single_docker_object(raw: str, action: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ExecutionSafetyError(f"{action} returned invalid JSON.") from error
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise ExecutionSafetyError(f"{action} did not return exactly one object.")
    return payload[0]


def _normalized_mount_source(value: str) -> str:
    normalized = value.replace("\\", "/").rstrip("/")
    return normalized.casefold() if os.name == "nt" else normalized


def _verify_docker_container(
    container: dict[str, Any],
    image_id: str,
    execution_id: str,
    profile: str,
    repository_dir: Path,
) -> None:
    config = container.get("Config") or {}
    host = container.get("HostConfig") or {}
    log_config = host.get("LogConfig") or {}
    restart = host.get("RestartPolicy") or {}
    expected_command = ["-E", "-s", "-B", *CONTAINER_TEST_PROFILES[profile]]
    failures: list[str] = []

    def require(condition: bool, name: str) -> None:
        if not condition:
            failures.append(name)

    require(container.get("Image") == image_id, "immutable image ID")
    require(config.get("User") == "65534:65534", "non-root user")
    require(config.get("WorkingDir") == "/workspace", "working directory")
    require(config.get("Entrypoint") == ["python"], "entrypoint")
    require(config.get("Cmd") == expected_command, "allowlisted command")
    require(config.get("Hostname") == "reposteward", "hostname")
    healthcheck = config.get("Healthcheck") or {}
    require(healthcheck.get("Test") == ["NONE"], "disabled health check")
    labels = config.get("Labels") or {}
    require(labels.get("com.docoply.reposteward.execution-id") == execution_id, "execution label")

    require(host.get("NetworkMode") == "none", "network namespace")
    require(host.get("IpcMode") == "none", "IPC namespace")
    require(host.get("ReadonlyRootfs") is True, "read-only root filesystem")
    require(host.get("Privileged") is False, "unprivileged mode")
    require(host.get("CapDrop") == ["ALL"], "dropped capabilities")
    require("no-new-privileges:true" in (host.get("SecurityOpt") or []), "no-new-privileges")
    require(host.get("PidsLimit") == DOCKER_PID_LIMIT, "PID limit")
    require(host.get("Memory") == DOCKER_MEMORY_BYTES, "memory limit")
    require(host.get("MemorySwap") == DOCKER_MEMORY_BYTES, "swap limit")
    require(host.get("NanoCpus") == DOCKER_NANO_CPUS, "CPU limit")
    require(restart.get("Name") == "no", "restart policy")
    require(log_config.get("Type") == "local", "bounded local log driver")
    log_options = log_config.get("Config") or {}
    require(log_options.get("max-size") == DOCKER_LOG_LIMIT, "log size limit")
    require(log_options.get("max-file") == "1", "log file limit")
    require(log_options.get("compress") == "false", "disabled log compression")
    tmpfs = host.get("Tmpfs") or {}
    tmpfs_options = tmpfs.get("/tmp", "")
    tmpfs_option_set = set(tmpfs_options.split(","))
    require("/tmp" in tmpfs, "bounded writable tmpfs")
    require(
        f"size={DOCKER_TMPFS_SIZE}" in tmpfs_options or "size=67108864" in tmpfs_options,
        "tmpfs size limit",
    )
    require({"rw", "noexec", "nosuid", "nodev", "mode=1777"}.issubset(tmpfs_option_set), "tmpfs restrictions")
    require(not {"exec", "suid", "dev"}.intersection(tmpfs_option_set), "tmpfs has no weakening options")
    require(host.get("Init") is True, "container init")
    require(not (host.get("Devices") or []), "no host devices")
    require(not (host.get("PortBindings") or {}), "no published ports")
    ulimits = {
        entry.get("Name"): (entry.get("Soft"), entry.get("Hard"))
        for entry in (host.get("Ulimits") or [])
        if isinstance(entry, dict)
    }
    require(ulimits.get("nofile") == (DOCKER_FILE_LIMIT, DOCKER_FILE_LIMIT), "open-file limit")
    require(ulimits.get("core") == (0, 0), "core-dump limit")

    requested_mounts = host.get("Mounts") or []
    effective_mounts = container.get("Mounts") or []
    require(len(requested_mounts) == 1, "single requested repository mount")
    if len(requested_mounts) == 1:
        mount = requested_mounts[0]
        require(mount.get("Type") == "bind", "bind mount type")
        require(mount.get("Target") == "/workspace", "repository mount target")
        require(mount.get("ReadOnly") is True, "read-only repository mount")
        require(
            _normalized_mount_source(str(mount.get("Source", "")))
            == _normalized_mount_source(str(repository_dir.resolve(strict=True))),
            "repository mount source",
        )
    if effective_mounts:
        require(len(effective_mounts) == 1, "single effective repository mount")
        if len(effective_mounts) == 1:
            mount = effective_mounts[0]
            require(mount.get("Type") == "bind", "effective bind mount type")
            require(mount.get("Destination") == "/workspace", "effective repository mount target")
            require(mount.get("RW") is False, "effective read-only repository mount")

    safe_environment = {
        "HOME=/tmp",
        "TMPDIR=/tmp",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONNOUSERSITE=1",
        "PYTHONHASHSEED=0",
        "PIP_NO_INDEX=1",
    }
    configured_environment = set(config.get("Env") or [])
    require(safe_environment.issubset(configured_environment), "sanitized environment")
    forbidden_names = {"GITHUB_TOKEN", "OPENAI_API_KEY", "SSH_AUTH_SOCK", "DOCKER_CONFIG", "DOCKER_HOST"}
    require(
        not any(item.partition("=")[0] in forbidden_names for item in configured_environment),
        "host secrets excluded",
    )

    if failures:
        raise ExecutionSafetyError(
            "Docker effective configuration failed verification: " + ", ".join(failures)
        )


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
    def __init__(
        self,
        workspace_root: Path,
        policy: ExecutionPolicy | None = None,
        *,
        docker_binary: str | None = None,
        docker_command_runner: CommandRunner | None = None,
    ):
        self.workspace_root = workspace_root.resolve()
        self.policy = policy or ExecutionPolicy()
        self.git = shutil.which("git")
        if not self.git:
            raise ExecutionSafetyError("Git is required for repository execution.")
        if self.policy.test_isolation not in TEST_ISOLATIONS:
            raise ExecutionSafetyError(f"Unknown test isolation mode: {self.policy.test_isolation}")
        self.docker: str | None = None
        self._docker_command: list[str] = []
        self._docker_command_runner = docker_command_runner or _run
        if self.policy.test_isolation == "docker":
            _validate_docker_image_reference(self.policy.docker_image)
            if self.policy.docker_image not in ALLOWED_DOCKER_IMAGES:
                raise ExecutionSafetyError("Docker image is not allowlisted by the execution policy.")
            self.docker = docker_binary or shutil.which("docker")
            if not self.docker:
                raise ExecutionSafetyError(
                    "Docker is required for Docker-isolated tests. Install Docker Desktop and use Linux containers."
                )
            self._docker_command = [self.docker]

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
        if self.policy.test_isolation == "process" and not self.policy.allow_test_execution:
            raise ExecutionSafetyError("Test execution requires explicit authorization for a trusted disposable repository.")

        self.workspace_root.mkdir(parents=True, exist_ok=True)
        execution_id = self._execution_id(issue, source, patch_text)
        execution_dir = Path(tempfile.mkdtemp(prefix=f"{execution_id}-", dir=self.workspace_root))
        repository_dir = execution_dir / "repository"
        home_dir = execution_dir / "home"
        home_dir.mkdir()
        environment = _safe_environment(home_dir)
        docker_environment = _docker_control_environment() if self.policy.test_isolation == "docker" else None
        docker_runtime = self._prepare_docker(docker_environment) if docker_environment is not None else None

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
        test_result = self._run_tests(
            repository_dir,
            environment,
            test_profile,
            execution_id,
            docker_runtime,
            docker_environment,
        )
        post_test_status = self._status_paths(repository_dir, environment)
        if post_test_status != sorted(declared_paths):
            raise ExecutionSafetyError("Test execution changed files outside the validated staged patch.")
        post_test_head = _require_success(
            _run([self.git, "rev-parse", "HEAD"], cwd=repository_dir, environment=environment),
            "Post-test HEAD verification",
        ).strip()
        if post_test_head != base_commit:
            raise ExecutionSafetyError("Test execution changed the repository commit.")
        post_test_patch = _require_success(
            _run(
                [self.git, "diff", "--cached", "--no-ext-diff", "--binary", "--full-index", "--"],
                cwd=repository_dir,
                environment=environment,
            ),
            "Post-test patch verification",
        )
        if hashlib.sha256(post_test_patch.encode("utf-8")).hexdigest() != patch_sha256:
            raise ExecutionSafetyError("Test execution changed the applied patch.")
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
            "safetyBoundary": self._safety_boundary(test_result),
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

    def _prepare_docker(self, environment: dict[str, str]) -> dict[str, dict[str, Any]]:
        assert self.docker is not None
        context = self._resolve_docker_context(environment)
        try:
            info_result = self._docker_command_runner(
                [*self._docker_command, "info", "--format", "{{json .}}"],
                cwd=None,
                environment=environment,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ExecutionSafetyError("Docker daemon preflight did not complete.") from error
        _require_success(info_result, "Docker daemon preflight")
        try:
            server = json.loads(info_result.stdout)
        except json.JSONDecodeError as error:
            raise ExecutionSafetyError("Docker daemon preflight returned invalid JSON.") from error
        if not isinstance(server, dict):
            raise ExecutionSafetyError("Docker daemon preflight returned an unexpected response.")
        if server.get("OSType") != "linux":
            raise ExecutionSafetyError("Docker must be running Linux containers for this execution profile.")
        required_resource_controls = ("MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit")
        unavailable_controls = [
            name for name in required_resource_controls if server.get(name) is not True
        ]
        if unavailable_controls:
            raise ExecutionSafetyError(
                "Docker daemon does not report required resource controls: "
                + ", ".join(unavailable_controls)
            )
        security_options = [str(option).casefold() for option in (server.get("SecurityOptions") or [])]
        if not any("seccomp" in option for option in security_options):
            raise ExecutionSafetyError("Docker daemon does not report an active seccomp security profile.")

        try:
            image_result = self._docker_command_runner(
                [*self._docker_command, "image", "inspect", self.policy.docker_image],
                cwd=None,
                environment=environment,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ExecutionSafetyError("Docker image inspection did not complete.") from error
        if image_result.returncode != 0:
            raise ExecutionSafetyError(
                f"Docker image {self.policy.docker_image!r} is not available locally; pull it before execution. "
                "Runtime image pulls are disabled."
            )
        image = _parse_single_docker_object(image_result.stdout, "Docker image inspection")
        if not DOCKER_IMAGE_ID_PATTERN.fullmatch(str(image.get("Id", ""))):
            raise ExecutionSafetyError("Docker image inspection did not return an immutable SHA-256 image ID.")
        if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
            raise ExecutionSafetyError("Docker test image must target linux/amd64.")
        if (image.get("Config") or {}).get("Volumes"):
            raise ExecutionSafetyError("Docker test image declares unexpected writable volumes.")
        repo_digests = image.get("RepoDigests") or []
        if not any(
            isinstance(digest, str) and DOCKER_PYTHON_REPO_DIGEST_PATTERN.fullmatch(digest)
            for digest in repo_digests
        ):
            raise ExecutionSafetyError("Docker test image has no recognised Python Official Image repo digest.")
        return {"server": server, "image": image, "context": context}

    def _resolve_docker_context(self, environment: dict[str, str]) -> dict[str, str]:
        assert self.docker is not None
        if os.environ.get("DOCKER_HOST"):
            raise ExecutionSafetyError(
                "DOCKER_HOST overrides are not allowed; select a local Docker context instead."
            )
        try:
            show_result = self._docker_command_runner(
                [self.docker, "context", "show"],
                cwd=None,
                environment=environment,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ExecutionSafetyError("Docker context discovery did not complete.") from error
        _require_success(show_result, "Docker context discovery")
        context_name = show_result.stdout.strip()
        if not DOCKER_CONTEXT_NAME_PATTERN.fullmatch(context_name):
            raise ExecutionSafetyError("Docker selected an invalid context name.")
        try:
            inspect_result = self._docker_command_runner(
                [self.docker, "context", "inspect", context_name],
                cwd=None,
                environment=environment,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ExecutionSafetyError("Docker context inspection did not complete.") from error
        _require_success(inspect_result, "Docker context inspection")
        context = _parse_single_docker_object(inspect_result.stdout, "Docker context inspection")
        endpoint = ((context.get("Endpoints") or {}).get("docker") or {}).get("Host")
        if not isinstance(endpoint, str):
            raise ExecutionSafetyError("Docker context does not declare an engine endpoint.")
        if endpoint.startswith("unix:///"):
            endpoint_type = "unix"
        elif endpoint.startswith("npipe:////"):
            endpoint_type = "npipe"
        else:
            raise ExecutionSafetyError("Docker context must use a local unix:// or npipe:// endpoint.")
        self._docker_command = [self.docker, "--context", context_name]
        return {"name": context_name, "endpointType": endpoint_type}

    def _run_tests(
        self,
        repository_dir: Path,
        environment: dict[str, str],
        profile: str,
        execution_id: str,
        docker_runtime: dict[str, dict[str, Any]] | None,
        docker_environment: dict[str, str] | None,
    ) -> TestResult:
        if self.policy.test_isolation == "docker":
            if docker_runtime is None or docker_environment is None:
                raise ExecutionSafetyError("Docker runtime preflight was not completed.")
            return self._run_tests_docker(
                repository_dir,
                docker_environment,
                profile,
                execution_id,
                docker_runtime,
            )
        return self._run_tests_process(repository_dir, environment, profile)

    def _run_tests_process(
        self,
        repository_dir: Path,
        environment: dict[str, str],
        profile: str,
    ) -> TestResult:
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

    def _run_tests_docker(
        self,
        repository_dir: Path,
        environment: dict[str, str],
        profile: str,
        execution_id: str,
        runtime: dict[str, dict[str, Any]],
    ) -> TestResult:
        assert self.docker is not None
        image = runtime["image"]
        image_id = str(image["Id"])
        container_name = (
            f"reposteward-{hashlib.sha256(execution_id.encode('ascii')).hexdigest()[:16]}-"
            f"{secrets.token_hex(4)}"
        )
        create_command = _build_docker_create_command(
            self._docker_command,
            image_id,
            repository_dir,
            container_name,
            execution_id,
            profile,
        )
        logical_command = ["python", "-E", "-s", "-B", *CONTAINER_TEST_PROFILES[profile]]
        try:
            create_result = self._docker_command_runner(
                create_command,
                cwd=None,
                environment=environment,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            self._remove_docker_container(container_name, environment)
            raise ExecutionSafetyError("Docker container creation did not complete.") from error
        if create_result.returncode != 0:
            self._remove_docker_container(container_name, environment)
        _require_success(create_result, "Docker container creation")
        container_id = create_result.stdout.strip()
        if not DOCKER_CONTAINER_ID_PATTERN.fullmatch(container_id):
            self._remove_docker_container(container_name, environment)
            raise ExecutionSafetyError("Docker container creation returned an invalid container ID.")

        started = perf_counter()
        timed_out = False
        try:
            inspection = self._inspect_docker_container(container_id, environment)
            _verify_docker_container(inspection, image_id, execution_id, profile, repository_dir)
            start_result = self._docker_command_runner(
                [*self._docker_command, "container", "start", container_id],
                cwd=None,
                environment=environment,
                timeout=30,
            )
            _require_success(start_result, "Docker container start")
            try:
                wait_result = self._docker_command_runner(
                    [*self._docker_command, "container", "wait", container_id],
                    cwd=None,
                    environment=environment,
                    timeout=self.policy.test_timeout_seconds,
                )
                _require_success(wait_result, "Docker container wait")
            except subprocess.TimeoutExpired:
                timed_out = True
                kill_result = self._docker_command_runner(
                    [*self._docker_command, "container", "kill", container_id],
                    cwd=None,
                    environment=environment,
                    timeout=15,
                )
                if kill_result.returncode != 0:
                    state_after_kill = self._inspect_docker_container(container_id, environment).get("State") or {}
                    if state_after_kill.get("Running") is True:
                        raise ExecutionSafetyError("Timed-out Docker container could not be stopped.")

            final_inspection = self._inspect_docker_container(container_id, environment)
            state = final_inspection.get("State") or {}
            if state.get("Running") is True:
                raise ExecutionSafetyError("Docker container remained running after test completion.")
            exit_code = state.get("ExitCode")
            if not isinstance(exit_code, int):
                raise ExecutionSafetyError("Docker container did not report a test exit code.")
            logs_result = self._docker_command_runner(
                [*self._docker_command, "container", "logs", container_id],
                cwd=None,
                environment=environment,
                timeout=15,
            )
            _require_success(logs_result, "Docker test log collection")
            duration_ms = round((perf_counter() - started) * 1000, 3)
            stdout_truncated = len(logs_result.stdout) > OUTPUT_LIMIT_CHARS
            stderr_truncated = len(logs_result.stderr) > OUTPUT_LIMIT_CHARS
            details = _docker_isolation_details(
                self.policy.docker_image,
                image,
                runtime["server"],
                runtime["context"],
                container_id,
                repository_dir,
            )
            details["oomKilled"] = bool(state.get("OOMKilled"))
            return TestResult(
                profile=profile,
                command=logical_command,
                return_code=exit_code,
                passed=exit_code == 0 and not timed_out and not bool(state.get("OOMKilled")),
                timed_out=timed_out,
                duration_ms=duration_ms,
                stdout=logs_result.stdout[-OUTPUT_LIMIT_CHARS:],
                stderr=logs_result.stderr[-OUTPUT_LIMIT_CHARS:],
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
                isolation_level="docker",
                isolation_details=details,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ExecutionSafetyError("Docker test lifecycle control operation did not complete.") from error
        finally:
            self._remove_docker_container(container_id, environment)

    def _inspect_docker_container(
        self,
        container: str,
        environment: dict[str, str],
    ) -> dict[str, Any]:
        assert self.docker is not None
        result = self._docker_command_runner(
            [*self._docker_command, "container", "inspect", container],
            cwd=None,
            environment=environment,
            timeout=15,
        )
        _require_success(result, "Docker container inspection")
        return _parse_single_docker_object(result.stdout, "Docker container inspection")

    def _remove_docker_container(self, container: str, environment: dict[str, str]) -> None:
        assert self.docker is not None
        try:
            result = self._docker_command_runner(
                [*self._docker_command, "container", "rm", "--force", "--volumes", container],
                cwd=None,
                environment=environment,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ExecutionSafetyError("Docker container cleanup did not complete; approval is blocked.") from error
        if result.returncode != 0:
            filter_value = (
                f"id={container}" if DOCKER_CONTAINER_ID_PATTERN.fullmatch(container)
                else f"name=^/{container}$"
            )
            try:
                verification = self._docker_command_runner(
                    [*self._docker_command, "container", "ls", "--all", "--quiet", "--filter", filter_value],
                    cwd=None,
                    environment=environment,
                    timeout=15,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ExecutionSafetyError("Docker container cleanup could not be verified; approval is blocked.") from error
            if verification.returncode == 0 and not verification.stdout.strip():
                return
            raise ExecutionSafetyError("Docker container cleanup failed; approval is blocked.")

    @staticmethod
    def _safety_boundary(test_result: TestResult) -> dict[str, Any]:
        if test_result.isolation_level == "docker":
            return {
                "testIsolation": "docker",
                "networkIsolation": True,
                "repositoryReadOnly": True,
                "rootFilesystemReadOnly": True,
                "hostCredentialsMounted": False,
                "dockerSocketMounted": False,
                "sharedKernelContainerBoundary": True,
                "trustedDisposableRepositoryRequired": False,
            }
        return {
            "testIsolation": "process_only",
            "networkIsolation": False,
            "trustedDisposableRepositoryRequired": True,
        }

    @staticmethod
    def _execution_id(issue: Issue, source: str, patch_text: str) -> str:
        payload = json.dumps(
            {"issue": issue.to_dict(), "source": source, "patch": patch_text},
            sort_keys=True,
        ).encode("utf-8")
        return f"RSX-{issue.number}-{hashlib.sha256(payload).hexdigest()[:10].upper()}"
