from __future__ import annotations

import io
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from reposteward.cli import build_execute_parser, run_execute
from reposteward.execution import (
    DEFAULT_DOCKER_IMAGE,
    DOCKER_CPU_LIMIT,
    DOCKER_FILE_LIMIT,
    DOCKER_LOG_LIMIT,
    DOCKER_MEMORY_BYTES,
    DOCKER_MEMORY_LIMIT,
    DOCKER_NANO_CPUS,
    DOCKER_PID_LIMIT,
    DOCKER_TMPFS_SIZE,
    OUTPUT_LIMIT_CHARS,
    ExecutionPolicy,
    ExecutionSafetyError,
    WorkspaceExecutor,
    _build_docker_create_command,
    _docker_bind_mount,
    _run,
    _safe_environment,
    _write_utf8_lf,
    validate_patch,
    validate_repository_source,
)
from reposteward.models import Issue


VALID_PATCH = """diff --git a/greeting.py b/greeting.py
--- a/greeting.py
+++ b/greeting.py
@@ -1,2 +1,2 @@
 def greeting(name: str) -> str:
-    return f\"Hello {name}\"
+    return f\"Hello, {name}!\"
"""

FAILING_PATCH = VALID_PATCH.replace('Hello, {name}!', 'Goodbye {name}')

DOCKER_IMAGE_ID = f"sha256:{'a' * 64}"
DOCKER_CONTAINER_ID = "b" * 64


def docker_args(command: object) -> list[str]:
    if not isinstance(command, list):
        raise AssertionError("Recorded Docker command is not an argv list")
    return command[3:] if len(command) > 3 and command[1] == "--context" else command[1:]


class FakeDocker:
    def __init__(
        self,
        *,
        exit_code: int = 0,
        time_out: bool = False,
        server_os: str = "linux",
        image_available: bool = True,
        network_mode: str = "none",
        cleanup_succeeds: bool = True,
        oom_killed: bool = False,
        create_times_out: bool = False,
        context_endpoint: str = "npipe:////./pipe/dockerDesktopLinuxEngine",
        mount_source_override: str | None = None,
        stdout: str = "container tests passed\n",
        stderr: str = "",
    ) -> None:
        self.exit_code = exit_code
        self.time_out = time_out
        self.server_os = server_os
        self.image_available = image_available
        self.network_mode = network_mode
        self.cleanup_succeeds = cleanup_succeeds
        self.oom_killed = oom_killed
        self.create_times_out = create_times_out
        self.context_endpoint = context_endpoint
        self.mount_source_override = mount_source_override
        self.stdout = stdout
        self.stderr = stderr
        self.calls: list[dict[str, object]] = []
        self.execution_id = ""
        self.mount_source = ""
        self.container_exists = False

    def __call__(
        self,
        command: list[str] | tuple[str, ...],
        *,
        cwd: Path | None,
        environment: dict[str, str],
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        argv = list(command)
        self.calls.append({
            "command": argv,
            "cwd": cwd,
            "environment": dict(environment),
            "timeout": timeout,
        })
        args = argv[3:] if len(argv) > 3 and argv[1] == "--context" else argv[1:]
        if args[:2] == ["context", "show"]:
            return self._completed(argv, stdout="desktop-linux\n")
        if args[:2] == ["context", "inspect"]:
            return self._completed(argv, stdout=json.dumps([{
                "Name": "desktop-linux",
                "Endpoints": {"docker": {"Host": self.context_endpoint}},
            }]))
        if args[0] == "info":
            return self._completed(
                argv,
                stdout=json.dumps({
                    "OSType": self.server_os,
                    "Architecture": "x86_64",
                    "ServerVersion": "test-engine",
                    "MemoryLimit": True,
                    "SwapLimit": True,
                    "CpuCfsQuota": True,
                    "PidsLimit": True,
                    "SecurityOptions": ["name=seccomp,profile=builtin"],
                }),
            )
        if args[:2] == ["image", "inspect"]:
            if not self.image_available:
                return self._completed(argv, return_code=1, stderr="No such image")
            return self._completed(argv, stdout=json.dumps([{
                "Id": DOCKER_IMAGE_ID,
                "RepoDigests": ["python@sha256:" + "c" * 64],
                "Os": "linux",
                "Architecture": "amd64",
                "Config": {"Volumes": None},
            }]))
        if args[0] == "create":
            label = argv[argv.index("--label") + 1]
            self.execution_id = label.partition("=")[2]
            mount = argv[argv.index("--mount") + 1]
            self.mount_source = mount.split(",source=", 1)[1].split(",target=", 1)[0]
            self.container_exists = True
            if self.create_times_out:
                raise subprocess.TimeoutExpired(argv, timeout)
            return self._completed(argv, stdout=f"{DOCKER_CONTAINER_ID}\n")
        if args[:2] == ["container", "inspect"]:
            return self._completed(argv, stdout=json.dumps([self._container_inspection()]))
        if args[:2] == ["container", "start"]:
            return self._completed(argv, stdout=f"{DOCKER_CONTAINER_ID}\n")
        if args[:2] == ["container", "wait"]:
            if self.time_out:
                raise subprocess.TimeoutExpired(argv, timeout)
            return self._completed(argv, stdout=f"{self.exit_code}\n")
        if args[:2] == ["container", "kill"]:
            return self._completed(argv, stdout=f"{DOCKER_CONTAINER_ID}\n")
        if args[:2] == ["container", "logs"]:
            return self._completed(argv, stdout=self.stdout, stderr=self.stderr)
        if args[:2] == ["container", "rm"]:
            if self.cleanup_succeeds:
                self.container_exists = False
            return self._completed(
                argv,
                return_code=0 if self.cleanup_succeeds else 1,
                stdout=f"{DOCKER_CONTAINER_ID}\n" if self.cleanup_succeeds else "",
                stderr="cleanup failed" if not self.cleanup_succeeds else "",
            )
        if args[:2] == ["container", "ls"]:
            return self._completed(
                argv,
                stdout=f"{DOCKER_CONTAINER_ID}\n" if self.container_exists else "",
            )
        raise AssertionError(f"Unexpected Docker command: {argv}")

    @staticmethod
    def _completed(
        command: list[str],
        *,
        return_code: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, return_code, stdout, stderr)

    def _container_inspection(self) -> dict[str, object]:
        final_exit_code = 137 if self.time_out else self.exit_code
        return {
            "Image": DOCKER_IMAGE_ID,
            "Config": {
                "User": "65534:65534",
                "WorkingDir": "/workspace",
                "Entrypoint": ["python"],
                "Cmd": ["-E", "-s", "-B", "-m", "unittest", "discover", "-s", "tests", "-v"],
                "Hostname": "reposteward",
                "Healthcheck": {"Test": ["NONE"]},
                "Labels": {"com.docoply.reposteward.execution-id": self.execution_id},
                "Env": [
                    "HOME=/tmp",
                    "TMPDIR=/tmp",
                    "PATH=/usr/local/bin:/usr/bin:/bin",
                    "PYTHONDONTWRITEBYTECODE=1",
                    "PYTHONNOUSERSITE=1",
                    "PYTHONHASHSEED=0",
                    "PIP_NO_INDEX=1",
                ],
            },
            "HostConfig": {
                "NetworkMode": self.network_mode,
                "IpcMode": "none",
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "PidsLimit": DOCKER_PID_LIMIT,
                "Memory": DOCKER_MEMORY_BYTES,
                "MemorySwap": DOCKER_MEMORY_BYTES,
                "NanoCpus": DOCKER_NANO_CPUS,
                "RestartPolicy": {"Name": "no"},
                "LogConfig": {
                    "Type": "local",
                    "Config": {"max-size": DOCKER_LOG_LIMIT, "max-file": "1"},
                },
                "Tmpfs": {"/tmp": f"rw,noexec,nosuid,nodev,size={DOCKER_TMPFS_SIZE},mode=1777"},
                "Init": True,
                "Devices": [],
                "PortBindings": {},
                "Ulimits": [
                    {"Name": "nofile", "Soft": DOCKER_FILE_LIMIT, "Hard": DOCKER_FILE_LIMIT},
                    {"Name": "core", "Soft": 0, "Hard": 0},
                ],
                "Mounts": [{
                    "Type": "bind",
                    "Source": self.mount_source_override or self.mount_source,
                    "Target": "/workspace",
                    "ReadOnly": True,
                }],
            },
            "State": {
                "Running": False,
                "ExitCode": final_exit_code,
                "OOMKilled": self.oom_killed,
            },
        }


class ExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "tests").mkdir()
        (self.source / "greeting.py").write_text(
            'def greeting(name: str) -> str:\n    return f"Hello {name}"\n',
            encoding="utf-8",
        )
        (self.source / "tests" / "test_greeting.py").write_text(
            "import unittest\nfrom greeting import greeting\n\n"
            "class Tests(unittest.TestCase):\n"
            "    def test_greeting(self):\n"
            "        self.assertEqual(greeting('Ada'), 'Hello, Ada!')\n",
            encoding="utf-8",
        )
        self._git("init", "-b", "main")
        self._git("config", "user.name", "RepoSteward Test")
        self._git("config", "user.email", "test@reposteward.invalid")
        self._git("add", ".")
        self._git("commit", "-m", "Create fixture")
        self.issue = Issue(
            repository="local/demo",
            number=7,
            title="Greeting omits punctuation",
            body="Return a punctuated greeting.",
            labels=("bug",),
            files=("greeting.py",),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> str:
        result = subprocess.run(
            ["git", *arguments],
            cwd=self.source,
            capture_output=True,
            text=True,
            check=True,
            shell=False,
        )
        return result.stdout

    def executor(self, **overrides: object) -> WorkspaceExecutor:
        values = {"allow_local_repository": True, "allow_test_execution": True}
        values.update(overrides)
        return WorkspaceExecutor(self.root / "workspaces", ExecutionPolicy(**values))

    def docker_executor(self, fake: FakeDocker, **overrides: object) -> WorkspaceExecutor:
        values = {
            "allow_local_repository": True,
            "allow_test_execution": False,
            "test_isolation": "docker",
        }
        values.update(overrides)
        return WorkspaceExecutor(
            self.root / "docker-workspaces",
            ExecutionPolicy(**values),
            docker_binary="docker",
            docker_command_runner=fake,
        )

    def test_valid_patch_runs_allowlisted_tests_and_stops_for_approval(self) -> None:
        receipt = self.executor().execute(self.issue, str(self.source), VALID_PATCH, "python-unittest")
        self.assertEqual(receipt["status"], "AWAITING_HUMAN_APPROVAL")
        self.assertTrue(receipt["tests"]["passed"])
        self.assertEqual(receipt["patch"]["changedFiles"], ["greeting.py"])
        self.assertEqual(receipt["patch"]["candidateSha256"], hashlib.sha256(VALID_PATCH.encode()).hexdigest())
        self.assertTrue(receipt["workspace"]["remoteRemoved"])
        self.assertFalse(receipt["approval"]["pushCapabilityPresent"])
        cloned = Path(receipt["workspace"]["path"])
        self.assertEqual(
            subprocess.run(["git", "remote"], cwd=cloned, capture_output=True, text=True, check=True).stdout,
            "",
        )
        self.assertIn("Hello, {name}!", (cloned / "greeting.py").read_text(encoding="utf-8"))
        self.assertIn("Hello {name}", (self.source / "greeting.py").read_text(encoding="utf-8"))
        self.assertEqual(receipt["tests"]["isolation_level"], "process_only")
        self.assertFalse(receipt["safetyBoundary"]["networkIsolation"])
        self.assertTrue(receipt["safetyBoundary"]["trustedDisposableRepositoryRequired"])

    def test_docker_mode_enforces_and_attests_isolation_controls(self) -> None:
        fake = FakeDocker()
        receipt = self.docker_executor(fake).execute(
            self.issue,
            str(self.source),
            VALID_PATCH,
            "python-unittest",
        )

        self.assertEqual(receipt["status"], "AWAITING_HUMAN_APPROVAL")
        self.assertTrue(receipt["tests"]["passed"])
        self.assertEqual(receipt["tests"]["isolation_level"], "docker")
        self.assertEqual(receipt["tests"]["command"][0], "python")
        isolation = receipt["tests"]["isolation_details"]
        self.assertEqual(isolation["imageReference"], DEFAULT_DOCKER_IMAGE)
        self.assertEqual(isolation["imageId"], DOCKER_IMAGE_ID)
        self.assertEqual(isolation["engineContext"], "desktop-linux")
        self.assertEqual(isolation["engineEndpointType"], "npipe")
        self.assertEqual(isolation["network"], "none")
        self.assertEqual(isolation["rootFilesystem"], "read_only")
        self.assertEqual(isolation["repositoryMount"], "read_only")
        self.assertTrue(isolation["containerConfigurationInspected"])
        self.assertTrue(isolation["cleanup"]["removed"])
        self.assertFalse(isolation["hostCredentialsMounted"])
        self.assertFalse(isolation["dockerSocketMounted"])
        self.assertEqual(receipt["safetyBoundary"]["testIsolation"], "docker")
        self.assertTrue(receipt["safetyBoundary"]["networkIsolation"])
        self.assertTrue(receipt["safetyBoundary"]["repositoryReadOnly"])
        self.assertTrue(receipt["safetyBoundary"]["sharedKernelContainerBoundary"])
        self.assertFalse(receipt["safetyBoundary"]["trustedDisposableRepositoryRequired"])
        self.assertTrue(receipt["approval"]["required"])
        self.assertFalse(receipt["approval"]["approved"])
        self.assertFalse(receipt["approval"]["pushCapabilityPresent"])
        self.assertTrue(receipt["workspace"]["remoteRemoved"])

        create = next(
            docker_args(call["command"])
            for call in fake.calls
            if docker_args(call["command"])[0] == "create"
        )
        self.assertEqual(create[create.index("--network") + 1], "none")
        self.assertIn("--read-only", create)
        self.assertEqual(create[create.index("--cap-drop") + 1], "ALL")
        self.assertEqual(create[create.index("--security-opt") + 1], "no-new-privileges:true")
        self.assertEqual(create[create.index("--user") + 1], "65534:65534")
        self.assertEqual(create[create.index("--memory") + 1], DOCKER_MEMORY_LIMIT)
        self.assertEqual(create[create.index("--cpus") + 1], DOCKER_CPU_LIMIT)
        self.assertEqual(create[create.index("--pids-limit") + 1], str(DOCKER_PID_LIMIT))
        self.assertEqual(create.count("--mount"), 1)
        mount = create[create.index("--mount") + 1]
        self.assertIn("target=/workspace", mount)
        self.assertTrue(mount.endswith(",readonly"))
        self.assertNotIn("--privileged", create)
        self.assertNotIn("docker.sock", " ".join(create))
        self.assertIn(DOCKER_IMAGE_ID, create)
        self.assertNotIn(DEFAULT_DOCKER_IMAGE, create)

    def test_docker_command_keeps_special_host_path_in_one_mount_argument(self) -> None:
        repository = self.root / "repo with spaces;dollar$()"
        repository.mkdir()
        command = _build_docker_create_command(
            ["docker"],
            DOCKER_IMAGE_ID,
            repository,
            "reposteward-test",
            "RSX-1-TEST",
            "python-unittest",
        )
        mount = command[command.index("--mount") + 1]
        self.assertEqual(command.count("--mount"), 1)
        self.assertIn(str(repository.resolve()), mount)
        self.assertIn("target=/workspace", mount)

    def test_docker_mount_grammar_injection_is_rejected(self) -> None:
        with self.assertRaisesRegex(ExecutionSafetyError, "mount grammar"):
            _docker_bind_mount(self.root / "comma,path")

    def test_docker_image_must_be_allowlisted(self) -> None:
        with self.assertRaisesRegex(ExecutionSafetyError, "not allowlisted"):
            self.docker_executor(FakeDocker(), docker_image="example/unreviewed:latest")

    def test_docker_timeout_kills_and_removes_container(self) -> None:
        fake = FakeDocker(time_out=True)
        receipt = self.docker_executor(fake).execute(
            self.issue,
            str(self.source),
            VALID_PATCH,
            "python-unittest",
        )
        self.assertEqual(receipt["status"], "BLOCKED_TEST_FAILURE")
        self.assertTrue(receipt["tests"]["timed_out"])
        self.assertFalse(receipt["tests"]["passed"])
        operations = [
            docker_args(call["command"])[1]
            for call in fake.calls
            if docker_args(call["command"])[0] == "container"
        ]
        self.assertIn("kill", operations)
        self.assertIn("rm", operations)

    def test_docker_create_timeout_removes_orphan_by_name(self) -> None:
        fake = FakeDocker(create_times_out=True)
        with self.assertRaisesRegex(ExecutionSafetyError, "creation did not complete"):
            self.docker_executor(fake).execute(
                self.issue,
                str(self.source),
                VALID_PATCH,
                "python-unittest",
            )
        operations = [
            docker_args(call["command"])[1]
            for call in fake.calls
            if docker_args(call["command"])[0] == "container"
        ]
        self.assertIn("rm", operations)
        self.assertFalse(fake.container_exists)

    def test_docker_oom_and_retained_output_block_approval(self) -> None:
        fake = FakeDocker(oom_killed=True, stdout="x" * (OUTPUT_LIMIT_CHARS + 500))
        receipt = self.docker_executor(fake).execute(
            self.issue,
            str(self.source),
            VALID_PATCH,
            "python-unittest",
        )
        self.assertEqual(receipt["status"], "BLOCKED_TEST_FAILURE")
        self.assertFalse(receipt["tests"]["passed"])
        self.assertTrue(receipt["tests"]["stdout_truncated"])
        self.assertEqual(len(receipt["tests"]["stdout"]), OUTPUT_LIMIT_CHARS)
        self.assertTrue(receipt["tests"]["isolation_details"]["oomKilled"])

    def test_docker_effective_config_mismatch_blocks_and_cleans_up(self) -> None:
        fake = FakeDocker(network_mode="bridge")
        with self.assertRaisesRegex(ExecutionSafetyError, "effective configuration"):
            self.docker_executor(fake).execute(
                self.issue,
                str(self.source),
                VALID_PATCH,
                "python-unittest",
            )
        operations = [
            docker_args(call["command"])[1]
            for call in fake.calls
            if docker_args(call["command"])[0] == "container"
        ]
        self.assertIn("rm", operations)
        self.assertNotIn("start", operations)

        with self.assertRaisesRegex(ExecutionSafetyError, "repository mount source"):
            self.docker_executor(FakeDocker(mount_source_override="/wrong/repository")).execute(
                self.issue,
                str(self.source),
                VALID_PATCH,
                "python-unittest",
            )

    def test_docker_cleanup_failure_blocks_approval(self) -> None:
        fake = FakeDocker(cleanup_succeeds=False)
        with self.assertRaisesRegex(ExecutionSafetyError, "cleanup failed"):
            self.docker_executor(fake).execute(
                self.issue,
                str(self.source),
                VALID_PATCH,
                "python-unittest",
            )

    def test_docker_preflight_rejects_windows_containers_and_missing_image(self) -> None:
        with self.assertRaisesRegex(ExecutionSafetyError, "Linux containers"):
            self.docker_executor(FakeDocker(server_os="windows")).execute(
                self.issue,
                str(self.source),
                VALID_PATCH,
                "python-unittest",
            )
        with self.assertRaisesRegex(ExecutionSafetyError, "not available locally"):
            self.docker_executor(FakeDocker(image_available=False)).execute(
                self.issue,
                str(self.source),
                VALID_PATCH,
                "python-unittest",
            )
        with self.assertRaisesRegex(ExecutionSafetyError, "local unix:// or npipe://"):
            self.docker_executor(FakeDocker(context_endpoint="tcp://remote.example:2376")).execute(
                self.issue,
                str(self.source),
                VALID_PATCH,
                "python-unittest",
            )

    def test_docker_does_not_forward_host_secrets(self) -> None:
        fake = FakeDocker()
        secrets = {
            "GITHUB_TOKEN": "github-secret",
            "OPENAI_API_KEY": "openai-secret",
            "SSH_AUTH_SOCK": "secret-socket",
            "DOCKER_CONFIG": "secret-config",
        }
        with patch.dict(os.environ, secrets):
            receipt = self.docker_executor(fake).execute(
                self.issue,
                str(self.source),
                VALID_PATCH,
                "python-unittest",
            )
        rendered = json.dumps(receipt)
        for name, value in secrets.items():
            self.assertNotIn(name, rendered)
            self.assertNotIn(value, rendered)
        create = next(
            docker_args(call["command"])
            for call in fake.calls
            if docker_args(call["command"])[0] == "create"
        )
        for value in secrets.values():
            self.assertNotIn(value, " ".join(create))

    def test_failing_tests_block_human_approval(self) -> None:
        receipt = self.executor().execute(self.issue, str(self.source), FAILING_PATCH, "python-unittest")
        self.assertEqual(receipt["status"], "BLOCKED_TEST_FAILURE")
        self.assertFalse(receipt["tests"]["passed"])
        self.assertEqual(receipt["approval"]["nextAction"], "remediate_and_rerun")

    def test_test_execution_requires_explicit_trusted_repo_authorization(self) -> None:
        executor = WorkspaceExecutor(
            self.root / "workspaces",
            ExecutionPolicy(allow_local_repository=True, allow_test_execution=False),
        )
        with self.assertRaisesRegex(ExecutionSafetyError, "explicit authorization"):
            executor.execute(self.issue, str(self.source), VALID_PATCH, "python-unittest")

    def test_patch_may_not_escape_reviewed_issue_scope(self) -> None:
        patch = VALID_PATCH.replace("greeting.py", "tests/test_greeting.py")
        with self.assertRaisesRegex(ExecutionSafetyError, "outside the reviewed issue scope"):
            self.executor().execute(self.issue, str(self.source), patch, "python-unittest")

    def test_unsafe_patch_forms_are_rejected(self) -> None:
        unsafe_patches = (
            VALID_PATCH.replace("a/greeting.py", "a/../../greeting.py", 1),
            VALID_PATCH.replace("diff --git", "new file mode 100644\ndiff --git", 1),
            VALID_PATCH.replace("diff --git", "old mode 100644\nnew mode 100755\ndiff --git", 1),
            VALID_PATCH.replace("greeting.py", ".git/config"),
            VALID_PATCH.replace("greeting.py", ".github/workflows/pwn.yml"),
            VALID_PATCH + "GIT binary patch\n",
        )
        for patch in unsafe_patches:
            with self.subTest(patch=patch[:70]):
                with self.assertRaises(ExecutionSafetyError):
                    validate_patch(patch, ExecutionPolicy())

    def test_disallowed_repository_sources_are_rejected(self) -> None:
        policy = ExecutionPolicy()
        sources = (
            "--upload-pack=malware",
            "ext::sh -c malware",
            "git://github.com/example/repo.git",
            "https://token@github.com/example/repo.git",
            "https://github.com.evil.example/example/repo.git",
            "https://github.com:bad/example/repo.git",
            "file:///tmp/repo",
        )
        for source in sources:
            with self.subTest(source=source):
                with self.assertRaises(ExecutionSafetyError):
                    validate_repository_source(source, policy)

    def test_unknown_test_profile_is_rejected(self) -> None:
        with self.assertRaisesRegex(ExecutionSafetyError, "Unknown test profile"):
            self.executor().execute(self.issue, str(self.source), VALID_PATCH, "python -c 'malware'")

    def test_tracked_symlink_is_rejected_without_reading_target(self) -> None:
        sentinel = self.root / "outside-secret.txt"
        sentinel.write_text("do-not-read", encoding="utf-8")
        (self.source / "outside-link").symlink_to(sentinel)
        self._git("add", "outside-link")
        self._git("commit", "-m", "Add unsafe symlink")
        with self.assertRaisesRegex(ExecutionSafetyError, "symlinks, submodules"):
            self.executor().execute(self.issue, str(self.source), VALID_PATCH, "python-unittest")

    def test_receipt_is_json_serializable_without_environment_secrets(self) -> None:
        receipt = self.executor().execute(self.issue, str(self.source), VALID_PATCH, "python-unittest")
        rendered = json.dumps(receipt)
        self.assertNotIn("GITHUB_TOKEN", rendered)
        self.assertNotIn("SSH_AUTH_SOCK", rendered)

    def test_candidate_patch_writer_preserves_lf_protocol_bytes(self) -> None:
        path = self.root / "candidate.patch"
        _write_utf8_lf(path, VALID_PATCH)
        self.assertEqual(path.read_bytes(), VALID_PATCH.encode("utf-8"))
        self.assertNotIn(b"\r\n", path.read_bytes())

    def test_subprocess_output_replaces_invalid_utf8(self) -> None:
        result = _run(
            [sys.executable, "-c", "import os; os.write(1, b'\\xff')"],
            cwd=self.root,
            environment=_safe_environment(self.root),
            timeout=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "\ufffd")

    def test_cli_missing_docker_returns_machine_readable_safety_receipt(self) -> None:
        patch_path = self.root / "candidate.patch"
        patch_path.write_text(VALID_PATCH, encoding="utf-8")
        issue_path = self.root / "issue.json"
        issue_path.write_text(json.dumps(self.issue.to_dict()), encoding="utf-8")
        git_binary = shutil.which("git")
        self.assertIsNotNone(git_binary)

        output = io.StringIO()
        with patch(
            "reposteward.execution.shutil.which",
            side_effect=lambda name: git_binary if name == "git" else None,
        ), redirect_stdout(output):
            return_code = run_execute([
                str(issue_path),
                "--repository",
                str(self.source),
                "--patch",
                str(patch_path),
                "--allow-local-repository",
                "--test-isolation",
                "docker",
            ])
        receipt = json.loads(output.getvalue())
        self.assertEqual(return_code, 2)
        self.assertEqual(receipt["status"], "BLOCKED_SAFETY_POLICY")
        self.assertIn("Docker", receipt["error"])

    def test_cli_rejects_unknown_test_isolation(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            build_execute_parser().parse_args([
                "issue.json",
                "--repository",
                "https://github.com/example/repo.git",
                "--patch",
                "candidate.patch",
                "--test-isolation",
                "microvm",
            ])


if __name__ == "__main__":
    unittest.main()
