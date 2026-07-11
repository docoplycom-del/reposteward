from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from reposteward.execution import (
    ExecutionPolicy,
    ExecutionSafetyError,
    WorkspaceExecutor,
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


if __name__ == "__main__":
    unittest.main()
