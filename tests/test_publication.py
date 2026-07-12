from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from reposteward.approval import (
    ApprovalSafetyError,
    create_approval,
    expected_confirmation,
    load_strict_json,
    verify_approval,
)
from reposteward.cli import _ArtifactReservation, run_approve, run_publish
from reposteward.execution import ExecutionPolicy, WorkspaceExecutor
from reposteward.models import Issue
from reposteward.publication import (
    GitHubTransportError,
    PreparedPublication,
    PublicationSafetyError,
    _github_error_message,
    prepare_publication,
    publish_prepared,
    snapshot_workspace,
)


VALID_PATCH = """diff --git a/greeting.py b/greeting.py
--- a/greeting.py
+++ b/greeting.py
@@ -1,2 +1,2 @@
 def greeting(name: str) -> str:
-    return f"Hello {name}"
+    return f"Hello, {name}!"
"""

APPROVAL_KEY = "approval-key-" + "x" * 32
NOW = datetime(2026, 7, 12, 12, 0, tzinfo=timezone.utc)
BASE_TREE_SHA = "d" * 40
PUBLICATION_COMMIT_SHA = "e" * 40


class FakeGitHub:
    def __init__(self, prepared: PreparedPublication, *, login: str = "octocat") -> None:
        self.prepared = prepared
        self.login = login
        self.repository_id = 123456
        self.refs: dict[str, str] = {
            prepared.intent["baseBranch"]: prepared.intent["baseCommit"],
        }
        self.commits: dict[str, dict[str, object]] = {
            prepared.intent["baseCommit"]: {
                "sha": prepared.intent["baseCommit"],
                "tree": {"sha": BASE_TREE_SHA},
                "parents": [],
                "message": "Base",
            }
        }
        self.pulls: dict[int, dict[str, object]] = {}
        self.calls: list[str] = []
        self.fail_operation: str | None = None
        self.wrong_blob = False
        self.wrong_tree = False
        self.move_base_after_pr = False
        self.fail_after_create_ref = False
        self.fail_after_create_pull: int | None = None
        self.pull_overrides: dict[str, object] = {}
        self.move_head_before_pull = False
        self.move_base_before_pull = False
        self.ref_counts: dict[str, int] = {}

    def _fail(self, operation: str) -> None:
        if self.fail_operation == operation:
            raise GitHubTransportError(operation, "simulated transport failure")

    def authenticated_login(self) -> str:
        self.calls.append("authenticated_login")
        self._fail("authenticated_login")
        return self.login

    def repository(self, repository: str) -> dict[str, object]:
        self.calls.append("repository")
        self._fail("repository")
        return {
            "id": self.repository_id,
            "full_name": self.prepared.intent["repository"],
            "default_branch": self.prepared.intent["baseBranch"],
        }

    def ref(self, repository: str, branch: str) -> str | None:
        self.calls.append(f"ref:{branch}")
        self._fail("ref")
        self.ref_counts[branch] = self.ref_counts.get(branch, 0) + 1
        if (
            self.move_head_before_pull
            and branch == self.prepared.intent["headBranch"]
            and self.ref_counts[branch] >= 3
        ):
            self.refs[branch] = "f" * 40
        if (
            self.move_base_before_pull
            and branch == self.prepared.intent["baseBranch"]
            and self.ref_counts[branch] >= 3
        ):
            self.refs[branch] = "f" * 40
        if self.move_base_after_pr and self.pulls and branch == self.prepared.intent["baseBranch"]:
            return "f" * 40
        return self.refs.get(branch)

    def git_commit(self, repository: str, sha: str) -> dict[str, object]:
        self.calls.append("git_commit")
        self._fail("git_commit")
        return self.commits[sha]

    def create_blob(self, repository: str, content: bytes) -> str:
        self.calls.append("create_blob")
        self._fail("create_blob")
        if self.wrong_blob:
            return "1" * 40
        return hashlib.sha1(f"blob {len(content)}\0".encode("ascii") + content).hexdigest()

    def create_tree(self, repository: str, base_tree: str, files: object, blob_shas: object) -> str:
        self.calls.append("create_tree")
        self._fail("create_tree")
        self.asserted_base_tree = base_tree
        return "2" * 40 if self.wrong_tree else self.prepared.workspace.tree_sha

    def create_commit(self, repository: str, message: str, tree_sha: str, parent_sha: str) -> str:
        self.calls.append("create_commit")
        self._fail("create_commit")
        self.commits[PUBLICATION_COMMIT_SHA] = {
            "sha": PUBLICATION_COMMIT_SHA,
            "tree": {"sha": tree_sha},
            "parents": [{"sha": parent_sha}],
            "message": message,
        }
        return PUBLICATION_COMMIT_SHA

    def create_ref(self, repository: str, branch: str, sha: str) -> None:
        self.calls.append("create_ref")
        self._fail("create_ref")
        if branch in self.refs:
            raise GitHubTransportError("reference creation", "already exists", 422)
        self.refs[branch] = sha
        if self.fail_after_create_ref:
            raise GitHubTransportError("reference creation", "simulated timeout after success")

    def matching_pull_requests(self, repository: str, owner: str, head_branch: str, base_branch: str) -> list[dict[str, object]]:
        self.calls.append("matching_pull_requests")
        self._fail("matching_pull_requests")
        return [
            value
            for value in self.pulls.values()
            if ((value.get("head") or {}).get("ref")) == head_branch
            and ((value.get("base") or {}).get("ref")) == base_branch
        ]

    def create_draft_pull_request(
        self,
        repository: str,
        title: str,
        body: str,
        head_branch: str,
        base_branch: str,
    ) -> dict[str, object]:
        self.calls.append("create_draft_pull_request")
        self._fail("create_draft_pull_request")
        number = 9
        value: dict[str, object] = {
            "number": number,
            "html_url": f"https://github.com/{repository}/pull/{number}",
            "state": "open",
            "draft": True,
            "merged_at": None,
            "title": title,
            "body": body,
            "head": {
                "ref": head_branch,
                "sha": self.refs[head_branch],
                "repo": {
                    "id": self.repository_id,
                    "full_name": self.prepared.intent["repository"],
                },
            },
            "base": {
                "ref": base_branch,
                "repo": {
                    "id": self.repository_id,
                    "full_name": self.prepared.intent["repository"],
                },
            },
        }
        value.update(copy.deepcopy(self.pull_overrides))
        self.pulls[number] = value
        if self.fail_after_create_pull is not None:
            raise GitHubTransportError(
                "draft pull request creation",
                "simulated ambiguous response after success",
                self.fail_after_create_pull,
            )
        return value

    def pull_request(self, repository: str, number: int) -> dict[str, object]:
        self.calls.append("pull_request")
        self._fail("pull_request")
        return self.pulls[number]


class PublicationTests(unittest.TestCase):
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
        self._git(self.source, "init", "-b", "main")
        self._git(self.source, "config", "user.name", "RepoSteward Test")
        self._git(self.source, "config", "user.email", "test@reposteward.invalid")
        self._git(self.source, "add", ".")
        self._git(self.source, "commit", "-m", "Create fixture")
        issue = Issue(
            repository="octocat/demo",
            number=7,
            title="Greeting omits punctuation",
            body="Return a punctuated greeting.",
            labels=("bug",),
            files=("greeting.py",),
        )
        self.workspace_root = self.root / "workspaces"
        receipt = WorkspaceExecutor(
            self.workspace_root,
            ExecutionPolicy(allow_local_repository=True, allow_test_execution=True),
        ).execute(issue, str(self.source), VALID_PATCH, "python-unittest")
        receipt["source"] = {
            "type": "https_git_repository",
            "reference": "https://github.com/octocat/demo.git",
        }
        receipt["tests"]["isolation_level"] = "docker"
        receipt["tests"]["command"] = [
            "python",
            "-E",
            "-s",
            "-B",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-v",
        ]
        receipt["tests"]["isolation_details"] = {
            "containerConfigurationInspected": True,
            "engine": "docker",
            "engineOs": "linux",
            "engineEndpointType": "npipe",
            "imageReference": "python:3.11.15-slim-bookworm",
            "imageId": "sha256:" + "a" * 64,
            "imageRepoDigests": ["python@sha256:" + "b" * 64],
            "imageOs": "linux",
            "imageArchitecture": "amd64",
            "imagePullPolicy": "never",
            "network": "none",
            "rootFilesystem": "read_only",
            "repositoryMount": "read_only",
            "hostCredentialsMounted": False,
            "dockerSocketMounted": False,
            "user": "65534:65534",
            "capabilitiesDropped": ["ALL"],
            "noNewPrivileges": True,
            "seccompProfile": "daemon_default",
            "oomKilled": False,
            "resourceLimits": {
                "cpus": "1.0",
                "memory": "512m",
                "memorySwap": "512m",
                "pids": 64,
                "openFiles": 256,
                "tmpfs": "64m",
                "retainedLogs": "64k",
            },
            "cleanup": {"removed": True, "verifiedByDaemon": True},
        }
        receipt["safetyBoundary"] = {
            "testIsolation": "docker",
            "networkIsolation": True,
            "repositoryReadOnly": True,
            "rootFilesystemReadOnly": True,
            "hostCredentialsMounted": False,
            "dockerSocketMounted": False,
            "sharedKernelContainerBoundary": True,
            "trustedDisposableRepositoryRequired": False,
        }
        receipt["planningRunId"] = "RS-7-TEST"
        receipt["planningDecision"] = {"status": "PROCEED_TO_PATCH"}
        self.execution = receipt
        self.approval = create_approval(
            receipt,
            approver="octocat",
            confirmation=expected_confirmation(receipt),
            key=APPROVAL_KEY,
            now=NOW,
            nonce="a" * 32,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _git(repository: Path, *arguments: str) -> str:
        return subprocess.run(
            ["git", *arguments],
            cwd=repository,
            capture_output=True,
            text=True,
            check=True,
        ).stdout

    def prepare(self, execution: dict[str, object] | None = None, approval: dict[str, object] | None = None) -> PreparedPublication:
        return prepare_publication(
            execution or self.execution,
            approval or self.approval,
            approval_key=APPROVAL_KEY,
            workspace_root=self.workspace_root,
            now=NOW + timedelta(minutes=1),
        )

    def publish(
        self,
        prepared: PreparedPublication,
        github: FakeGitHub,
        *,
        at: datetime | None = None,
    ) -> dict[str, object]:
        return publish_prepared(
            prepared,
            github,
            clock=lambda: at or NOW + timedelta(minutes=1),
        )

    def test_approval_is_bound_and_tampering_is_rejected(self) -> None:
        verified = verify_approval(
            self.execution,
            self.approval,
            key=APPROVAL_KEY,
            now=NOW + timedelta(minutes=1),
        )
        self.assertEqual(verified["approvedBy"], "octocat")

        tampered_execution = copy.deepcopy(self.execution)
        tampered_execution["patch"]["candidateSha256"] = "0" * 64
        with self.assertRaises(ApprovalSafetyError):
            verify_approval(tampered_execution, self.approval, key=APPROVAL_KEY, now=NOW + timedelta(minutes=1))

        tampered_approval = copy.deepcopy(self.approval)
        tampered_approval["approvedBy"] = "attacker"
        with self.assertRaisesRegex(ApprovalSafetyError, "signature"):
            verify_approval(self.execution, tampered_approval, key=APPROVAL_KEY, now=NOW + timedelta(minutes=1))

    def test_approval_expiry_and_confirmation_are_fail_closed(self) -> None:
        with self.assertRaisesRegex(ApprovalSafetyError, "confirmation"):
            create_approval(
                self.execution,
                approver="octocat",
                confirmation="APPROVE something else",
                key=APPROVAL_KEY,
                now=NOW,
            )
        with self.assertRaisesRegex(ApprovalSafetyError, "currently valid"):
            verify_approval(
                self.execution,
                self.approval,
                key=APPROVAL_KEY,
                now=NOW + timedelta(minutes=16),
            )

    def test_strict_json_rejects_duplicate_keys_and_non_finite_numbers(self) -> None:
        with self.assertRaisesRegex(ApprovalSafetyError, "Duplicate JSON key"):
            load_strict_json('{"status":"one","status":"two"}')
        with self.assertRaisesRegex(ApprovalSafetyError, "Non-finite"):
            load_strict_json('{"value":NaN}')

    def test_ineligible_execution_receipts_are_rejected(self) -> None:
        mutations = (
            ("local source", lambda value: value.__setitem__("source", {"type": "local_disposable_repository", "reference": "local"})),
            ("process tests", lambda value: value["tests"].__setitem__("isolation_level", "process_only")),
            ("wrong test profile", lambda value: value["tests"].__setitem__("profile", "custom")),
            ("wrong test command", lambda value: value["tests"].__setitem__("command", ["python", "tests.py"])),
            ("truncated tests", lambda value: value["tests"].__setitem__("stdout_truncated", True)),
            ("unclean container", lambda value: value["tests"]["isolation_details"]["cleanup"].__setitem__("removed", False)),
            ("push capability", lambda value: value["approval"].__setitem__("pushCapabilityPresent", True)),
            ("repository mismatch", lambda value: value["issue"].__setitem__("repository", "someone/else")),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                value = copy.deepcopy(self.execution)
                mutate(value)
                with self.assertRaises(ApprovalSafetyError):
                    create_approval(
                        value,
                        approver="octocat",
                        confirmation="irrelevant",
                        key=APPROVAL_KEY,
                        now=NOW,
                    )

    def test_cli_approval_refuses_non_interactive_input(self) -> None:
        receipt_path = self.root / "execution.json"
        receipt_path.write_text(json.dumps(self.execution), encoding="utf-8")
        output = StringIO()
        with patch.dict(os.environ, {"REPOSTEWARD_APPROVAL_KEY": APPROVAL_KEY}), patch.object(
            sys.stdin, "isatty", return_value=False
        ), redirect_stdout(output):
            code = run_approve([
                str(receipt_path),
                "--workspace-root",
                str(self.workspace_root),
                "--approver",
                "octocat",
                "--output",
                str(self.root / "approval.json"),
            ])
        self.assertEqual(code, 2)
        self.assertIn("BLOCKED_APPROVAL_POLICY", output.getvalue())

    def test_workspace_revalidation_detects_tampering_and_root_escape(self) -> None:
        snapshot = snapshot_workspace(self.execution, workspace_root=self.workspace_root)
        self.assertEqual(snapshot.applied_diff_sha256, self.execution["patch"]["appliedDiffSha256"])
        with self.assertRaisesRegex(PublicationSafetyError, "Workspace root"):
            snapshot_workspace(self.execution, workspace_root=self.root / "elsewhere")

        workspace = Path(self.execution["workspace"]["path"])
        (workspace / "greeting.py").write_text("tampered\n", encoding="utf-8")
        with self.assertRaises(PublicationSafetyError):
            snapshot_workspace(self.execution, workspace_root=self.workspace_root)

    def test_happy_path_creates_only_a_draft_pr(self) -> None:
        prepared = self.prepare()
        github = FakeGitHub(prepared)
        receipt = self.publish(prepared, github)
        self.assertEqual(receipt["status"], "DRAFT_PR_CREATED")
        self.assertTrue(receipt["pullRequest"]["draft"])
        self.assertEqual(receipt["pullRequest"]["number"], 9)
        self.assertEqual(github.refs[prepared.intent["baseBranch"]], prepared.intent["baseCommit"])
        self.assertEqual(github.refs[prepared.intent["headBranch"]], PUBLICATION_COMMIT_SHA)
        self.assertFalse(receipt["controls"]["mergeOperationExposed"])
        self.assertFalse(receipt["controls"]["forceUpdateOperationExposed"])
        self.assertFalse(receipt["controls"]["tokenIncludedInReceipt"])
        self.assertIn("create_draft_pull_request", github.calls)

    def test_base_drift_and_token_identity_mismatch_block_before_mutation(self) -> None:
        prepared = self.prepare()
        github = FakeGitHub(prepared)
        github.refs[prepared.intent["baseBranch"]] = "f" * 40
        with self.assertRaisesRegex(PublicationSafetyError, "base branch moved"):
            self.publish(prepared, github)
        self.assertNotIn("create_blob", github.calls)

        github = FakeGitHub(prepared, login="someone-else")
        with self.assertRaisesRegex(PublicationSafetyError, "identity"):
            self.publish(prepared, github)
        self.assertNotIn("create_blob", github.calls)

    def test_remote_blob_and_tree_mismatches_are_rejected(self) -> None:
        prepared = self.prepare()
        github = FakeGitHub(prepared)
        github.wrong_blob = True
        with self.assertRaisesRegex(PublicationSafetyError, "blob SHA"):
            self.publish(prepared, github)
        self.assertNotIn("create_ref", github.calls)

        github = FakeGitHub(prepared)
        github.wrong_tree = True
        with self.assertRaisesRegex(PublicationSafetyError, "tree SHA"):
            self.publish(prepared, github)
        self.assertNotIn("create_ref", github.calls)

    def test_exact_existing_draft_is_reused_and_conflict_is_blocked(self) -> None:
        prepared = self.prepare()
        github = FakeGitHub(prepared)
        first = self.publish(prepared, github)
        second = self.publish(prepared, github)
        self.assertEqual(first["status"], "DRAFT_PR_CREATED")
        self.assertEqual(second["status"], "DRAFT_PR_REUSED")
        self.assertEqual(second["pullRequest"]["number"], first["pullRequest"]["number"])

        github = FakeGitHub(prepared)
        github.refs[prepared.intent["headBranch"]] = "1" * 40
        github.commits["1" * 40] = {
            "tree": {"sha": "2" * 40},
            "parents": [{"sha": prepared.intent["baseCommit"]}],
            "message": "different",
        }
        with self.assertRaisesRegex(PublicationSafetyError, "different content"):
            self.publish(prepared, github)

    def test_pr_failure_returns_an_auditable_partial_receipt(self) -> None:
        prepared = self.prepare()
        github = FakeGitHub(prepared)
        github.fail_operation = "create_draft_pull_request"
        receipt = self.publish(prepared, github)
        self.assertEqual(receipt["status"], "PARTIAL_UNVERIFIED_DRAFT")
        self.assertEqual(receipt["repository"]["publicationCommit"], PUBLICATION_COMMIT_SHA)
        self.assertIsNone(receipt["pullRequest"])

    def test_fresh_approval_recovers_the_same_partial_branch(self) -> None:
        prepared = self.prepare()
        github = FakeGitHub(prepared)
        github.fail_operation = "create_draft_pull_request"
        partial = self.publish(prepared, github)
        self.assertEqual(partial["status"], "PARTIAL_UNVERIFIED_DRAFT")

        fresh_approval = create_approval(
            self.execution,
            approver="octocat",
            confirmation=expected_confirmation(self.execution),
            key=APPROVAL_KEY,
            now=NOW + timedelta(minutes=16),
            nonce="c" * 32,
        )
        fresh = prepare_publication(
            self.execution,
            fresh_approval,
            approval_key=APPROVAL_KEY,
            workspace_root=self.workspace_root,
            now=NOW + timedelta(minutes=17),
        )
        self.assertEqual(fresh.publication_id, prepared.publication_id)
        github.fail_operation = None
        recovered = self.publish(fresh, github, at=NOW + timedelta(minutes=17))
        self.assertEqual(recovered["status"], "DRAFT_PR_CREATED")
        self.assertEqual(recovered["approvalId"], fresh_approval["approvalId"])
        self.assertEqual(recovered["repository"]["publicationCommit"], PUBLICATION_COMMIT_SHA)

    def test_base_move_after_draft_is_reported(self) -> None:
        prepared = self.prepare()
        github = FakeGitHub(prepared)
        github.move_base_after_pr = True
        receipt = self.publish(prepared, github)
        self.assertEqual(receipt["status"], "DRAFT_PR_STALE_BASE")
        self.assertTrue(receipt["pullRequest"]["draft"])

    def test_success_then_timeout_is_reconciled_for_branch_and_pull_request(self) -> None:
        prepared = self.prepare()
        github = FakeGitHub(prepared)
        github.fail_after_create_ref = True
        github.fail_after_create_pull = 422
        receipt = self.publish(prepared, github)
        self.assertEqual(receipt["status"], "DRAFT_PR_CREATED")
        self.assertEqual(receipt["pullRequest"]["number"], 9)
        self.assertEqual(github.refs[prepared.intent["headBranch"]], PUBLICATION_COMMIT_SHA)

    def test_approval_expiry_after_branch_creation_stops_before_pull_request(self) -> None:
        prepared = self.prepare()
        github = FakeGitHub(prepared)
        moments = iter(
            (
                NOW + timedelta(minutes=1),
                NOW + timedelta(minutes=1),
                NOW + timedelta(minutes=14, seconds=45),
            )
        )
        receipt = publish_prepared(prepared, github, clock=lambda: next(moments))
        self.assertEqual(receipt["status"], "PARTIAL_BRANCH_CREATED")
        self.assertIsNone(receipt["pullRequest"])
        self.assertNotIn("create_draft_pull_request", github.calls)

    def test_head_and_base_are_rechecked_immediately_before_draft_creation(self) -> None:
        prepared = self.prepare()
        github = FakeGitHub(prepared)
        github.move_head_before_pull = True
        receipt = self.publish(prepared, github)
        self.assertEqual(receipt["status"], "PARTIAL_UNVERIFIED_BRANCH")
        self.assertNotIn("create_draft_pull_request", github.calls)

        prepared = self.prepare()
        github = FakeGitHub(prepared)
        github.move_base_before_pull = True
        receipt = self.publish(prepared, github)
        self.assertEqual(receipt["status"], "PARTIAL_BRANCH_CREATED")
        self.assertNotIn("create_draft_pull_request", github.calls)

    def test_created_pull_request_must_match_every_postcondition(self) -> None:
        mutations = (
            ("title", {"title": "altered"}),
            ("body", {"body": "altered"}),
            ("draft", {"draft": False}),
            ("state", {"state": "closed"}),
            ("merged", {"merged_at": "2026-07-12T12:00:00Z"}),
            ("head repository", {"head": {"ref": "wrong", "sha": "f" * 40, "repo": {"id": 999, "full_name": "other/repo"}}}),
        )
        for label, overrides in mutations:
            with self.subTest(label=label):
                prepared = self.prepare()
                github = FakeGitHub(prepared)
                github.pull_overrides = overrides
                receipt = self.publish(prepared, github)
                self.assertEqual(receipt["status"], "PARTIAL_UNVERIFIED_DRAFT")
                self.assertFalse((receipt.get("pullRequest") or {}).get("verified", False))

    def test_multiple_existing_pull_requests_fail_closed(self) -> None:
        prepared = self.prepare()
        github = FakeGitHub(prepared)
        self.publish(prepared, github)
        github.pulls[10] = copy.deepcopy(github.pulls[9])
        github.pulls[10]["number"] = 10
        github.pulls[10]["html_url"] = f"https://github.com/{prepared.intent['repository']}/pull/10"
        with self.assertRaisesRegex(PublicationSafetyError, "Multiple pull requests"):
            self.publish(prepared, github)

    def test_github_error_message_redacts_the_token(self) -> None:
        token = "github_pat_secret-value"
        raw = json.dumps({"message": f"Rejected Bearer {token}; token={token}"}).encode("utf-8")
        rendered = _github_error_message(raw, token)
        self.assertNotIn(token, rendered)
        self.assertIn("[REDACTED]", rendered)

    def test_publication_output_collision_blocks_before_transport_creation(self) -> None:
        receipt_path = self.root / "execution.json"
        approval_path = self.root / "approval.json"
        output_path = self.root / "publication.json"
        receipt_path.write_text("{}", encoding="utf-8")
        approval_path.write_text("{}", encoding="utf-8")
        output_path.write_text("preserve me\n", encoding="utf-8")
        output = StringIO()
        with patch("reposteward.cli.prepare_publication", return_value=self.prepare()), patch(
            "reposteward.cli.GitHubRestTransport"
        ) as transport, redirect_stdout(output):
            code = run_publish(
                [
                    "--receipt",
                    str(receipt_path),
                    "--approval",
                    str(approval_path),
                    "--workspace-root",
                    str(self.workspace_root),
                    "--output",
                    str(output_path),
                ]
            )
        self.assertEqual(code, 2)
        transport.assert_not_called()
        self.assertEqual(output_path.read_text(encoding="utf-8"), "preserve me\n")

    def test_reserved_audit_sentinel_survives_atomic_replacement_failure(self) -> None:
        output_path = self.root / "publication.json"
        reservation = _ArtifactReservation(
            output_path,
            publication_id="RSP-" + "A" * 24,
            execution_id="RSX-7-AAAAAAAAAA",
        )
        with patch("reposteward.cli.os.replace", side_effect=OSError("simulated failure")), self.assertRaisesRegex(
            PublicationSafetyError,
            "existing audit artifact",
        ):
            reservation.write({"status": "DRAFT_PR_CREATED"})
        retained = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(retained["status"], "PUBLICATION_IN_PROGRESS")

    def test_cli_reports_remote_outcome_when_final_audit_replace_fails(self) -> None:
        receipt_path = self.root / "execution.json"
        approval_path = self.root / "approval.json"
        output_path = self.root / "publication.json"
        receipt_path.write_text("{}", encoding="utf-8")
        approval_path.write_text("{}", encoding="utf-8")
        prepared = self.prepare()
        outcome = {
            "contractVersion": "reposteward.publication.v1",
            "publicationId": prepared.publication_id,
            "status": "DRAFT_PR_CREATED",
        }
        error_output = StringIO()
        with patch("reposteward.cli.prepare_publication", return_value=prepared), patch(
            "reposteward.cli.GitHubRestTransport",
            return_value=object(),
        ), patch("reposteward.cli.publish_prepared", return_value=outcome), patch(
            "reposteward.cli.os.replace",
            side_effect=OSError("simulated failure"),
        ), redirect_stderr(error_output):
            code = run_publish(
                [
                    "--receipt",
                    str(receipt_path),
                    "--approval",
                    str(approval_path),
                    "--workspace-root",
                    str(self.workspace_root),
                    "--output",
                    str(output_path),
                ]
            )
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(output_path.read_text(encoding="utf-8"))["status"], "PUBLICATION_IN_PROGRESS")
        critical = json.loads(error_output.getvalue())
        self.assertEqual(critical["status"], "CRITICAL_AUDIT_WRITE_FAILED")
        self.assertEqual(critical["publicationOutcome"]["status"], "DRAFT_PR_CREATED")


if __name__ == "__main__":
    unittest.main()
