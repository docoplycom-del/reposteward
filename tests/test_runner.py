from __future__ import annotations

import json
import unittest
from pathlib import Path

from reposteward.models import Issue
from reposteward.runner import CONTRACT_VERSION, run_job


def fixed_time() -> str:
    return "2026-07-11T10:00:00Z"


class RunnerTests(unittest.TestCase):
    def load_example(self) -> Issue:
        path = Path(__file__).parents[1] / "examples" / "issues" / "timeout.json"
        return Issue.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def test_bug_with_api_context_delegates_research_and_qa(self) -> None:
        receipt = run_job(self.load_example(), clock=fixed_time)
        self.assertEqual(receipt.plan, ["manager", "triager", "researcher", "patcher", "qa", "reviewer"])

    def test_every_handoff_survives_in_shared_memory(self) -> None:
        receipt = run_job(self.load_example(), clock=fixed_time)
        self.assertEqual(set(receipt.shared_memory), set(receipt.plan))
        self.assertEqual([event["sequence"] for event in receipt.trace], [1, 2, 3, 4, 5, 6, 7])
        self.assertEqual(receipt.trace[2]["action"], "dynamic_delegation")

    def test_bounded_medium_risk_issue_can_proceed_to_patch(self) -> None:
        receipt = run_job(self.load_example(), clock=fixed_time)
        self.assertEqual(receipt.final_decision["status"], "PROCEED_TO_PATCH")
        self.assertEqual(receipt.final_decision["nextAction"], "patch_execution")

    def test_high_risk_change_escalates_to_a_human(self) -> None:
        issue = Issue(
            repository="example/acme-api",
            number=43,
            title="Change authentication permission handling",
            body="Update the security role mapping.",
            labels=("enhancement",),
            files=("src/auth.py",),
        )
        receipt = run_job(issue, clock=fixed_time)
        self.assertEqual(receipt.final_decision["status"], "HUMAN_REVIEW_REQUIRED")
        self.assertTrue(receipt.final_decision["blockers"])

    def test_receipt_contract_and_run_id_are_stable(self) -> None:
        first = run_job(self.load_example(), clock=fixed_time)
        second = run_job(self.load_example(), clock=fixed_time)
        self.assertEqual(first.contract_version, CONTRACT_VERSION)
        self.assertEqual(first.run_id, second.run_id)


if __name__ == "__main__":
    unittest.main()
