from __future__ import annotations

import re
from typing import Any

from .models import AgentOutput, Issue


HIGH_RISK_TERMS = {"auth", "authentication", "permission", "secret", "security", "payment", "migration"}
RESEARCH_TERMS = {"api", "dependency", "docs", "documentation", "security", "authentication", "version"}
BUG_TERMS = {"bug", "crash", "error", "fail", "regression", "timeout", "broken"}


def _tokens(issue: Issue) -> set[str]:
    return set(re.findall(r"[a-z0-9_-]+", f"{issue.title} {issue.body} {' '.join(issue.labels)}".lower()))


class ManagerAgent:
    role = "manager"

    def start(self, issue: Issue) -> AgentOutput:
        return AgentOutput(
            role=self.role,
            summary=f"Opened maintenance job for {issue.repository}#{issue.number} and assigned triage.",
            memory={"initialRole": "triager", "delegatedRoles": []},
        )

    def delegate(self, issue: Issue, triage: AgentOutput) -> AgentOutput:
        tokens = _tokens(issue)
        roles: list[str] = []
        reasons: list[str] = []
        if tokens & RESEARCH_TERMS:
            roles.append("researcher")
            reasons.append("The issue depends on external API, documentation, version or security context.")
        roles.append("patcher")
        if triage.memory["issueType"] == "bug":
            roles.append("qa")
            reasons.append("Bug-class work requires an explicit regression verification plan.")
        roles.append("reviewer")
        return AgentOutput(
            role=self.role,
            summary=f"Delegated the job to {', '.join(roles)}.",
            memory={"initialRole": "triager", "delegatedRoles": roles, "delegationReasons": reasons},
        )


class TriagerAgent:
    role = "triager"

    def run(self, issue: Issue, _: dict[str, Any]) -> AgentOutput:
        tokens = _tokens(issue)
        issue_type = "bug" if tokens & BUG_TERMS else "documentation" if {"docs", "documentation"} & tokens else "enhancement"
        risk = "high" if tokens & HIGH_RISK_TERMS else "medium" if issue_type == "bug" else "low"
        acceptance = [line[2:].strip() for line in issue.body.splitlines() if line.strip().startswith("- ")]
        if not acceptance:
            acceptance = [f"Resolve issue #{issue.number}: {issue.title}", "Existing behaviour remains covered by tests"]
        return AgentOutput(
            role=self.role,
            summary=f"Classified as {issue_type} with {risk} change risk.",
            memory={"issueType": issue_type, "risk": risk, "acceptanceCriteria": acceptance},
        )


class ResearcherAgent:
    role = "researcher"

    def run(self, issue: Issue, memory: dict[str, Any]) -> AgentOutput:
        tokens = _tokens(issue)
        topics = sorted(tokens & RESEARCH_TERMS)
        questions = [f"Confirm current upstream guidance for {topic}." for topic in topics]
        return AgentOutput(
            role=self.role,
            summary=f"Prepared {len(questions)} targeted research question(s).",
            memory={"researchTopics": topics, "researchQuestions": questions, "triageRisk": memory["triager"]["risk"]},
        )


class PatcherAgent:
    role = "patcher"

    def run(self, issue: Issue, memory: dict[str, Any]) -> AgentOutput:
        files = list(issue.files)
        steps = [f"Inspect {path}" for path in files] or ["Inspect the repository tree and locate the smallest change surface"]
        steps.extend(["Implement the narrowest change satisfying the acceptance criteria", "Preserve unrelated behaviour"])
        return AgentOutput(
            role=self.role,
            summary=f"Prepared a {len(steps)}-step patch plan.",
            memory={
                "targetFiles": files,
                "patchPlan": steps,
                "acceptanceCriteria": memory["triager"]["acceptanceCriteria"],
            },
        )


class QAAgent:
    role = "qa"

    def run(self, _: Issue, memory: dict[str, Any]) -> AgentOutput:
        criteria = memory["triager"]["acceptanceCriteria"]
        checks = [f"Verify: {criterion}" for criterion in criteria]
        checks.append("Run the repository's existing automated test suite")
        return AgentOutput(
            role=self.role,
            summary=f"Defined {len(checks)} verification checks.",
            memory={"verificationChecks": checks},
        )


class ReviewerAgent:
    role = "reviewer"

    def run(self, _: Issue, memory: dict[str, Any]) -> AgentOutput:
        risk = memory["triager"]["risk"]
        target_files = memory["patcher"]["targetFiles"]
        blockers: list[str] = []
        if risk == "high":
            blockers.append("High-risk change requires human approval before patch execution.")
        if not target_files:
            blockers.append("Repository inspection is required before the patch scope can be verified.")
        decision = "HUMAN_REVIEW_REQUIRED" if blockers else "PROCEED_TO_PATCH"
        return AgentOutput(
            role=self.role,
            summary=f"Reviewer decision: {decision}.",
            memory={"decision": decision, "blockers": blockers},
        )


AGENTS = {
    "triager": TriagerAgent(),
    "researcher": ResearcherAgent(),
    "patcher": PatcherAgent(),
    "qa": QAAgent(),
    "reviewer": ReviewerAgent(),
}
