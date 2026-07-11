from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from time import perf_counter
from typing import Callable

from .agents import AGENTS, ManagerAgent
from .models import AgentOutput, Issue, RunReceipt


CONTRACT_VERSION = "reposteward.run.v1"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _run_id(issue: Issue) -> str:
    payload = json.dumps(issue.to_dict(), sort_keys=True).encode()
    digest = hashlib.sha256(payload).hexdigest()[:10].upper()
    return f"RS-{issue.number}-{digest}"


def run_job(issue: Issue, clock: Callable[[], str] = _utc_now) -> RunReceipt:
    manager = ManagerAgent()
    receipt = RunReceipt(
        contract_version=CONTRACT_VERSION,
        run_id=_run_id(issue),
        issue=issue,
        plan=["manager", "triager"],
    )

    def record(output: AgentOutput, started_at: str, started: float, action: str) -> AgentOutput:
        duration_ms = round((perf_counter() - started) * 1000, 3)
        receipt.outputs.append(output)
        receipt.shared_memory[output.role] = output.memory
        receipt.trace.append({
            "sequence": len(receipt.trace) + 1,
            "role": output.role,
            "action": action,
            "status": output.status,
            "startedAt": started_at,
            "completedAt": clock(),
            "durationMs": duration_ms,
            "summary": output.summary,
        })
        return output

    def execute(role: str) -> AgentOutput:
        started_at = clock()
        started = perf_counter()
        output = AGENTS[role].run(issue, receipt.shared_memory)
        return record(output, started_at, started, "specialist_execution")

    manager_started_at = clock()
    manager_started = perf_counter()
    record(manager.start(issue), manager_started_at, manager_started, "initial_plan")
    triage = execute("triager")
    manager_started_at = clock()
    manager_started = perf_counter()
    delegation = record(manager.delegate(issue, triage), manager_started_at, manager_started, "dynamic_delegation")
    delegated_roles = delegation.memory["delegatedRoles"]
    receipt.plan.extend(delegated_roles)
    for role in delegated_roles:
        execute(role)

    reviewer_memory = receipt.shared_memory["reviewer"]
    receipt.final_decision = {
        "status": reviewer_memory["decision"],
        "blockers": reviewer_memory["blockers"],
        "nextAction": "human_approval" if reviewer_memory["blockers"] else "patch_execution",
    }
    return receipt
