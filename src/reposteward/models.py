from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Issue:
    repository: str
    number: int
    title: str
    body: str
    labels: tuple[str, ...] = ()
    files: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Issue":
        required = ("repository", "number", "title", "body")
        missing = [key for key in required if value.get(key) in (None, "")]
        if missing:
            raise ValueError(f"Issue is missing required fields: {', '.join(missing)}")
        return cls(
            repository=str(value["repository"]),
            number=int(value["number"]),
            title=str(value["title"]),
            body=str(value["body"]),
            labels=tuple(str(label) for label in value.get("labels", [])),
            files=tuple(str(path) for path in value.get("files", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["labels"] = list(self.labels)
        value["files"] = list(self.files)
        return value


@dataclass(frozen=True)
class AgentOutput:
    role: str
    summary: str
    memory: dict[str, Any]
    status: str = "completed"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RunReceipt:
    contract_version: str
    run_id: str
    issue: Issue
    plan: list[str]
    outputs: list[AgentOutput] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)
    shared_memory: dict[str, Any] = field(default_factory=dict)
    final_decision: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contractVersion": self.contract_version,
            "runId": self.run_id,
            "issue": self.issue.to_dict(),
            "plan": self.plan,
            "outputs": [output.to_dict() for output in self.outputs],
            "trace": self.trace,
            "sharedMemory": self.shared_memory,
            "finalDecision": self.final_decision,
        }

