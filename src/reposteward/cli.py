from __future__ import annotations

import argparse
import json
from pathlib import Path

from .models import Issue
from .runner import run_job


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a RepoSteward maintenance job")
    parser.add_argument("issue", type=Path, help="Path to a GitHub issue JSON fixture")
    parser.add_argument("--output", type=Path, help="Optional path for the durable run receipt")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    issue = Issue.from_dict(json.loads(args.issue.read_text(encoding="utf-8")))
    receipt = run_job(issue).to_dict()
    rendered = json.dumps(receipt, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{rendered}\n", encoding="utf-8")
    print(rendered)
    return 0

