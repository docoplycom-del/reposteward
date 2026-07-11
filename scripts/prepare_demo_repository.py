from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a disposable Git repository for the RepoSteward execution demo")
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    destination = args.destination.resolve()
    source = Path(__file__).parents[1] / "examples" / "demo_repository"
    if destination.exists():
        raise SystemExit(f"Destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination)
    commands = (
        ("git", "init", "-b", "main"),
        ("git", "config", "user.name", "RepoSteward Demo"),
        ("git", "config", "user.email", "demo@reposteward.invalid"),
        ("git", "add", "."),
        ("git", "commit", "-m", "Create failing greeting fixture"),
    )
    for command in commands:
        subprocess.run(command, cwd=destination, check=True, capture_output=True, text=True, shell=False)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

