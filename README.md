# RepoSteward

RepoSteward is an AI open-source maintenance agency that turns a GitHub issue into a planned, traceable and reviewable repository change.

The product organisation is intentionally explicit:

- a manager delegates work dynamically;
- a triager classifies the issue and risk;
- a researcher is added when external context is needed;
- a patcher prepares the implementation plan;
- a QA specialist defines verification for bugs and regressions;
- a reviewer either releases the job to implementation or escalates it to a human.

The first executable slice focuses on the orchestration contract, memory handoffs and durable run receipt. The second slice adds constrained patch execution in a trusted disposable Git repository. The third adds an opt-in Docker boundary for running the allowlisted Python test profile without host credentials or network access. Pull-request publication is intentionally not present yet.

## Run the first slice

```bash
PYTHONPATH=src python -m reposteward examples/issues/timeout.json --output build/demo-run.json
```

The command prints and optionally saves a complete run receipt containing the dynamic plan, every specialist output, ordered trace events, shared memory and the final reviewer decision.

Run the tests with:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Run the trusted process demo

First create the disposable Git fixture:

```bash
python scripts/prepare_demo_repository.py build/demo-target
```

Then let RepoSteward clone it, apply the reviewed patch, run the allowlisted test profile and emit an execution receipt:

```bash
PYTHONPATH=src python -m reposteward execute examples/issues/greeting.json \
  --repository build/demo-target \
  --patch examples/patches/fix-greeting.patch \
  --allow-local-repository \
  --allow-trusted-test-execution \
  --output build/demo-execution.json
```

A successful run ends at `AWAITING_HUMAN_APPROVAL`. RepoSteward removes the cloned repository's `origin`, does not commit, has no push capability and does not open a pull request.

Process mode is not OS- or network-sandboxed and must be used only with controlled disposable repositories.

## Run tests in Docker isolation

Install Docker Desktop, select Linux containers, and explicitly acquire the allowlisted image before execution:

```bash
docker pull --platform linux/amd64 python:3.11.15-slim-bookworm
```

Prepare the same disposable fixture, then select Docker isolation. This mode does not require `--allow-trusted-test-execution`:

```bash
python scripts/prepare_demo_repository.py build/demo-target

PYTHONPATH=src python -m reposteward execute examples/issues/greeting.json \
  --repository build/demo-target \
  --patch examples/patches/fix-greeting.patch \
  --allow-local-repository \
  --test-isolation docker \
  --output build/demo-docker-execution.json
```

RepoSteward resolves the currently selected Docker context and accepts only a local `npipe://` or `unix://` engine endpoint. It refuses runtime image pulls, resolves the pre-pulled image to its immutable local image ID, creates the container without starting it, and inspects the effective configuration. Tests start only after verifying no external network, a read-only root filesystem and repository mount, a non-root user, dropped capabilities, no-new-privileges, bounded CPU/memory/processes/logs and a bounded `/tmp` tmpfs. The container must be removed successfully before approval can proceed.

The Docker profile intentionally supports only standard-library `unittest` projects with dependencies already present in the image. Docker is a shared-kernel boundary, not a microVM. See [`docs/SAFETY_BOUNDARY.md`](docs/SAFETY_BOUNDARY.md) for the enforced controls and remaining limitations.
