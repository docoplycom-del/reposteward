# RepoSteward

RepoSteward is an AI open-source maintenance agency that turns a GitHub issue into a planned, traceable and reviewable repository change.

The product organisation is intentionally explicit:

- a manager delegates work dynamically;
- a triager classifies the issue and risk;
- a researcher is added when external context is needed;
- a patcher prepares the implementation plan;
- a QA specialist defines verification for bugs and regressions;
- a reviewer either releases the job to implementation or escalates it to a human.

The first executable slice focuses on the orchestration contract, memory handoffs and durable run receipt. Repository checkout, patch application and pull-request publication are the next slice.

## Run the first slice

```bash
PYTHONPATH=src python -m reposteward examples/issues/timeout.json --output build/demo-run.json
```

The command prints and optionally saves a complete run receipt containing the dynamic plan, every specialist output, ordered trace events, shared memory and the final reviewer decision.

Run the tests with:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

