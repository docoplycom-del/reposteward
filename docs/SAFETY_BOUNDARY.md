# Safe execution boundary

RepoSteward offers two explicit test-execution boundaries. Process mode is for a controlled disposable fixture. Docker mode is the first isolated profile for repository-controlled tests.

## Enforced before either test mode

- HTTPS repositories are restricted to configured hosts; local repositories require explicit authorization.
- Git receives validated argv values with no shell interpolation, no interactive credential prompt and no user or system Git configuration.
- The clone is disposable, shallow for remote repositories and created beneath a dedicated workspace root.
- Tracked symlinks, submodules, special entries, case-fold collisions and excessive repository sizes are rejected.
- Patches are limited to UTF-8 modifications of existing regular files named in the reviewed issue.
- Binary changes, adds, deletes, renames, mode changes, `.git`, `.gitmodules` and GitHub workflow changes are rejected.
- The repository must be clean before application and contain exactly the declared changes afterwards.
- Tests are selected by an immutable policy ID; neither mode accepts a shell command from the issue or caller.
- `origin` is removed before patch execution. The executor contains no commit, tag, push or pull-request publication operation.
- RepoSteward rechecks `HEAD`, Git status and the applied-diff SHA-256 after tests.
- Every successful test run still ends at `AWAITING_HUMAN_APPROVAL`.

## Trusted process mode

Process mode uses an argv list, sanitized environment, retained-output limit and process-tree timeout. It requires the explicit `--allow-trusted-test-execution` flag.

This mode is not a security sandbox. Repository code can still read host-accessible files, create child processes and reach the network. Use it only with a controlled disposable fixture.

## Docker mode

Docker mode is selected with `--test-isolation docker`. The engine and image must already be present, and the engine must be running Linux containers.

The executor:

- disables runtime image pulls and resolves the configured local tag to a validated immutable image ID;
- resolves one explicit Docker context and rejects TCP, SSH and other non-local engine endpoints;
- requires a `linux/amd64` image with no declared writable volumes;
- creates a stopped container, inspects its effective configuration, and starts it only if every expected control is present;
- uses `--network none`, a read-only root filesystem and one read-only bind mount at `/workspace`;
- runs as numeric user `65534:65534`, drops all capabilities, enables no-new-privileges and requires the daemon's seccomp profile;
- publishes no ports and mounts no devices, credentials, host home or Docker socket;
- provides a 64 MB no-exec `/tmp` tmpfs as declared scratch space;
- limits the container to one CPU, 512 MB memory and swap, 64 processes and 256 open files;
- disables image health checks and restarts;
- retains at most one uncompressed 64 KB local Docker log file before collecting bounded output tails;
- removes the named container after create failures, kills it on test timeout and requires daemon-confirmed removal before returning a receipt; and
- records the resolved image ID, effective-control attestation, resource limits and hashed container/workspace identifiers in the receipt.

No dependency installation occurs inside this profile. The current allowlisted command is Python standard-library `unittest`; missing third-party dependencies are ordinary test failures.

## Remaining limitations

Docker containers share the Linux kernel boundary and are not equivalent to a microVM. A Docker Engine or kernel escape is outside this slice's threat model.

The default image reference is an administrator-pulled tag. RepoSteward closes the inspect/start race by executing the resolved local image ID and recording it, but the acquisition step is not yet signature-, SBOM- or vulnerability-policy verified. A production profile should use a RepoSteward-owned image pinned by manifest digest and verified in CI.

Bind mounts are resolved by the Docker daemon host. Docker Desktop users must share the workspace drive and use Linux-container mode. Paths containing commas are rejected because Docker's `--mount` grammar uses commas as field separators.

The current profile targets `linux/amd64`, has no package-install phase, and does not claim microVM-grade tenant isolation. Those are deliberate constraints, not silent fallbacks.
