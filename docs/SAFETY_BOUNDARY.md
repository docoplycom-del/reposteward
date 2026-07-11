# Safe execution boundary

RepoSteward's second slice is a constrained local executor, not a security sandbox.

## Enforced in this slice

- HTTPS repositories are restricted to configured hosts; local repositories require explicit authorization.
- Git receives validated argv values with no shell interpolation, no interactive credential prompt and no user or system Git configuration.
- The clone is disposable, shallow for remote repositories and created beneath a dedicated workspace root.
- Tracked symlinks, submodules, special entries, case-fold collisions and excessive repository sizes are rejected.
- Patches are limited to UTF-8 modifications of existing regular files named in the reviewed issue.
- Binary changes, adds, deletes, renames, mode changes, `.git`, `.gitmodules` and GitHub workflow changes are rejected.
- The repository must be clean before application and contain exactly the declared changes afterwards.
- Tests are selected by an immutable policy ID and run with an argv list, a sanitized environment, output limits and a timeout.
- `origin` is removed before patch execution. The executor contains no commit, tag, push or pull-request publication operation.
- Every successful test run still ends at `AWAITING_HUMAN_APPROVAL`.

## Not enforced yet

Allowlisted commands prevent shell injection, but test code still comes from the repository and patch. Process isolation alone does not prevent that code from reading host-accessible files, creating child processes or reaching the network.

Before RepoSteward executes changes from untrusted public repositories, add an ephemeral container or microVM with:

- no host credentials or mounted user directories;
- outbound network disabled by default;
- read-only base filesystem plus a bounded writable workspace;
- CPU, memory, process and wall-clock limits;
- process-tree termination and output quotas;
- an independently verified toolchain image.

Until then, use execution only with a controlled disposable fixture and the explicit `--allow-trusted-test-execution` flag.

