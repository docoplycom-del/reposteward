# Human approval and GitHub publication boundary

RepoSteward keeps test execution, human approval and GitHub mutation as three separate artifacts and processes.

## Eligibility

Publication fails closed unless the execution receipt records all of the following:

- planning ended at `PROCEED_TO_PATCH`;
- execution ended at `AWAITING_HUMAN_APPROVAL`;
- the source is a credential-free HTTPS GitHub repository matching the issue repository;
- the exact allowlisted `python-unittest` command passed without timeout or truncated output in Docker isolation;
- the stopped container's network, filesystem, mount, identity and resource controls were inspected;
- container removal was confirmed by the Docker daemon;
- the disposable Git workspace has no remote; and
- the execution stage still records `approved: false` and `pushCapabilityPresent: false`.

Local repository receipts are never eligible for GitHub publication. They remain useful as execution and isolation evidence only.

## Human approval artifact

`reposteward approve` runs without GitHub credentials. It requires an interactive terminal and an exact challenge containing the execution ID, repository and issue, full base commit, and full applied-diff digest. It creates a short-lived `reposteward.approval.v1` artifact that binds:

- the canonical SHA-256 of the complete execution receipt;
- repository, issue, tested base branch and exact base commit;
- candidate and applied-diff SHA-256 values;
- the ordered changed-file set;
- deterministic draft branch, title and body digests; and
- approver, approval time, expiry and a random nonce.

The artifact is authenticated with HMAC-SHA-256 using `REPOSTEWARD_APPROVAL_KEY`. The key is never written to an artifact.

The local TTY and shared-key procedure is an auditable operator gate. It is not proof against a fully compromised host or an agent that has access to the operator's terminal and approval key. A later production profile should use an external identity provider or hardware-backed signing key.

## Tested-byte revalidation

Before the GitHub token is loaded, the publisher:

- resolves the receipt workspace strictly beneath the supplied workspace root;
- acquires an exclusive publication lock;
- verifies the workspace has no Git remote;
- requires `HEAD` and the named branch to match the execution receipt;
- permits only the approved staged modifications, with no unstaged or untracked files;
- requires the full-index staged diff to equal the execution receipt byte-for-byte and by SHA-256;
- reads each approved file from the tested Git index, not from an unverified worktree path;
- verifies file modes, blob IDs, UTF-8 content and size limits; and
- captures the exact Git tree ID and repeats the workspace checks before network mutation.

## GitHub capability

`reposteward publish` reads `REPOSTEWARD_GITHUB_TOKEN` only after local validation. The fixed-host REST transport talks only to `api.github.com`, rejects oversized or invalid responses and never passes the token to Git, a subprocess argument, an artifact or an error message.

This slice requires a fine-grained user PAT because it verifies the approver through `GET /user`; GitHub App installation tokens are not supported. The token identity must match the approval's GitHub login. The target repository's numeric ID, canonical full name and default branch are checked before mutation and recorded in the publication receipt. Recommended permissions are limited to:

- Metadata: read;
- Contents: write; and
- Pull requests: write.

The transport can create content-addressed blobs, one tree, one commit, one new deterministic branch and one draft pull request. It contains no update-ref, force-push, delete, merge, close, reopen or ready-for-review operation.

The publisher verifies that GitHub's blob and tree IDs match the exact tested Git index. It checks the base branch before creating any content and again immediately before creating the publication branch. Immediately before draft creation it re-reads both the base and deterministic head refs. It then re-fetches the pull request and verifies its exact canonical URL, title, body, repository identities, head commit and base branch, and requires it to be open, unmerged and draft.

The offline approval binds the repository name and tested commit, but cannot know GitHub's numeric repository ID without adding an online identity step. Publication therefore rejects any repository whose current name, default branch or tested commit differs and records the numeric ID. An owner/name deletion-and-recreation race that preserves the exact tested commit remains a documented limitation; a production signer should bind GitHub's numeric repository ID before approval.

## Retry and partial states

The deterministic branch prevents duplicate proposals. A retry reuses only an exact branch commit and exact open draft pull request. A mismatched branch or pull request blocks publication and is never overwritten.

Machine-readable outcomes include:

- `DRAFT_PR_CREATED`;
- `DRAFT_PR_REUSED`;
- `DRAFT_PR_STALE_BASE` when the base moves after draft creation; and
- `PARTIAL_BRANCH_CREATED` when the exact branch was verified but pull-request creation was not attempted;
- `PARTIAL_UNVERIFIED_BRANCH` when branch creation was attempted but its final state could not be verified; and
- `PARTIAL_UNVERIFIED_DRAFT` when draft creation was attempted but no exact open draft could be verified.

Unreferenced Git objects may remain after an early API failure. RepoSteward never deletes or rewrites remote objects automatically. A base branch that moves before branch creation requires a fresh execution and approval.
