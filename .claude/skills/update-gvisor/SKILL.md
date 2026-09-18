---
name: update-gvisor
description: >-
  Bump gvisor.dev/gvisor using commits from upstream’s go branch only; surface
  several candidate commits with a changelog from the repo’s current version.
  Verify each candidate SHA includes regenerated Go artifacts (e.g. state
  autogen); on go, those files often land in the commit after the hand-written
  change.
trigger: When the user wants to update, bump, or refresh the gvisor dependency
user_invocable: true
---

# Update gvisor.dev/gvisor (go branch only)

## Why the `go` branch

Upstream is [google/gvisor](https://github.com/google/gvisor). **`main` and `release-*` tags are not valid targets for `go get` in this project**: they assume Bazel and omit or mismatch Go-generated artifacts, which breaks builds (see `doc/MAINTAINERS.md` and [Using go get](https://github.com/google/gvisor?tab=readme-ov-file#using-go-get)).

**Always pin to a full commit hash on the [`go`](https://github.com/google/gvisor/tree/go) branch** (e.g. `go get gvisor.dev/gvisor@<40-char-sha>`). Do not use `master`/`main` or release tags for the module version.

## Prerequisites in this repo

- Current requirement lives in `go.mod` under `gvisor.dev/gvisor` (pseudo-version like `v0.0.0-20251220000015-517913d17844`).
- Dependencies are **vendored**: after changing the module version, run `go mod vendor` (and keep `vendor/` + `go.sum` consistent).
- Validate with `go build ./...` and project tests as appropriate.

## Step 1 — Record the current revision

1. Read the `gvisor.dev/gvisor` line in `go.mod`.
2. The **pseudo-version** ends with `-<12+ hex commit prefix>` (e.g. `517913d17844`). That is the **current upstream commit** (abbreviated). Resolve to a full 40-character hash when comparing logs (e.g. `git rev-parse <prefix>` in a gvisor checkout, or use the hash GitHub shows for that commit).

Optional: `go list -m -json gvisor.dev/gvisor` confirms the resolved version in the module cache.

## Step 2 — Fetch history on the `go` branch only

Use a local clone of `https://github.com/google/gvisor` **checked out at `origin/go`** (shallow clone is fine if you deepen enough to include the current commit and newer tips).

Suggested commands:

```bash
git clone --filter=blob:none -b go https://github.com/google/gvisor.git /tmp/gvisor-go
cd /tmp/gvisor-go
git fetch origin go
CURRENT_FULL=$(git rev-parse <current-commit-prefix-from-go.mod>)
```

## Step 3 — Build several candidate commits (user choice)

Do **not** default to a single “latest” without context. Propose **at least 3 options**, for example:

| Option | Role | How to pick |
|--------|------|-------------|
| **A** | Conservative | Tip of `go` at start of task, or a commit a few days old with a clean CI story if known |
| **B** | Middle | A recent merge point or weekly-ish step between current and tip |
| **C** | Aggressive | `origin/go` **HEAD** (newest) |

For each candidate, record:

- Full **40-character** SHA (what `go get` should use).
- **Commit date** (author or committer, be consistent).
- **One-line** subject from `git log -1 --format=%s`.
- Short **rationale** (e.g. “newest on go”, “includes tcpip fix for …”, “smaller delta from current”).

### Verify each candidate is a complete module snapshot (required)

On the **`go` branch**, upstream sometimes **splits** work across commits: hand-written changes land in one commit, and **regenerated Go files** (notably `*_state_autogen.go`, `*_unsafe_state_autogen.go`, and other `*_autogen.go` outputs under `pkg/`) land in a **follow-up** commit. **Not every commit on `go` is safe to pin** with `go get @<sha>`—a SHA that updates types or serialized state without the matching autogen refresh in the **same** tree state can break consumers.

For **each** candidate SHA before presenting it:

1. **Inspect what the commit touches**:

   ```bash
   git show --pretty=format: --name-only <CANDIDATE_FULL>
   ```

2. **If the commit changes hand-written gVisor sources** (e.g. under `pkg/tcpip/`, `pkg/buffer/`, `pkg/state/`, `pkg/refs/`) **in ways that typically require codegen**, check whether **that same commit** also updates the corresponding generated files (`*state_autogen.go`, etc.). If it does not:

   - **Advance the candidate** to the **next commit on `go`** (often the immediate child) that adds the missing generated files, **or**
   - Drop that SHA and pick another anchor (e.g. a later merge point) that **does** include a consistent autogen set.

3. **If the only purpose** of a candidate was “this one-line log entry,” still **pin the full revision** that leaves the tree consistent—usually the **last** commit in a short chain that includes autogen.

When in doubt, compare with **`git log --oneline -5 <CANDIDATE_FULL>`** and walk forward until `git show --name-only` shows the expected `*_autogen.go` / `*_state_autogen.go` updates alongside (or immediately after) the functional change. **Call this out explicitly** in the candidate table when the “interesting” commit and the **pin SHA** differ (e.g. “Feature described in `abc1234`; use `def5678` for `go get`—adds state autogen.”).

## Step 4 — Changelog from the current version (required)

Between **`CURRENT_FULL`** and each candidate **`CANDIDATE_FULL`**, generate a reviewable delta:

```bash
git log --oneline --no-decorate CURRENT_FULL..CANDIDATE_FULL
```

Enhance the summary for maintainers:

1. **High-level overview** (a short paragraph): themes of changes (e.g. TCP/IP stack, buffer pooling, locking, IPv4/IPv6, gonet adapters).
2. **Notable commits**: cherry-pick 5–15 bullets from the log—prefer subjects touching `pkg/tcpip/`, `pkg/buffer/`, `pkg/sync/`, `pkg/waiter/`, `pkg/atomicbitops/`, or other paths this repo vendors (see `vendor/modules.txt` / `vendor/gvisor.dev/gvisor/`).
3. **Risk callouts**: large refactors, API renames, behavior changes in stack/endpoints, anything that might force code changes outside `vendor/`.

If the range is huge, **narrow** with path filters, e.g.:

```bash
git log --oneline CURRENT_FULL..CANDIDATE_FULL -- pkg/tcpip pkg/buffer pkg/waiter pkg/sync pkg/atomicbitops
```

Present the changelog **per candidate** (or one shared log if options are nested) so the user can choose knowingly.

## Step 5 — After the user selects a commit

1. Run:

   ```bash
   go get gvisor.dev/gvisor@<FULL_40_CHAR_SHA>
   go mod tidy
   go mod vendor
   ```

2. Build and test:

   ```bash
   make cross
   ```

   Run targeted tests if the bump touches networking behavior (project’s `test/`, CI scripts, etc.).

3. Summarize the PR/commit for humans: old pseudo-version → new, full SHA, and 2–3 bullets from the changelog.

## Anti-patterns

- Using **`main`**, **`master`**, or **`release-*` tags** as the module version for this project.
- Running **`go get gvisor.dev/gvisor@latest`** without verifying the resolved revision is on the **`go`** branch and without showing commit options plus changelog.
- Proposing **`go get` SHAs** from `go` **without checking** that the revision includes **regenerated Go files** where the branch split hand-written edits and autogen across consecutive commits.
- Vendoring updates without **`go mod tidy`** when imports or indirect deps shift.

## Reference

- Maintainer notes: `doc/MAINTAINERS.md` (“Updating the gvisor.dev/gvisor go module”).
- Upstream README: [Using go get](https://github.com/google/gvisor?tab=readme-ov-file#using-go-get).
