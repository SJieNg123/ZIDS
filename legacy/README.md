# Legacy material

Current code lives in `src/zids/`, tests in `tests/`, and supported utilities in
`tools/`. Start with [RUN.md](../docs/RUN.md) and
[implementation status](../docs/IMPLEMENTATION_STATUS.md).

| Path | Retained material |
| --- | --- |
| `src/`, `tests/`, `tools/` | Retired implementation, tests and scripts |
| `configs/`, `rules/` | Retired experiment settings and rule subsets |
| `audit/` | Original protocol audit, raw evidence and reproduction scripts |
| `plans/` | Original protocol rewrite and workstation development plans |
| `benchmarks/` | Historical reports, digest indexes and measured source archives |
| `local/` | Ignored large outputs, old environments and raw experiment runs |

The old implementation is retained for inspection. Its imports, configuration
paths and audit scripts describe the original repository layout. They are not
supported commands in the current checkout. To run or inspect that layout
separately, create a worktree from the revision before cleanup:

```text
git worktree add --detach ../ZIDS-before-cleanup 69a0e63
```

Read the [original protocol audit](audit/paper_conformance_2026-10-02.md),
[protocol implementation plan](plans/EASYLIST_PROTOCOL_IMPLEMENTATION_PLAN.md)
or [workstation plan](plans/WORKSTATION_CODING_PLAN.md) for historical context.
These documents do not override the current protocol contract or status.

Audit JSON/CSV evidence, benchmark JSON/ZIP records and measured source snapshots
retain their original contents. Old package paths inside those records identify
what was measured. The current verification tool compares exact module hashes
across package renames and rejects missing or ambiguous source entries.

On the original Windows workspace, `local/artifacts/` and `local/output/`
contain the old large protocol outputs. `local/runs/` contains earlier
experiments and their checkpoints. The old environment and incomplete Python
download are under `local/python-environment/` and `local/python-downloads/`.
These files were moved without deletion and still occupy disk space.

The earlier cleanup's 34 CSV/summary files and size manifest remain in
`local/runs/repo-cleanup-20261006/`. Paths inside its manifests describe that
earlier layout. `local/` is ignored by Git and is excluded from source archives.
New experiments belong in the root `runs/` directory.

The current package layout was introduced after `e31a9b1`. Old benchmark resume
requires the matching source revision because its harness and source-path hashes
are bound to the original report. Do not rewrite report or checkpoint identities.
Policies and protocol bytes retain their formats. A direct compiler checkpoint
still requires identical compiler contents, inputs and Python patch version.
