# Historical material

The current implementation and commands are documented in
[RUN_V2.md](../RUN_V2.md) and [IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md).
This directory retains the rationale and evidence behind the rewrite:

- [Original protocol audit](audit/paper_conformance_2026-10-02.md) and its raw evidence
- [Protocol and EasyList implementation plan](EASYLIST_PROTOCOL_IMPLEMENTATION_PLAN.md)
- [Workstation preparation plan](WORKSTATION_CODING_PLAN.md)

These documents describe earlier snapshots. Legacy paths and commit identifiers
inside them are historical references. Their proposed features and old validation
results do not override the current protocol contract or implementation status.
The archived audit's JSON and CSV evidence is retained without modification.

The 2026-10-06 cleanup removed unused legacy clients, servers, crypto modules,
tests, configurations, generators, benchmark tools and rule subsets from the
active tree. Only `rules/easylist.txt` and `rules/small.abp` remain as benchmark
inputs. The self-contained 200-rule fixtures remain under `tests_v2/fixtures/`.
The older `easylist copy.txt` was an unused separate snapshot, not an identical
copy of the supported snapshot.

The last revision before cleanup is `69a0e63`. To inspect the original paths or
audit reproduction scripts without changing this checkout, run in PowerShell or Bash:

```text
git show 69a0e63:audit/reproduce_findings.py
git worktree add --detach ../ZIDS-before-cleanup 69a0e63
```

That checkout recovers tracked source and data. Large local artifacts were not
tracked at that revision. On the original Windows workspace, retired source,
environments and output directories are preserved under ignored
`v2-runs/repo-cleanup-20261006/retired/`. Moving those files did not reclaim disk
space. Its sibling `legacy-benchmark-results.zip` separately preserves 34 CSV and
summary files, and `manifest.json` records the archive digest and artifact sizes.
These local archives are not included in Git clones or the Ubuntu source bundle.

Current v2 experiment directories, checkpoints and the committed reports in
`benchmarks/v2/` were retained. Measured source archives in that directory remain
useful for interpreting old measurements and are not runtime dependencies.
