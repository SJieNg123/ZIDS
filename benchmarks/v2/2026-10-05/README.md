# Workstation preparation measurements

`readiness-report.json` contains six fresh private evaluations from the detached
synthetic/small benchmark on Windows Python 3.12.0. Its per-process metrics,
contexts, source/harness hashes and reference identity are retained. Session
identifiers are public metadata. No private policy, garbling keys, OT seeds or
checkpoint files are included. `readiness-sources.zip` retains the exact measured
implementation and harness. The final harness additionally makes source/case
publication atomic, without changing the measured protocol modules.

`readiness-equivalence.json` verifies canonical language digests and protocol
module hashes against that run. `generated-coverage.json` records independent
ABP labels for generated candidates. Only the 200-rule cases were also compared
with a compiled DFA in the suite. Full-snapshot DFA compilation remains pending.
`validation.json` binds the final test results to source hashes. `sha256.json`
binds the reports and source archive.

The complete Windows test suite passed 63 tests in 96.398 s. Commands and evidence
limits are in [WORKSTATION.md](../../../docs/WORKSTATION.md) and
[BENCHMARK_V2.md](../../../docs/BENCHMARK_V2.md).
