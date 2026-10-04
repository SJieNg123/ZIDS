# Implementation status

Planning commit: `47e4cf2`. User authorized automatic commits after each validated step and continuation through steps 1–12. No push requested.

Latest scope: base OT only. No OT extension or OT-specific preprocessing optimizations. Browser execution excluded.

2026-10-05 execution update: the user requested running DFA compilation until
completion or hardware/resource failure. Compiler state/time limits and the
outer benchmark compile-worker timeout are now disabled by default. Optional
explicit limits remain available to reproduce the historical measurements below.
Unlimited runs record phase and state counts and detect worker death without a
deadline. Removing limits alone does not complete full-scale acceptance.
Validation passed all 46 tests in 34.760 s on Windows Python 3.12. New regressions
cross the former default NFA/DFA limits, simulate an elapsed deadline, and verify
progress, allocation-error reporting and hard worker-exit handling.

| Step | Status | Evidence |
| --- | --- | --- |
| 1 | Complete | Windows Python 3.12.0 / PyNaCl 1.6.2 native group smoke passed, pip check passed, NP Protocols 3.1 and 2.1 inspected. Linux runtime verification remains for platform CI |
| 2 | Complete | `python -B -m unittest tests_v2.test_wire -v`, 4 tests passed in 0.111 s, including two spawned processes and malformed/replayed frames |
| 3 | Complete | NP Protocol 3.1 base OT over native Edwards25519. Base OT + wire suites: 8 tests in 0.226 s, two processes, invalid points, equal-key branch separation and replay |
| 4 | Complete | All 256 choices with fresh real base OT, four-ciphertext XOR regression, malformed tables and cross-session/replay tests passed in 4.455 s |
| 5 | Complete | Two-process whole/split batches agree, wire byte counters agree, 8n base transfers measured, extension names rejected. 2 tests in 0.559 s |
| 6 | Complete | Exhaustive short-word grouping/search checks, six state-index widths, tail/alignment/resource/permutation cases. 3 tests in 0.002 s |
| 7 | Complete | Sparse position matrix, fresh keys/permutations/pad chains and final-only evaluation. Exhaustive ideal-selection tests plus real OT in two processes, 3 tests in 0.931 s |
| 8 | Complete | Streaming public matrix/private bundles, canonical manifests, mmap evaluation and hashes. Roundtrip, tampering and bounded-memory checks passed, 3 tests in 0.381 s |
| 9 | Complete | Pinned independent ABP oracle, typed parser, fixed PSL/context codec. 3 semantic test groups passed in 0.130 s. Full snapshot parser coverage: 47,154 supported, 23,813 out of scope, 299 metadata, zero invalid/unsupported |
| 10 | Complete | One total byte policy DFA, output-preserving minimization and fail-closed bounds. 4 test groups passed in 34.599 s, including 272 oracle/DFA cases and three real base-OT/GDFA decisions. Full snapshot regex feature coverage has zero failures |
| 11 | Complete | SQLite atomic reservation, fail-closed crash/disconnect handling, manifest binding and supported CLI. 12 lifecycle/CLI/artifact/wire tests passed in 7.488 s, including independent server/client processes and concurrent claimants. Remote mode requires mutual TLS 1.3 |
| 12 | Implemented, full-scale acceptance incomplete | Final 40 tests passed in 50.466 s. Frozen 200-rule fixture has 406 oracle/DFA agreements and three fresh private decisions. Full parser/regex coverage passes. Expanded 2,000-rule and full-snapshot compilation still exceed bounds. See `docs/BENCHMARK_V2.md` and committed raw records |

Existing dirty legacy code, configurations, datasets and large artifacts are preserved and excluded from step commits. New code uses `src/zids_v2/`, tests use `tests_v2/`, runtime artifacts use ignored `v2-runs/`.

Completed step commits: 1 `64a2a92`, 2 `251f983`, 3 `8a6bb16`, 4 `f034c0e`,
5 `de0acb5`, 6 `e764bd7`, 7 `1f3c608`, 8 `7982ea9`, 9 `a4cb70a`,
10 `c8fce3b`, 11 `49b5044`. Step 12's implementation and measurements are committed
separately, with large-scale acceptance explicitly remaining open.
