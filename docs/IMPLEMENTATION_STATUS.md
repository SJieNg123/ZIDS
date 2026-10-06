# Implementation status

The supported implementation is `src/zids_v2/`, with tests in `tests_v2/`.
The scope is EasyList network matching through the paper-style sparse GDFA
and real Naor-Pinkas base OT. OT extension, Beaver preprocessing, short-key
optimization and browser execution are excluded.

All protocol and workstation preparation code is implemented. Full-scale
acceptance remains incomplete. The current compiler has not produced a final
DFA for the 2,000-rule profile or full EasyList snapshot, so their private
evaluations and capacity measurements remain pending on the Ubuntu workstation.

| Area | Status | Evidence |
| --- | --- | --- |
| Dependencies and native crypto | Implemented | uv lockfile, pinned Python 3.12.3, dependency and native group checks on Windows and Ubuntu WSL2 |
| Wire format | Implemented | Independent processes, strict frame validation, truncation and replay tests |
| Base OT | Implemented | Naor-Pinkas Protocol 3.1, native Edwards25519, point validation and transcript binding |
| 1-of-256 OT and batching | Implemented | All 256 choices tested with real base OT, 8n bit transfers, XOR-relation and cross-session regressions |
| DFA grouping and codec | Implemented | Global character groups, alignment, padding, index widths and exhaustive short-input checks |
| GDFA construction and evaluation | Implemented | Fresh position keys, pads and permutations, final-only output, real OT integration |
| Artifacts and streaming | Implemented | Public/private separation, mmap policies, bounded buffers, large-row and fragmented transport tests |
| EasyList profile | Implemented | Fixed reference matcher and PSL, explicit coverage categories, supported context and regex semantics |
| Compiler | Implemented, full scale pending | Oracle/DFA agreement for fixtures, output-preserving minimization and unlimited default execution |
| Lifecycle and CLI | Implemented | Atomic reservation, consume/burn semantics, crash handling, fresh sessions and mutual TLS |
| Workstation tooling | Implemented | Detached jobs, persisted exit status, transactional checkpoints, packed transitions and benchmark resume |
| Large-scale experiments | Pending | Final 2,000-rule/full-snapshot DFA, semantic comparisons and fresh private evaluations |

After repository cleanup on 2026-10-06, Windows uv 0.10.5 with Python 3.12.0 passed
all 63 tests in 160.412 seconds. During the preceding uv migration, Ubuntu WSL2
with Python 3.12.3 synced the same lockfile and passed dependency and native group
checks. Before that migration,
Ubuntu 24.04.1 WSL2 with Python 3.12.3 and Node 22.23.3 passed all 63 tests in
82.200 seconds. The actual Ubuntu workstation and remote CI remain unverified.

Six fresh synthetic/small private decisions passed in the retained workstation
readiness run. The full-snapshot oracle labelled 187,782 generated candidates,
with automatic witnesses for 46,901 of 47,154 supported rules and 253 explicitly
unwitnessed rules. These are oracle results, not full-snapshot DFA equivalence.

An older unlimited 2,000-rule attempt ended without a final policy or recorded
exit reason. It predates checkpoint support and cannot be resumed. No OOM cause
or hardware ceiling was established. Compiler state/time caps remain disabled by
default, with explicit limits available to reproduce historical bounded attempts.

Use [RUN_V2.md](RUN_V2.md) for the supported CLI and
[WORKSTATION.md](WORKSTATION.md) for Ubuntu execution and recovery.
[BENCHMARK_V2.md](BENCHMARK_V2.md) describes measurements and evidence limits.
[History](history/README.md) retains the original audit, step-by-step plans and
recovery instructions for the retired implementation.
