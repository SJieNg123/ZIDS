# Implementation status

Planning commit: `47e4cf2`. User authorized automatic commits after each validated step and continuation through steps 1–12. No push requested.

Latest scope: base OT only. No OT extension or OT-specific preprocessing optimizations. Browser execution excluded.

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
| 9 | Pending | EasyList parser, context and reference |
| 10 | Pending | Policy DFA compiler |
| 11 | Pending | Persistent lifecycle and supported CLI |
| 12 | Pending | Coverage, scale and benchmark |

Existing dirty legacy code, configurations, datasets and large artifacts are preserved and excluded from step commits. New code uses `src/zids_v2/`, tests use `tests_v2/`, runtime artifacts use ignored `v2-runs/`.
