# Implementation status

Planning commit: `47e4cf2`. User authorized automatic commits after each validated step and continuation through steps 1–12. No push requested.

Latest scope: base OT only. No OT extension or OT-specific preprocessing optimizations. Browser execution excluded.

| Step | Status | Evidence |
| --- | --- | --- |
| 1 | Complete | Windows Python 3.12.0 / PyNaCl 1.6.2 native group smoke passed, pip check passed, NP Protocols 3.1 and 2.1 inspected. Linux runtime verification remains for platform CI |
| 2 | Complete | `python -B -m unittest tests_v2.test_wire -v`, 4 tests passed in 0.111 s, including two spawned processes and malformed/replayed frames |
| 3 | Pending | NP amortized base OT |
| 4 | Pending | NP 1-of-256 PRF reduction |
| 5 | Pending | Batch base-OT integration, no extension |
| 6 | Pending | Global groups and bit codec |
| 7 | Pending | Position-based GDFA and real OT |
| 8 | Pending | Streaming offline GDFA |
| 9 | Pending | EasyList parser, context and reference |
| 10 | Pending | Policy DFA compiler |
| 11 | Pending | Persistent lifecycle and supported CLI |
| 12 | Pending | Coverage, scale and benchmark |

Existing dirty legacy code, configurations, datasets and large artifacts are preserved and excluded from step commits. New code uses `src/zids_v2/`, tests use `tests_v2/`, runtime artifacts use ignored `v2-runs/`.
