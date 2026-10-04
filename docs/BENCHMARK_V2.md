# v2 validation and capacity, 2026-10-04

Compiler execution policy changed on 2026-10-05 at the user's request. State and
time caps, including the outer compile-worker timeout, are now disabled by
default. The measurements below are preserved historical bounded attempts and
do not establish a hardware ceiling. New unlimited runs retain phase/count
progress and report actual completion, allocation errors or worker exits.

Steps 1–11 implement the supported base-OT protocol and EasyList profile. Step 12
provides reproducible coverage, differential fixtures, process measurements and
capacity checks. Full-scale acceptance remains incomplete because the 2,000-rule
profile and full snapshot exceed the tested compiler bounds. They are not reported
as successful private evaluations.

The final Windows Python 3.12.0 / PyNaCl 1.6.2 run passed all 40 tests in 50.466 s.
The native group smoke check and `pip check` passed. Tests include all 256 OT
choices, malformed points and transcripts, two independent processes, GDFA
alignment and padding, durable reservation races and crashes, mutual TLS,
independent matcher comparisons and actual base-OT/GDFA decisions.

Windows and Linux CI jobs are configured in `.github/workflows/zids-v2.yml`.
Linux execution and the remote CI jobs have not been observed in this workspace.

## Matching and compiler results

| Dataset | Network rules | Reference cases | Final minimized Q | outmax | cmax | Status |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Synthetic | 2 | 3 | 27 | 5 | 16 | Three private decisions passed |
| `rules/small.abp` | 2 | 3 | 48 | 7 | 29 | Three private decisions passed |
| Frozen context fixture | 200 | 406 | 1,475 | 38 | 162 | Zero DFA mismatches, three private decisions passed |
| First 2,000 network rules | 2,000 | 16 | unavailable | unavailable | unavailable | Determinization exceeded 100,000 intermediate states |
| Full fixed snapshot | 47,154 | 16 | unavailable | unavailable | unavailable | Expanded compilation exceeded its time budget |

The 200-rule fixture has 202 BLOCK, 1 ALLOW and 203 NOMATCH cases. Its JSONL
ground truth is checked against the pinned independent ABP matcher in the test
suite. It includes existing input200 URLs, explicit negatives, a request exception
and context-dependent rules. The other semantic tests cover document exceptions,
ancestor chains, generic-block suppression, party, case, regex and domain edges.

Full snapshot parser coverage is 47,154 supported network candidates, 23,813
out-of-scope lines and 299 metadata/blank lines. There are zero invalid or unknown
option lines and zero regex feature failures. The independent matcher accepts
all parser-supported rules. This establishes syntax coverage, not complete
full-snapshot semantic equivalence or successful full-snapshot garbling.

Snapshot SHA256:
`2888c230ef758e3c5c73a867376ed379d12cd2e9d9b94551634fc60dc1a05f34`.
Per-line reports and ground truth are retained under the corresponding local
`v2-runs/benchmark-20261004*` directories. Compact raw measurements are committed
under `benchmarks/v2/2026-10-04/` with a digest index.

The first 200-rule attempt hit the default DFA bound. Sharing regex prefixes,
matched policy suffixes and redundant active alternatives reduced its latest
compile time to 1.684 s. All three successfully measured policies are isomorphic
to the final compiler's output under canonical BFS state numbering. All 13
protocol module hashes are unchanged from the OT measurement run. The verification
record preserves those checks, so the later compiler and context fixes do not
invalidate the measured GDFA/OT results for these inputs.

## Actual base-OT measurements

Each row below used a new session and separate preparation, server and client
processes. Q = 1,475, outmax = 38 and cmax = 162 for this 200-rule policy.

| Decision | n | Offline prepare, s | Server online, s | Fresh request total, s | Client received bytes | Base bit transfers |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| BLOCK | 79 | 27.202 | 94.311 | 122.040 | 259,312,123 | 632 |
| ALLOW | 82 | 28.475 | 204.406 | 233.423 | 269,159,616 | 656 |
| NOMATCH | 89 | 52.637 | 223.085 | 276.405 | 292,136,453 | 712 |

For the first row, the public matrix is 147,870,225 bytes and the private position
bundles are 111,393,792 bytes. Server peak RSS in these three samples is about
118 MiB. The raw records contain process CPU, peak RSS, disk footprint, each role's
send/receive bytes and frames, prefetch, OT and local decode durations.

Byte counters measure the application protocol, including frame headers. They
exclude TCP/IP and TLS overhead and transport retransmissions. The public JSON
manifest can differ slightly in length because the initial state is randomly
permuted. The observed 8n public-key bit transfers confirm base OT rather than OT
extension. Client decisions are not present in server results.

These are three functional samples with noticeable runtime variation, not a
statistical throughput claim. Compiled policy reuse is separate from fresh
garbling and OT. Total time includes worker startup and preparation but excludes
compilation and the independent matcher. There is no warmed one-time material.

## Remaining capacity limits

The final 2,000-rule attempt used a 100,000-state DFA bound and a 300 s compiler
budget. It hit the intermediate DFA bound after 126.200 s, at about 676 MiB peak
RSS, before a minimized DFA could be produced.

The final full-snapshot attempt allowed 1,000,000 NFA states and 20,000 DFA states
with a 300 s construction/determinization/minimization budget. It timed out after
319.859 s total, including the separately measured regex feature validation, at
about 1,780 MiB peak RSS. Earlier NFA and DFA limit failures are preserved as well.

Further work is required on large-policy construction and determinization.
Increasing a limit does not establish that the resulting matrix and OT bundles
will fit their own resource bounds. Those bounded attempts stopped explicitly
at their requested limits. No full-snapshot result, large-scale speedup or complete
full-profile delivery is claimed.

## Reproduce

After the setup in [RUN_V2.md](RUN_V2.md), use a new output directory per run:

```text
python -m tools.benchmark_v2 --output v2-runs/my-benchmark --secure-scales synthetic small context200
python -m tools.benchmark_v2 --output v2-runs/my-2000 --scales profile2000 --secure-scales --max-dfa 100000 --seconds 300
python -m tools.benchmark_v2 --output v2-runs/my-full --scales full --secure-scales --max-nfa 1000000 --max-dfa 20000 --seconds 300
python -m tools.verify_benchmark_policies --run v2-runs/my-benchmark --output v2-runs/my-equivalence.json
```

The benchmark retains failed attempts, source hashes, implementation snapshots
and per-request records. Session private files remain in the local ignored run
directories. Committed reports and the full-run source archive contain no session
key material. Compiler source-text hashes use UTF-8 after text newline handling,
while CLI coverage also records hashes of the original input files.
