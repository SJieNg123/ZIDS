# Workstation coding plan, 2026-10-05

Complete and commit each validated increment before the next long experiment.
Use real base OT without extension. Preserve the declared EasyList semantics,
private policy, final-only output and one-time garbling/OT lifecycle. Compiler
state and time caps remain opt-in. Existing legacy edits and prior runs stay intact.

1. Durable jobs: detached supervisor, atomic status, stdout/stderr, exit codes,
   heartbeat and reconciliation after supervisor failure. Test success, failure,
   launcher exit and interruption with real processes.
2. Compiler checkpoints: transactional storage of discovered subsets and completed
   transitions, source/compiler binding and continuation after abrupt interruption.
   Restore only private compilation work, never consumed protocol sessions.
3. Compiler storage: compact alphabet-class transitions, packed integer state
   references and output-preserving refinement without dense Python rows for
   intermediate states. Verify resumed and uninterrupted language equivalence.
4. Large artifacts: versioned binary private policy, streamed matrix rows and
   fragmented OT options with public fixed schedules. Remove arbitrary default
   aggregate byte caps while retaining canonical format and transcript checks.
5. Verification and portability: broader independent EasyList oracle cases,
   regression coverage of old thresholds, workstation commands and CI coverage.
   Report actual Windows/Linux execution separately from configured workflows.

Full-snapshot acceptance remains pending workstation measurements. Large
intermediate state counts do not establish the size of the final minimized DFA.

Step 1 implemented: `python -m tools.jobs_v2 start --directory JOB -- COMMAND`
launches a detached supervisor. `python -m tools.jobs_v2 status --directory JOB`
returns persisted state. Two tests passed in 4.572 s, covering launcher exit,
successful/failed real child processes, retained logs and lost-supervisor
reconciliation. `SUPERVISOR_LOST` means the worker outcome is unknown, not OOM.
Machine shutdown or an enclosing OS job manager can still interrupt execution.

Step 2 implemented: SQLite transactional checkpoints and CLI/benchmark wiring.
A real child exits abruptly after 60 committed rows, then the resumed DFA has
the same canonical digest as uninterrupted compilation. Identity mismatches and
concurrent writers are rejected. Eight checkpoint/CLI/benchmark tests passed in
9.290 s, and all eight existing compiler tests passed in the preceding run.

Step 3 implemented: compact alphabet-class arrays for intermediate/final DFAs,
SQLite transition rows, and packed refinement signatures. Fifteen storage,
checkpoint, compiler and codec tests passed in 23.784 s. A 2,000-byte literal
fixture uses under one twentieth of dense uint64 transition storage. Random
labelled DFAs retain all three outputs after refinement. No full-scale speedup
or reduction in reachable subset count is claimed.

Step 4a implemented: atomic binary policy publication, complete-file SHA256,
strict format validation, mmap loading and legacy JSON reading. CLI and benchmark
use `policy.bin`. Eight policy/CLI/benchmark tests passed in 9.718 s, including a
real file larger than 128 MiB, checksum corruption and fresh real-OT evaluation.

Step 4b implemented: streaming matrix preparation, lazy private OT table slices,
PRF slices with identical domains, fixed public ciphertext fragments and local
spooling of received tables/selections. Default aggregate byte caps are removed.
Seventeen existing protocol/artifact/CLI/lifecycle tests passed in 14.936 s.
Five additional streaming tests passed in 13.167 s, including a real garbled row
over 64 MiB, a transport payload over 64 MiB with under 24 MiB traced buffers,
real base OT over small frames, and invalid fragment ordering/lengths. The large
transport test isolates framing, it is not a large-scale private evaluation.
