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
