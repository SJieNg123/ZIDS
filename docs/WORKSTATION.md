# Workstation execution

The workstation preparation code supports detached jobs, transactional compiler
checkpoints, packed byte-class transitions, binary mmap policies and streamed
GDFA/base-OT transport. OT extension and browser execution are excluded.
Large-scale acceptance still requires successful 2,000-rule and full-snapshot
compilation, semantic comparisons and fresh private evaluations on real hardware.

## Setup

Use Python 3.12 and Node.js 22. From the repository root, Windows PowerShell:

```powershell
py -3.12 -m venv .venv-v2
.\.venv-v2\Scripts\Activate.ps1
python -m pip install -r requirements-v2.txt
python tools/setup_reference.py
python tools/check_v2_crypto.py
python -B -m unittest discover -s tests_v2 -v
```

Linux Bash:

```bash
python3.12 -m venv .venv-v2
source .venv-v2/bin/activate
python -m pip install -r requirements-v2.txt
python tools/setup_reference.py
python tools/check_v2_crypto.py
python -B -m unittest discover -s tests_v2 -v
```

Linux CI is configured. Runtime results in this workspace were measured on
Windows only. Record the actual Python patch version, CPU, RAM, swap and storage
of the workstation with each experiment. A new compile can use another Python
3.12 patch version, but resuming a checkpoint requires the original patch version.

## Detached compilation without state or time caps

After activating the environment, these commands work in either shell:

```text
python -m tools.jobs_v2 start --directory v2-runs/workstation-job-01 -- python -B -X utf8 -m tools.benchmark_v2 --output v2-runs/workstation-compile --scales profile2000 full --secure-scales
python -m tools.jobs_v2 status --directory v2-runs/workstation-job-01
```

Both output directories must initially be new. The empty `--secure-scales`
requests compilation and independent semantic comparisons. Scales run in order.
There are no default NFA, DFA or compiler-time caps. RAM, committed memory and
available disk can still be exhausted. Packed storage reduces bytes per state,
it does not remove subset explosion. Checkpoints can be large, use local storage
with enough free space and keep private rules and artifacts under server access.

The launcher returns after the supervisor acknowledges startup. The job keeps
`stdout.log`, `stderr.log`, `supervisor.log` and atomic `job.json` with a heartbeat,
process IDs and the actual worker exit code. `SUCCEEDED` requires exit code zero.
`FAILED` retains the error logs. `SUPERVISOR_LOST` means the supervisor no longer
owns its OS lock and the worker outcome is unknown. It does not establish OOM.
Detached jobs survive normal launcher exit, but shutdown and enclosing OS job
managers can still terminate them. Check the recorded worker and its child
processes before restarting an interrupted job.

Each scale keeps `rules.abp`, `compiler.sqlite`, `compile-progress.jsonl`,
`coverage.json`, `ground_truth.json`, `attempt-NNNN.json` and, on successful
compilation, `policy.bin`. Progress includes raw/processed DFA counts and peak
working-set RSS. RSS is not Windows private committed memory. The root
`report.json` is updated atomically between phases and scales.

## Resume compilation

After confirming the previous worker and its children have stopped, launch a new
job directory using the same benchmark output:

```text
python -m tools.jobs_v2 start --directory v2-runs/workstation-job-02 -- python -B -X utf8 -m tools.benchmark_v2 --output v2-runs/workstation-compile --scales profile2000 full --secure-scales --resume
python -m tools.jobs_v2 status --directory v2-runs/workstation-job-02
```

Resume verifies input contexts, rule text, compiler, harness, PSL, dependencies,
reference lock and Python patch version. Keep those files unchanged throughout
an experiment. Completed scales are validated and skipped. Failed attempts stay
on disk, progress is appended and each new attempt gets its own record. A record
left `running` by abrupt controller death is incomplete evidence, never success.
Explicit compilation bounds may be changed for the next attempt. A benchmark
file lock and per-checkpoint lock reject concurrent writers.

SQLite commits completed transitions and discovered pending subsets together
every 1,000 rows or 30 seconds of row processing. Interrupted transactions roll
back to the last commit. NFA construction repeats on resume, completed
determinization is retained, and minimization restarts. Minimization still loads
compact transitions into RAM and uses Moore refinement. The entire compilation
is not an external-memory algorithm.

To move a checkpoint, stop all writers first. Copy the whole run directory,
including any SQLite WAL sidecars, using a consistent copy. Retain the matching
source revision and Python patch version. The older unlimited experiment had
no checkpoint, so its intermediate states cannot be resumed.

For direct CLI compilation, specify a persistent checkpoint and a new output
directory on every attempt:

```text
python -m src.zids_v2 compile --rules rules/easylist.txt --checkpoint v2-runs/full-compiler.sqlite --output v2-runs/full-attempt-01
python -m src.zids_v2 compile --rules rules/easylist.txt --checkpoint v2-runs/full-compiler.sqlite --output v2-runs/full-attempt-02
```

## Coverage and diagnosis

For `profile2000` and `full`, the benchmark generates per-rule positive candidates
and context mutations, then obtains final labels from the pinned independent ABP
matcher. `generated-cases.json` records every rule without an automatic witness.
Mutations are not assumed negative, because another policy rule may match them.
Regex and difficult exception rules can need manually supplied cases. Generated
coverage is sampled semantic evidence, not a proof of all inputs.

Inspect context-condition groups without determinizing the whole policy:

```text
python -m tools.diagnose_v2 --rules rules/easylist.txt --output v2-runs/full-groups.json
```

The report ranks URL-union NFA sizes and maps each group back to rule IDs. It
excludes context guards and suffixes. Large groups are candidates for profiling,
their size alone does not identify the cause of DFA subset explosion.

## Fresh private evaluations

Use the compiled `policy.bin` with `length`, `estimate`, `prepare`, `serve` and
`evaluate` as shown in [RUN_V2.md](RUN_V2.md). Policies can be reused. Every
evaluation requires fresh garbling and real base OT. Benchmark `--resume`
rejects secure evaluation scales and never reuses OT state.

Binary policies are checksummed and mapped read-only. Matrix generation streams
bounded chunks. OT option ciphertexts use a fixed public fragment schedule, with
the same 8n base transfers. The receiver spools the complete ciphertext tables
before choosing locally, then evaluates after the transport closes. Temporary
storage is therefore required as well as server artifact storage. Aggregate byte
caps are disabled by default, but canonical wire field widths still apply.

To run a small complete measurement with fresh sessions:

```text
python -m tools.jobs_v2 start --directory v2-runs/smoke-job -- python -B -X utf8 -m tools.benchmark_v2 --output v2-runs/smoke --scales synthetic small --secure-scales synthetic small
python -m tools.jobs_v2 status --directory v2-runs/smoke-job
python -m tools.verify_benchmark_policies --run v2-runs/smoke --output v2-runs/smoke-equivalence.json
```

Run the verifier after the job succeeds. It supports legacy JSON and binary
policies and checks both language equivalence and protocol-source hashes.
Changed hashes mean older protocol measurements cannot be presented as current
measurements, even when the compiled policy language remains equivalent.
