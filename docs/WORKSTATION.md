# Ubuntu workstation execution

The workstation preparation code supports detached jobs, transactional compiler
checkpoints, packed byte-class transitions, binary mmap policies and streamed
GDFA/base-OT transport. OT extension and browser execution are excluded.
Large-scale acceptance still requires successful 2,000-rule and full-snapshot
compilation, semantic comparisons and fresh private evaluations on real hardware.

## Move the project from Windows

The target workstation uses Ubuntu. The package commands below use Ubuntu 24.04
LTS as the setup baseline. Check the actual release with `cat /etc/os-release`.
Local validation on Ubuntu 24.04.1 WSL2 with Python 3.12.3 and Node 22.23.3 passed
all 63 tests in 82.200 s. Dependency and native group checks also passed. This
validates Linux execution locally, not the target workstation or full-scale runs.
Ubuntu 22.04's default Python is 3.10, so use a separately installed Python 3.12
there. On other releases, also select Python 3.12 explicitly. Do not replace
Ubuntu's system `python3` command.

Transfer the committed source to a directory on the workstation's local SSD.
The current changes are committed locally and have not been pushed. To create a
source archive from Windows PowerShell, run at the repository root:

```powershell
git archive --format=tar.gz --output=v2-runs/ubuntu-source.tar.gz HEAD `
  .gitattributes requirements-v2.txt src/zids_v2 tests_v2 docs `
  rules/easylist.txt rules/small.abp `
  tools/jobs_v2.py tools/benchmark_v2.py tools/cases_v2.py tools/diagnose_v2.py `
  tools/verify_benchmark_policies.py tools/check_v2_crypto.py `
  tools/setup_reference.py tools/reference_matcher.cjs tools/reference-lock.json
```

Copy that archive to Ubuntu using your normal file transfer method, then extract
into a new directory. This archive contains committed files, including the fixed
rule snapshot. It excludes legacy artifacts, local uncommitted edits, `.venv-v2`,
`.reference` and ignored `v2-runs` checkpoints. Checkpoints must be transferred separately if needed.
Recreate the virtual environment on Ubuntu instead of copying the Windows one.

## Ubuntu setup

On Ubuntu 24.04, install the Python and download utilities:

```bash
sudo apt-get update
sudo apt-get install python3.12 python3.12-venv ca-certificates curl xz-utils
```

Use Node.js 22 for the independent reference matcher. If it is already installed,
check `node --version` and skip the following download. This example installs the
official x86-64 binary in a private tools directory inside the project. For an
ARM64 workstation replace `linux-x64` with `linux-arm64` throughout. Run in Bash:

```bash
mkdir -p v2-runs/tools
pushd v2-runs/tools
curl --fail --location --remote-name https://nodejs.org/dist/v22.23.3/node-v22.23.3-linux-x64.tar.xz
curl --fail --location --output node-v22.23.3-SHASUMS256.txt https://nodejs.org/dist/v22.23.3/SHASUMS256.txt
sha256sum --check --ignore-missing node-v22.23.3-SHASUMS256.txt && tar -xf node-v22.23.3-linux-x64.tar.xz
popd
export PATH="$PWD/v2-runs/tools/node-v22.23.3-linux-x64/bin:$PATH"
node --version
```

Reapply that `PATH` export in each new shell that runs the oracle or tests.
The detached supervisor inherits it. Node is needed for validation, the protocol
client does not use it. The pinned Python requirements install into the venv:

```bash
umask 077
python3.12 -m venv .venv-v2
source .venv-v2/bin/activate
python -m pip install -r requirements-v2.txt
python -m pip check
python tools/setup_reference.py
python tools/check_v2_crypto.py
python -B -m unittest discover -s tests_v2 -v
```

Record the actual Python patch version, CPU, RAM, swap and storage with each run:

```bash
python --version
node --version
uname -a
lscpu
free -h
swapon --show
df -h . /tmp
```

The Python package baseline follows the [Ubuntu 24.04 package catalogue](https://packages.ubuntu.com/noble/python3.12-venv).
The separate 22.04 interpreter requirement follows its [default Python package](https://packages.ubuntu.com/jammy/python3).
Node archives and checksums come from the [official Node distribution](https://nodejs.org/dist/v22.23.3/).
Python documents virtual environments as [non-portable](https://docs.python.org/3.12/library/venv.html).

## Detached compilation without state or time caps

After activating the Ubuntu environment, run from the repository root:

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

For SSH operation, reconnect and query job status after disconnecting. A machine
with a scheduler or login-session cleanup policy may terminate detached children
too, so use its allocated job environment when required. The tool does not change
administrator resource policies or add compiler state/time limits.

Follow progress on Ubuntu:

```bash
tail -f v2-runs/workstation-job-01/stdout.log
tail -n 5 v2-runs/workstation-compile/profile2000/compile-progress.jsonl
```

If a worker disappears, inspect `stderr.log` and the kernel log before assigning
a cause. SIGKILL alone is not evidence of OOM:

```bash
sudo journalctl --kernel --since "1 hour ago" --no-pager --grep 'Out of memory|oom|Killed process'
```

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

The existing Windows measurements used Python 3.12.0. Ubuntu 24.04's distribution
Python is 3.12.3, so checkpoints from those two interpreters will intentionally
fail the version check. Start a new Ubuntu run unless the checkpoint was created
with exactly the same patch version and matching code. Do not edit checkpoint
identity metadata to bypass that check.

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

To put spooled data on a chosen local SSD, set `TMPDIR` before launching the
supervisor. The directory must have space for the run and remain available:

```bash
mkdir -p v2-runs/tmp
chmod 700 v2-runs/tmp
export TMPDIR="$PWD/v2-runs/tmp"
```

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
