# ZIDS: EasyList and base OT

ZIDS compiles the declared EasyList network profile into one policy DFA and
evaluates private request context through a garbled DFA with Naor-Pinkas base OT.
The server and client run in separate processes. The client receives the final
`ALLOW`, `BLOCK` or `NOMATCH` result. OT extension and browser execution are out
of scope.

Install uv and Node.js 22, then run from the repository root in PowerShell or Bash:

```text
uv python install
uv sync --locked
uv run --locked python tools/setup_reference.py
uv run --locked python tools/check_v2_crypto.py
uv run --locked python -B -m unittest discover -s tests_v2 -v
```

Python 3.12.3 is pinned in `.python-version`. Dependencies are locked in `uv.lock`.
uv manages the local `.venv` without shell activation.

Follow [RUN_V2.md](docs/RUN_V2.md) for compile, prepare, serve and evaluate commands.
Use [WORKSTATION.md](docs/WORKSTATION.md) for Ubuntu setup, detached experiments
and checkpoint recovery. After cleanup, Windows Python 3.12.0 passed 63 tests in
160.412 seconds using uv. See [implementation status](docs/IMPLEMENTATION_STATUS.md)
and [measurement evidence](docs/BENCHMARK_V2.md) for validation details.
The 2,000-rule and full-snapshot DFA acceptance experiments remain incomplete.

| Path | Purpose |
| --- | --- |
| `src/zids_v2/` | Supported protocol, EasyList compiler and CLI |
| `tests_v2/` | Protocol tests and fixed semantic fixtures |
| `tools/` | Reference setup, benchmarks, jobs and diagnostics |
| `rules/` | Fixed EasyList snapshot and small benchmark input |
| `docs/` | Current protocol specifications and operation guides |
| `benchmarks/v2/` | Historical measurement reports and measured source snapshots |
| `docs/history/` | Original audit evidence and completed development plans |
| `v2-runs/` | Ignored local experiments, checkpoints and retired files |

The [protocol contract](docs/protocol_spec.md), [OT suite](docs/ot_suite.md),
[EasyList profile](docs/easylist_profile.md) and [compiler notes](docs/compiler.md)
define the supported behavior. Legacy source recovery is documented in
[history](docs/history/README.md).
