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
uv run --locked python tools/check_crypto.py
uv run --locked python -B -m unittest discover -s tests -v
```

Python 3.12.3 is pinned in `.python-version`. Dependencies are locked in `uv.lock`.
uv manages the local `.venv` without shell activation.

Follow [RUN.md](docs/RUN.md) for compile, prepare, serve and evaluate commands.
Use [WORKSTATION.md](docs/WORKSTATION.md) for Ubuntu setup, detached experiments
and checkpoint recovery. After the layout rename, Windows Python 3.12.0 passed
66 tests in 143.886 seconds using uv. See [implementation status](docs/IMPLEMENTATION_STATUS.md)
and [measurement evidence](docs/BENCHMARK.md) for validation details.
The 2,000-rule and full-snapshot DFA acceptance experiments remain incomplete.

| Path | Purpose |
| --- | --- |
| `src/zids/` | Supported protocol, EasyList compiler and CLI |
| `tests/` | Protocol tests and fixed semantic fixtures |
| `tools/` | Reference setup, benchmarks, jobs and diagnostics |
| `rules/` | Fixed EasyList snapshot and small benchmark input |
| `docs/` | Current protocol specifications and operation guides |
| `legacy/` | Retired code, inputs, audit, plans and historical measurements |
| `runs/` | Ignored current experiments and checkpoints |

The [protocol contract](docs/protocol_spec.md), [OT suite](docs/ot_suite.md),
[EasyList profile](docs/easylist_profile.md) and [compiler notes](docs/compiler.md)
define the supported behavior. The [legacy guide](legacy/README.md) documents
the archived layout and recovery of historical experiments.
