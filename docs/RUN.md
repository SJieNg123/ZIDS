# Run ZIDS

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) first. The
project pins Python 3.12.3 in `.python-version` and all Python dependencies in
`uv.lock`. Windows PowerShell and Linux use the same setup:

```powershell
uv python install
uv sync --locked
uv pip check
```

`uv sync` creates and manages `.venv`. Activation is not required. The commands
below work in PowerShell or Bash. They only match serialized
request context and never fetch the example URLs. Output directories must be new.

```text
uv run --locked python -m src.zids compile --rules tests/fixtures/demo.abp --output runs/demo-policy
uv run --locked python -m src.zids length --request tests/fixtures/request.json
uv run --locked python -m src.zids estimate --policy runs/demo-policy/policy.bin --length 41
uv run --locked python -m src.zids prepare --policy runs/demo-policy/policy.bin --length 41 --output runs/demo-session
uv run --locked python -m src.zids serve --session runs/demo-session --port 8787
```

The fixture encodes to 41 bytes. For other inputs, use the length printed by
`length`. Preparation takes only this public length and the private policy.
Leave `serve` running and use a second terminal from the repository root:

```text
uv run --locked python -m src.zids evaluate --request tests/fixtures/request.json --output runs/demo-client --port 8787
uv run --locked python -m src.zids status --session runs/demo-session
```

Expected client label is `ALLOW` and final server status is `CONSUMED`. Evaluation
uses two independent processes and actual Naor-Pinkas base OT. There is no master
key argument, alternate chooser, simulated OT or OT extension switch.

Prepare a fresh session in a new directory for every evaluation, even when the
policy and input length are unchanged. A dropped connection burns its session.
After a process crash, a RESERVED session stays unusable. Stop the old server,
then `uv run --locked python -m src.zids recover --session PATH` records it as BURNED.
Recovery never makes old keys reusable. TCP may retransmit the same bytes within
a connection, but application reconnect and transcript replay are not supported.

The server needs the complete session directory. The client receives only the
public manifest, complete matrix and its OT-selected bundles. It does not need
access to the policy, server private directory, EasyList rules or Node. Keep
server private files and the lifecycle database together. Do not restore a
consumed session from backup or duplicate it into multiple session stores.
Windows filesystem ACLs must be managed by the operator for OS-level isolation.

Unauthenticated sockets are restricted to numeric loopback addresses for local
testing. Remote use requires mutual TLS 1.3. Supply `--cert CERT --key KEY --ca CA`
on both commands, plus `--server-name NAME` on the client when the certificate
name differs from `--host`. Certificate validation cannot be disabled in the CLI.

For another rules file, run `compile --rules FILE --output NEW_DIRECTORY`.
New compilations write a checksummed `policy.bin` with compact transitions and
read-only memory mapping. Legacy `policy.json` remains readable. Private policy
loading has no default file-size cap. Never send either policy format to clients.
Compilation defaults to unlimited states and runtime. To run the large compiler
experiments sequentially without state or time caps, use a fresh directory:

```text
uv run --locked python -m tools.benchmark --output runs/unlimited-compile --scales profile2000 full --secure-scales
```

The empty `--secure-scales` selects compilation and reference comparisons only.
Each scale retains `compile-progress.jsonl`, its final record and any policy.
See [WORKSTATION.md](WORKSTATION.md) for detached execution, checkpoint recovery,
benchmark `--resume`, broader oracle cases and large-policy storage details.
The run continues until completion or an actual process/resource failure.
Optional `--max-nfa`, `--max-dfa` and `--seconds` reproduce explicitly bounded
experiments. Omitting them also disables the outer compile-worker timeout.

`coverage` accepts the same rules/output arguments and writes the per-line report
without building a DFA. Compilation errors retain coverage and never drop an
unsupported network rule silently. The public session exposes n, q, outmax, cmax
and fixed-size metadata. Rule sources, hashes and diagnostics remain private.

For independent matching tests, install Node.js and the pinned reference once:

```text
uv run --locked python tools/setup_reference.py
uv run --locked python tools/check_crypto.py
uv run --locked python -m unittest discover -s tests -v
```

After the layout rename, Windows uv 0.10.5 with Python 3.12.0 passed all 66 tests
in 143.886 seconds on 2026-10-08. During the preceding uv migration, Ubuntu
24.04.1 WSL2 with Python 3.12.3 synced the same lockfile and passed dependency
and native group checks. Before the
migration, that Ubuntu environment passed all 63 tests in 82.200 seconds. See
[BENCHMARK.md](BENCHMARK.md) for measured capacity, timings and remaining
large-profile limits. The target Ubuntu workstation and remote CI have not yet
been exercised. Ubuntu setup and transfer commands are in [WORKSTATION.md](WORKSTATION.md).

Protocol details are in [protocol_spec.md](protocol_spec.md),
[ot_suite.md](ot_suite.md), [easylist_profile.md](easylist_profile.md) and
[compiler.md](compiler.md). The retired implementation and original audit can be
located through [history](../legacy/README.md).
