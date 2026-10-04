# Run ZIDS v2

Use Python 3.12. Windows PowerShell setup:

```powershell
py -3.12 -m venv .venv-v2
.\.venv-v2\Scripts\Activate.ps1
python -m pip install -r requirements-v2.txt
```

Bash setup for Linux:

```bash
python3.12 -m venv .venv-v2
source .venv-v2/bin/activate
python -m pip install -r requirements-v2.txt
```

The commands below work in either activated shell. They only match serialized
request context and never fetch the example URLs. Output directories must be new.

```text
python -m src.zids_v2 compile --rules tests_v2/fixtures/demo.abp --output v2-runs/demo-policy
python -m src.zids_v2 length --request tests_v2/fixtures/request.json
python -m src.zids_v2 estimate --policy v2-runs/demo-policy/policy.json --length 41
python -m src.zids_v2 prepare --policy v2-runs/demo-policy/policy.json --length 41 --output v2-runs/demo-session
python -m src.zids_v2 serve --session v2-runs/demo-session --port 8787
```

The fixture encodes to 41 bytes. For other inputs, use the length printed by
`length`. Preparation takes only this public length and the private policy.
Leave `serve` running and use a second activated terminal:

```text
python -m src.zids_v2 evaluate --request tests_v2/fixtures/request.json --output v2-runs/demo-client --port 8787
python -m src.zids_v2 status --session v2-runs/demo-session
```

Expected client label is `ALLOW` and final server status is `CONSUMED`. Evaluation
uses two independent processes and actual Naor-Pinkas base OT. There is no master
key argument, alternate chooser, simulated OT or OT extension switch.

Prepare a fresh session in a new directory for every evaluation, even when the
policy and input length are unchanged. A dropped connection burns its session.
After a process crash, a RESERVED session stays unusable. Stop the old server,
then `python -m src.zids_v2 recover --session PATH` records it as BURNED.
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
`coverage` accepts the same rules/output arguments and writes the per-line report
without building a DFA. Compilation errors retain coverage and never drop an
unsupported network rule silently. The public session exposes n, q, outmax, cmax
and fixed-size metadata. Rule sources, hashes and diagnostics remain private.

For independent matching tests, install Node.js and the pinned reference once:

```text
python tools/setup_reference.py
python tools/check_v2_crypto.py
python -m unittest discover -s tests_v2 -v
```

On Windows Python 3.12, the step 11 lifecycle, CLI, artifact and wire tests passed
12 tests in 7.488 seconds. The full suite timing and scale results are recorded
in the final benchmark report. Linux commands are provided, but Linux execution
has not yet been verified in this workspace.

Protocol details are in [protocol_spec.md](protocol_spec.md),
[ot_suite.md](ot_suite.md), [easylist_profile.md](easylist_profile.md) and
[compiler.md](compiler.md). Historical entry points below the v2 banner in the
root README are retained as legacy material and are outside the supported flow.
