# ZIDS v2: EasyList and base OT

The supported implementation is `src/zids_v2`. It compiles the declared EasyList
network profile into one policy DFA, prepares the paper-style GDFA, and evaluates
it with real Naor-Pinkas base OT in separate server and client processes.
OT extension and browser execution are excluded.

Follow [the runnable Windows and Bash guide](docs/RUN_V2.md).
See [implementation status](docs/IMPLEMENTATION_STATUS.md) and
[protocol and leakage contract](docs/protocol_spec.md) for validated scope.
Full-snapshot parser coverage does not establish full-snapshot compilation capacity.

The historical commands below use legacy code and do not implement the supported
v2 protocol. In particular, the shared-master chooser must not be used for private
evaluation. Existing legacy code and local changes are retained for comparison.

---

## Development of ZIDS
how to use
for OT server, start a terminal and run:
```
python -m src.server.ot.dev_ot_server `
  --port 8787 `
  --master-hex 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff `
  --single-threaded
```
for OT client, start another terminal and run:
```
python tools/bench_all.py `
--easylist rules/input200/easylist_(number).abp `
--dataset rules/input200/dataset/dataset_L(number)_urls.txt `
--engine-init-file configs/engine_init_L(number).json `
--outdir out/bench_pipeline_L(number) `
--artifacts-outdir out/bench_pipeline_L(number)/artifacts `
--engine-repeat 3 `
--engine-warmup 5 `
--ot-repeats 1 `
--ot-warmup 3 `
--ot-max-urls 200 `
--with-regex-baseline `
--regex-repeat 3 `
--regex-warmup 5 `
--outmax 256 `
--cmax 1 `
--gk-bytes 32
```
Replace (number) with 8, 12, 16, 20, 24, 28, 32, 48, 64, 128 to run different configurations.
