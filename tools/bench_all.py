# tools/benchmark.py
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Dict, Any


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"


def _run_step(label: str, cmd: List[str]) -> float:
    """
    Run a subprocess step and return elapsed seconds.
    """
    print(f"[benchmark] STEP {label}")
    print("           ", " ".join(cmd))
    t0 = time.perf_counter()
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[benchmark] ERROR in step {label}: exit code {e.returncode}", file=sys.stderr)
        raise
    dt = time.perf_counter() - t0
    print(f"[benchmark] DONE {label}: {dt:.3f}s\n")
    return dt


def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _auto_urls_from_dataset(dataset: Path, out_path: Path, max_urls: Optional[int]) -> Path:
    """
    給一個 'req|doc|type' ABP dataset，抽出 req 當作 URL，
    寫成一行一個 URL 的檔案，給 OT benchmark 用。
    """
    _ensure_dir(out_path.parent)
    n_in = n_out = 0
    with dataset.open("r", encoding="utf-8-sig", errors="ignore") as fin, \
         out_path.open("w", encoding="utf-8") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            n_in += 1
            req = line.split("|", 1)[0].strip()
            if not req:
                continue
            fout.write(req + "\n")
            n_out += 1
            if max_urls and n_out >= max_urls:
                break
    print(f"[benchmark] extracted {n_out} URLs from {dataset} → {out_path}")
    return out_path


def main() -> None:
    ap = argparse.ArgumentParser(
        description="End-to-end ZIDS pipeline benchmark (EasyList → artifacts → engine/OT)"
    )
    ap.add_argument("--easylist", required=True, help="ABP/EasyList rules file")
    ap.add_argument("--dataset", required=True,
                    help="ABP-style dataset: each line 'req|doc|type' (for bench_zids)")
    ap.add_argument("--engine-init-file", required=True,
                    help="engine init JSON (for src.client.online.engine)")
    ap.add_argument("--engine-module", default="src.client.online.engine",
                    help="engine module for online eval (default: src.client.online.engine)")
    ap.add_argument("--outdir", default="out/bench_pipeline",
                    help="directory for benchmark outputs (CSV, summary.json)")
    ap.add_argument("--artifacts-outdir", default=None,
                    help="directory for build_artifacts output "
                         "(default: <outdir>/artifacts)")
    ap.add_argument("--idmap-path", default=None,
                    help="id→action JSON path (default: <outdir>/id_to_action.json)")
    ap.add_argument("--ot-urls", default=None,
                    help="text file: one URL per line for OT benchmark; "
                         "if omitted, derived from --dataset")
    ap.add_argument("--ot-max-urls", type=int, default=1000,
                    help="max URLs to extract from dataset for OT benchmark (0 = no limit)")
    ap.add_argument("--engine-repeat", type=int, default=1,
                    help="repeat per sample in engine benchmark (passed to bench_zids.py)")
    ap.add_argument("--engine-warmup", type=int, default=5,
                    help="warmup samples for engine benchmark")
    ap.add_argument("--ot-repeats", type=int, default=1,
                    help="repeat per URL in OT benchmark")
    ap.add_argument("--ot-warmup", type=int, default=3,
                    help="warmup evaluations before OT timing")
    ap.add_argument("--with-regex-baseline", action="store_true",
                    help="also run regex-only benchmark (bench_zids.py --easylist)")
    ap.add_argument("--regex-repeat", type=int, default=1,
                    help="repeat per sample in regex baseline benchmark")
    ap.add_argument("--regex-warmup", type=int, default=5,
                    help="warmup samples for regex baseline")
    ap.add_argument("--outmax", default="auto",
                    help="forwarded to build_artifacts.py --outmax (default: auto)")
    ap.add_argument("--cmax", type=int, default=1,
                    help="forwarded to build_artifacts.py --cmax (default: 1)")
    ap.add_argument("--gk-bytes", type=int, default=32,
                    help="forwarded to build_artifacts.py --gk-bytes")
    args = ap.parse_args()

    outdir = (REPO_ROOT / args.outdir).resolve()
    _ensure_dir(outdir)

    artifacts_outdir = (REPO_ROOT / args.artifacts_outdir).resolve() if args.artifacts_outdir else (outdir / "artifacts")
    _ensure_dir(artifacts_outdir)

    idmap_path = Path(args.idmap_path).resolve() if args.idmap_path else (outdir / "id_to_action.json")

    easylist = Path(args.easylist).resolve()
    dataset = Path(args.dataset).resolve()
    engine_init_file = Path(args.engine_init_file).resolve()

    if not easylist.exists():
        ap.error(f"EasyList not found: {easylist}")
    if not dataset.exists():
        ap.error(f"dataset not found: {dataset}")
    if not engine_init_file.exists():
        ap.error(f"engine-init-file not found: {engine_init_file}")

    # ------------ STEP 0: export id→action ------------
    export_id_py = TOOLS_DIR / "export_id_to_action.py"
    if not export_id_py.exists():
        print(f"[benchmark] WARNING: {export_id_py} not found, skipping idmap export",
              file=sys.stderr)
        idmap_time = 0.0
    else:
        cmd = [
            sys.executable,
            str(export_id_py),
            "--easylist", str(easylist),
            "--out", str(idmap_path),
        ]
        idmap_time = _run_step("export_id_to_action", cmd)

    # ------------ STEP 1: build artifacts (offline pipeline) ------------
    build_artifacts_py = TOOLS_DIR / "build_artifacts.py"
    if not build_artifacts_py.exists():
        print(f"[benchmark] ERROR: {build_artifacts_py} not found", file=sys.stderr)
        sys.exit(1)

    ba_cmd = [
        sys.executable,
        str(build_artifacts_py),
        "--easylist", str(easylist),
        "--outdir", str(artifacts_outdir),
        "--outmax", str(args.outmax),
        "--cmax", str(args.cmax),
        "--gk-bytes", str(args.gk_bytes),
    ]
    offline_time = _run_step("build_artifacts", ba_cmd)

    # ------------ STEP 2: engine benchmark (online evaluation) ------------
    bench_zids_py = TOOLS_DIR / "bench_zids.py"
    engine_csv = outdir / "bench_engine.csv"
    engine_time = 0.0
    if bench_zids_py.exists():
        bz_cmd = [
            sys.executable,
            str(bench_zids_py),
            "--dataset", str(dataset),
            "--idmap", str(idmap_path),
            "--engine", args.engine_module,
            "--engine-init-file", str(engine_init_file),
            "--repeat", str(args.engine_repeat),
            "--warmup", str(args.engine_warmup),
            "--export", str(engine_csv),
        ]
        engine_time = _run_step("bench_zids_engine", bz_cmd)
    else:
        print(f"[benchmark] WARNING: {bench_zids_py} not found, skipping engine benchmark",
              file=sys.stderr)

    # ------------ STEP 3: regex baseline benchmark (optional) ------------
    regex_csv = outdir / "bench_regex.csv"
    regex_time = 0.0
    if args.with_regex_baseline:
        if bench_zids_py.exists():
            rz_cmd = [
                sys.executable,
                str(bench_zids_py),
                "--dataset", str(dataset),
                "--idmap", str(idmap_path),
                "--easylist", str(easylist),
                "--repeat", str(args.regex_repeat),
                "--warmup", str(args.regex_warmup),
                "--export", str(regex_csv),
            ]
            regex_time = _run_step("bench_zids_regex", rz_cmd)
        else:
            print(f"[benchmark] WARNING: {bench_zids_py} not found, cannot run regex baseline",
                  file=sys.stderr)

    # ------------ STEP 4: OT benchmark ------------
    bench_ot_py = TOOLS_DIR / "bench_ot.py"
    ot_time = 0.0
    if bench_ot_py.exists():
        if args.ot_urls:
            ot_urls = Path(args.ot_urls).resolve()
        else:
            ot_urls = outdir / "bench_ot_urls.txt"
            max_urls = None if args.ot_max_urls <= 0 else args.ot_max_urls
            ot_urls = _auto_urls_from_dataset(dataset, ot_urls, max_urls)

        ot_cmd = [
            sys.executable,
            str(bench_ot_py),
            "--engine", args.engine_module,
            "--engine-init-file", str(engine_init_file),
            "--urls", str(ot_urls),
            "--repeats", str(args.ot_repeats),
            "--warmup", str(args.ot_warmup),
        ]
        ot_time = _run_step("bench_ot", ot_cmd)
    else:
        print(f"[benchmark] WARNING: {bench_ot_py} not found, skipping OT benchmark",
              file=sys.stderr)

    total_online = engine_time + regex_time + ot_time
    total_all = idmap_time + offline_time + total_online

    print("========== PIPELINE SUMMARY ==========")
    print(f"ID map export time      : {idmap_time:.3f}s")
    print(f"Offline build_artifacts : {offline_time:.3f}s")
    print(f"Engine benchmark time   : {engine_time:.3f}s")
    if args.with_regex_baseline:
        print(f"Regex baseline time     : {regex_time:.3f}s")
    print(f"OT benchmark time       : {ot_time:.3f}s")
    print("--------------------------------------")
    print(f"Total online (engine+regex+OT): {total_online:.3f}s")
    print(f"Total pipeline (offline+online): {total_all:.3f}s")

    # summary.json
    summary: Dict[str, Any] = {
        "idmap_time_s": idmap_time,
        "offline_build_time_s": offline_time,
        "engine_bench_time_s": engine_time,
        "regex_bench_time_s": regex_time,
        "ot_bench_time_s": ot_time,
        "total_online_time_s": total_online,
        "total_pipeline_time_s": total_all,
        "paths": {
            "easylist": str(easylist),
            "dataset": str(dataset),
            "engine_init_file": str(engine_init_file),
            "outdir": str(outdir),
            "artifacts_outdir": str(artifacts_outdir),
            "idmap": str(idmap_path),
            "engine_csv": str(engine_csv),
            "regex_csv": str(regex_csv),
        },
    }
    import json
    summary_path = outdir / "pipeline_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[benchmark] summary written to {summary_path}")


if __name__ == "__main__":
    main()
