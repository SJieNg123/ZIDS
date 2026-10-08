# tools/bench_ot.py
from __future__ import annotations
import argparse, json, sys, time, importlib
from pathlib import Path
from statistics import mean, median

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

def _load_init_cfg(engine_init_file: str) -> dict:
    return json.loads(Path(engine_init_file).read_text(encoding="utf-8-sig"))

def _mk_payload(url: str) -> str:
    # domain-only 規則可直接丟 URL（不加 ABP meta）
    u = url.strip()
    if "://" not in u:
        u = "https://" + u
    return u

def main():
    ap = argparse.ArgumentParser(description="Benchmark ZIDS OT (end-to-end) over a list of URLs")
    ap.add_argument("--engine", default="src.client.online.engine", help="engine module (default: src.client.online.engine)")
    ap.add_argument("--engine-init-file", required=True, help="engine init JSON (OT chooser etc.)")
    ap.add_argument("--urls", help="text file: one URL per line")
    ap.add_argument("--one", help="single URL (overrides --urls if set)")
    ap.add_argument("--repeats", type=int, default=1, help="repeat each URL N times (default: 1)")
    ap.add_argument("--warmup", type=int, default=3, help="warmup evaluations before timing (default: 3)")
    args = ap.parse_args()

    mod = importlib.import_module(args.engine)
    cfg = _load_init_cfg(args.engine_init_file)
    # bootstrap engine
    if hasattr(mod, "init_for_cli"):
        mod.init_for_cli(cfg)
    else:
        raise RuntimeError("engine module has no init_for_cli")

    # build URL list
    urls: list[str] = []
    if args.one:
        urls = [args.one]
    elif args.urls:
        urls = [ln.strip() for ln in Path(args.urls).read_text(encoding="utf-8").splitlines() if ln.strip()]
    else:
        raise SystemExit("provide --one or --urls")

    # warmup
    for _ in range(max(args.warmup, 0)):
        for u in urls[:min(len(urls), 5)]:  # 不用全跑
            payload = _mk_payload(u)
            getattr(mod, "eval_rule_ids")(payload)

    # reset OT stats
    if hasattr(mod, "reset_ot_stats"):
        mod.reset_ot_stats()

    times: list[float] = []
    hits_total = 0

    t_begin = time.perf_counter()
    for u in urls:
        payload = _mk_payload(u)
        for _ in range(max(args.repeats, 1)):
            t0 = time.perf_counter()
            res = getattr(mod, "eval_rule_ids")(payload)
            dt = time.perf_counter() - t0
            times.append(dt)
            # res 是命中 AID 列表（或其他兼容格式）；盡量以 list 處理
            if isinstance(res, int):
                hits_total += int(res != 0)
            elif isinstance(res, (list, tuple, set)):
                hits_total += int(len(res) > 0)
            else:
                # 其它型別略過計數
                pass
    t_end = time.perf_counter()

    # pull OT metrics
    ot = getattr(mod, "get_ot_stats")() if hasattr(mod, "get_ot_stats") else None

    # report
    total = len(times)
    print("=== OT benchmark (end-to-end) ===")
    print(f"urls           : {len(urls)}")
    print(f"repeats/url    : {args.repeats}")
    print(f"evals total    : {total}")
    if total:
        print(f"time total     : {(t_end - t_begin)*1000:.1f} ms")
        print(f"time avg       : {mean(times)*1000:.3f} ms")
        print(f"time p50       : {median(times)*1000:.3f} ms")
        print(f"time min/max   : {min(times)*1000:.3f} / {max(times)*1000:.3f} ms")
    print(f"hits (eval>0)  : {hits_total}")

    if ot:
        up = ot.get("bytes_up", 0)
        down = ot.get("bytes_down", 0)
        choose = ot.get("num_choose", 0)
        print("--- OT I/O ---")
        print(f"choose calls   : {choose}")
        print(f"bytes up       : {up}  ({up/1024:.2f} KB)")
        print(f"bytes down     : {down} ({down/1024:.2f} KB)")
        print(f"OT lat avg     : {ot.get('lat_avg_s',0.0)*1000:.3f} ms")
        print(f"OT lat p50/p95 : {ot.get('lat_p50_s',0.0)*1000:.3f} / {ot.get('lat_p95_s',0.0)*1000:.3f} ms")

if __name__ == "__main__":
    main()