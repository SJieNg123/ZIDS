# tools/bench_zids.py
from __future__ import annotations
import argparse, sys, time, json, statistics as stats
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.common.abp_canonicalize import canonicalize_for_abp
from src.client.online.abp_decide import load_id_to_action, decide_from_rule_ids
# 借用你已有的工具函式（不會觸發它的 CLI）
from tools.run_dfa_with_abp import (
    evaluate_rule_ids_via_engine,
    compile_rules_to_regex,
    evaluate_rule_ids_by_regex,
    _load_init_cfg,
)

try:
    import psutil
except Exception:
    psutil = None

def _percentile(values, p):
    if not values: return 0.0
    return float(stats.quantiles(values, n=100, method="inclusive")[p-1])

def main():
    ap = argparse.ArgumentParser(description="ZIDS micro-bench: engine vs regex baseline")
    ap.add_argument("--dataset", required=True, help="text file: each line 'req|doc|type'")
    ap.add_argument("--idmap",   required=True, help="out/id_to_action.json")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--easylist", help="regex baseline: path to rules (ABP/txt)")
    g.add_argument("--engine",   help="engine module, e.g. src.client.online.engine")
    ap.add_argument("--engine-init-file", help="engine init JSON", default=None)
    ap.add_argument("--repeat", type=int, default=1, help="repeat per sample for timing")
    ap.add_argument("--warmup", type=int, default=5, help="warm-up samples (ignored in metrics)")
    ap.add_argument("--export",  default="out/bench.csv", help="CSV output path")
    ap.add_argument("--both", action="store_true", help="run both engine and regex to compare")
    args = ap.parse_args()

    rows = [ln.strip() for ln in Path(args.dataset).read_text(encoding="utf-8-sig", errors="ignore").splitlines() if ln.strip()]
    if not rows:
        print("[bench] empty dataset"); sys.exit(2)

    # 載入 id->action
    idmap = load_id_to_action(json.loads(Path(args.idmap).read_text(encoding="utf-8-sig")))
    # baseline
    compiled = None
    if args.easylist or args.both:
        el = args.easylist or ""  # both 模式下也要給 baseline
        if not el:
            print("[bench] --both 需要同時給 --easylist"); sys.exit(2)
        compiled = compile_rules_to_regex(el)

    # engine
    cfg = None
    if args.engine or args.both:
        cfg = _load_init_cfg(None, args.engine_init_file)
        # 提前 bootstrap（避免每次動態載入成本）
        from tools.run_dfa_with_abp import importlib
        mod = importlib.import_module(args.engine or "src.client.online.engine")
        from tools.run_dfa_with_abp import _maybe_bootstrap_engine
        _maybe_bootstrap_engine(mod, cfg)

    # 預先 canonicalize payloads
    payloads = []
    for ln in rows:
        parts = (ln.split("|") + ["", "", "other"])[:3]
        payloads.append(canonicalize_for_abp(parts[0].strip(), parts[1].strip(), parts[2].strip()))

    # 記憶體採樣
    proc = psutil.Process() if psutil else None
    peak_mem = 0

    # 暖身
    for i in range(min(args.warmup, len(payloads))):
        pl = payloads[i]
        if compiled:
            _ = evaluate_rule_ids_by_regex(pl, compiled)
        if cfg:
            _ = evaluate_rule_ids_via_engine(pl, args.engine, cfg)

    # 正式測
    import csv
    outp = Path(args.export); outp.parent.mkdir(parents=True, exist_ok=True)
    fw = outp.open("w", newline="", encoding="utf-8")
    w = csv.writer(fw)
    w.writerow(["idx","bytes","engine_ms","regex_ms","engine_verdict","regex_verdict","agree","engine_hits","regex_hits"])

    t0 = time.perf_counter()
    eng_times, rx_times = [], []
    agree = 0

    for i, pl in enumerate(payloads):
        nbytes = len(pl.encode("utf-8")) if isinstance(pl, str) else len(pl)
        # engine
        eng_hits = []; eng_ms = None; eng_verdict = "N/A"
        if cfg:
            t1 = time.perf_counter()
            for _ in range(args.repeat):
                rule_ids, bits = evaluate_rule_ids_via_engine(pl, args.engine, cfg)
                if bits is not None:
                    allow_bit, block_bit = bits
                    eng_verdict = "ALLOW" if allow_bit else ("BLOCK" if block_bit else "NOMATCH")
                    eng_hits = []
                else:
                    eng_verdict, eng_hits = decide_from_rule_ids(rule_ids, idmap)
            eng_ms = (time.perf_counter() - t1) * 1000.0 / max(1, args.repeat)
            eng_times.append(eng_ms)

        # regex
        rx_hits = []; rx_ms = None; rx_verdict = "N/A"
        if compiled:
            t2 = time.perf_counter()
            for _ in range(args.repeat):
                rids = evaluate_rule_ids_by_regex(pl, compiled)
                rx_verdict, rx_hits = decide_from_rule_ids(rids, idmap)
            rx_ms = (time.perf_counter() - t2) * 1000.0 / max(1, args.repeat)
            rx_times.append(rx_ms)

        # 比對
        is_agree = (eng_verdict == rx_verdict) if (cfg and compiled) else ""
        if is_agree == True: agree += 1

        w.writerow([i, nbytes, f"{eng_ms:.3f}" if eng_ms is not None else "",
                    f"{rx_ms:.3f}" if rx_ms is not None else "",
                    eng_verdict, rx_verdict, is_agree, ";".join(map(str, eng_hits)), ";".join(map(str, rx_hits))])

        if psutil:
            try:
                mi = proc.memory_info()
                # Windows: peak_wset；其他平台：rss 取最大值
                cur_peak = getattr(mi, "peak_wset", 0) or mi.rss
                peak_mem = max(peak_mem, cur_peak)
            except Exception:
                pass

    fw.close()
    total_s = time.perf_counter() - t0
    n = len(payloads)

    def _summ(times):
        if not times: return {}
        arr = sorted(times)
        return {
            "avg": sum(arr)/len(arr),
            "p50": _percentile(arr, 50),
            "p90": _percentile(arr, 90),
            "p99": _percentile(arr, 99),
            "max": max(arr),
        }

    eng = _summ(eng_times); rx = _summ(rx_times)
    if cfg:
        print(f"[engine] n={n}  avg={eng.get('avg',0):.3f}ms  p50={eng.get('p50',0):.3f}  p90={eng.get('p90',0):.3f}  p99={eng.get('p99',0):.3f}  max={eng.get('max',0):.3f}")
        print(f"[engine] throughput ≈ {n/total_s:.1f} req/s")
    if compiled:
        print(f"[regex ] n={n}  avg={rx.get('avg',0):.3f}ms  p50={rx.get('p50',0):.3f}  p90={rx.get('p90',0):.3f}  p99={rx.get('p99',0):.3f}  max={rx.get('max',0):.3f}")
    if cfg and compiled:
        print(f"[agree ] {agree}/{n} ({agree*100.0/n:.1f}%) engine vs regex")
    if psutil:
        print(f"[memory] peak ≈ {peak_mem/1024/1024:.1f} MB (process)")

    print(f"[write ] {outp}")

if __name__ == "__main__":
    main()