# src/server/offline/dfa_optimizer/sparsity_analysis.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Tuple

from src.common.odfa.matrix import ODFA

@dataclass(frozen=True)
class SparsityReport:
    num_states: int
    outdeg_hist: Dict[int, int]   # deg -> count of rows
    max_outdeg: int
    avg_outdeg: float
    p95_outdeg: int
    suggest_outmax: int
    suggest_cmax: int
    hot_rows: List[Tuple[int, int]]  # [(row_id, outdeg)] sorted desc

def _percentile_from_hist(hist: Dict[int, int], q: float) -> int:
    assert 0.0 <= q <= 1.0
    items = sorted(hist.items())  # (deg, count)
    total = sum(c for _, c in items)
    if total == 0:
        return 0
    target = q * total
    acc = 0.0
    for deg, cnt in items:
        acc += cnt
        if acc >= target:
            return deg
    return items[-1][0]

def analyze_odfa_sparsity(odfa: ODFA, topk: int = 20) -> SparsityReport:
    """
    對 ODFA 做列外度（out-degree）統計，產出 outmax/cmax 建議。
    論文設定下 cmax 建議 = 1（每個位元組在該列只屬於一個群）。
    """
    num_states = odfa.num_states
    hist: Dict[int, int] = {}
    hot: List[Tuple[int, int]] = []
    total_deg = 0
    max_deg = 0

    for row_id, row in enumerate(odfa.rows):
        deg = len(row.edges)
        total_deg += deg
        max_deg = max(max_deg, deg)
        hist[deg] = hist.get(deg, 0) + 1
        hot.append((row_id, deg))

    hot.sort(key=lambda x: (-x[1], x[0]))
    hot = hot[:max(0, topk)]

    avg = (total_deg / num_states) if num_states > 0 else 0.0
    p95 = _percentile_from_hist(hist, 0.95)

    # 嚴謹復現：建議 outmax 用 max outdegree，以避免任何語意合併
    suggest_outmax = max_deg
    suggest_cmax = 1

    return SparsityReport(
        num_states=num_states,
        outdeg_hist=dict(sorted(hist.items())),
        max_outdeg=max_deg,
        avg_outdeg=avg,
        p95_outdeg=p95,
        suggest_outmax=suggest_outmax,
        suggest_cmax=suggest_cmax,
        hot_rows=hot,
    )

# 簡單 CLI
if __name__ == "__main__":
    import json
    from src.scripts.build_gdfa_offline import load_odfa_json  # 只借用 loader
    import argparse

    ap = argparse.ArgumentParser(description="Analyze ODFA sparsity")
    ap.add_argument("--odfa-json", required=True)
    args = ap.parse_args()

    odfa = load_odfa_json(args.odfa_json)
    rep = analyze_odfa_sparsity(odfa)
    print(json.dumps({
        "num_states": rep.num_states,
        "outdeg_hist": rep.outdeg_hist,
        "max_outdeg": rep.max_outdeg,
        "avg_outdeg": rep.avg_outdeg,
        "p95_outdeg": rep.p95_outdeg,
        "suggest_outmax": rep.suggest_outmax,
        "suggest_cmax": rep.suggest_cmax,
        "hot_rows": rep.hot_rows,
    }, indent=2, sort_keys=True))
