# src/server/offline/dfa_combiner.py
from __future__ import annotations
from typing import Iterable, Optional, Dict, List, Tuple, Any
from concurrent.futures import ProcessPoolExecutor

from src.common.odfa.matrix import ODFA
from src.server.offline.rules_to_dfa.chain_rules import (
    RuleSpec,
    compile_regex_to_dfa,
    RegexFlags,
    _union_dfas,            # 聯集多條 DFA（帶 attack_id tag）
    minimize_tagged_dfa,    # 可選最小化（保留 tags）
    tagged_dfa_to_odfa,     # 轉成 ODFA（含 aggregate 策略）
    TaggedDFA,              # 具 tag 的 DFA 結構
)

# ---- helpers (top-level, 可被 multiprocessing pickle) ----
def _coerce_flags(v: Any) -> int:
    if isinstance(v, int):
        return v
    try:
        w = getattr(v, "value", None)
        return int(w) if isinstance(w, int) else int(v)
    except Exception:
        return 0

def _compile_one_for_mp(args: Tuple[str, int, int, bool]) -> Tuple[object, int]:
    """
    worker：在子程序內把單條 regex 轉成 DFA，回傳 (dfa_obj, attack_id)
    注意：這要求 DFA 物件可被 pickle（多數純 Python 結構都可以）。
    """
    pat, flags, aid, minimize = args
    d = compile_regex_to_dfa(pat, flags=flags, minimize=minimize)
    return d, int(aid)

# ---- main API ----
def rules_to_odfa_and_dfa_trans(
    rules: Iterable[RuleSpec],
    *,
    minimize: bool = True,
    aggregate: str = "min",                 # or "bitmask16"
    id_to_bit: Optional[Dict[int, int]] = None,
    compile_workers: int = 0,               # **新增**：>1 則啟用多程序平行編譯
) -> Tuple[ODFA, List[Dict[int, int]]]:
    """
    將多條規則合成單一 ODFA，並同時回傳對應的 DFA 轉移表 (state -> {byte -> next_state})。
    這份 DFA 轉移表可直接提供給 char_grouping 產生 RowAlphabet。
    - compile_workers: 0/1 = 單執行緒；>1 = 用 ProcessPoolExecutor 平行編譯 regex→DFA。
                       若因為物件不可 picklable 失敗會自動回退到單執行緒。
    """
    rule_list = list(rules)
    if not rule_list:
        td = _union_dfas([])  # 會回傳單一非接受起始態
        odfa = tagged_dfa_to_odfa(td, aggregate=aggregate, id_to_bit=id_to_bit)
        return odfa, td.trans

    # ---- 編譯規則：可平行 ----
    compiled: List[Tuple[object, int]] = []
    use_mp = isinstance(compile_workers, int) and compile_workers > 1 and len(rule_list) > 1

    if use_mp:
        try:
            # 先把 RuleSpec 轉成可序列化的 (pattern, flags, aid, minimize)
            tasks: List[Tuple[str, int, int, bool]] = []
            for r in rule_list:
                r.sanity_check()
                flags = _coerce_flags(getattr(r, "flags", 0))
                tasks.append((str(r.pattern), flags, int(getattr(r, "attack_id", 0)), True))

            # Windows 下 spawn，務必確保 worker 在模組頂層（已保證）
            chunksize = max(1, len(tasks) // (compile_workers * 4) or 1)
            with ProcessPoolExecutor(max_workers=compile_workers) as ex:
                for d, aid in ex.map(_compile_one_for_mp, tasks, chunksize=chunksize):
                    compiled.append((d, aid))
        except Exception as e:
            print(f"[dfa_combiner][warn] parallel compile failed ({e}); falling back to single-thread.", flush=True)
            compiled.clear()
            use_mp = False  # 回退

    if not use_mp:
        for r in rule_list:
            r.sanity_check()
            d = compile_regex_to_dfa(r.pattern, flags=r.flags, minimize=True)
            compiled.append((d, r.attack_id))

    # ---- 聯集 +（選擇性）最小化（保留 tags）----
    td: TaggedDFA = _union_dfas(compiled)
    if minimize:
        td = minimize_tagged_dfa(td)

    # ---- 轉 ODFA（選擇 attack_id 聚合策略）----
    odfa: ODFA = tagged_dfa_to_odfa(td, aggregate=aggregate, id_to_bit=id_to_bit)

    # ---- 回傳 DFA 轉移表供後續 char_grouping 使用 ----
    dfa_trans: List[Dict[int, int]] = td.trans

    # ---- 觀察資訊（行級 AID 數量）----
    nz = 0
    rows = getattr(odfa, "rows", []) or []
    for i, row in enumerate(rows):
        for name in ("attack_id", "aid", "accept_id", "rule_id"):
            if hasattr(row, name):
                try:
                    if int(getattr(row, name) or 0) > 0:
                        nz += 1
                        break
                except Exception:
                    pass
    accept_vec = None
    for name in ("accept_ids", "row_aids", "aid_by_state", "accept_map", "accepting"):
        v = getattr(odfa, name, None)
        if isinstance(v, (list, tuple)) and len(v) == getattr(odfa, "num_states", 0):
            accept_vec = v
            break
    if accept_vec is not None:
        nz2 = sum(1 for x in accept_vec if (isinstance(x, int) and x > 0))
        print(f"[combiner] ODFA rows with row-level AID: {nz}; vector:{nz2}", flush=True)
    else:
        print(f"[combiner] ODFA rows with row-level AID: {nz}; vector:None", flush=True)

    return odfa, dfa_trans


# 舊介面：保留相容性（若只要 ODFA）
def rules_to_odfa(
    rules: Iterable[RuleSpec],
    *,
    minimize: bool = True,
    aggregate: str = "min",
    id_to_bit: Optional[Dict[int, int]] = None,
    compile_workers: int = 0,   # **新增**：沿用到主要實作
) -> ODFA:
    odfa, _ = rules_to_odfa_and_dfa_trans(
        rules,
        minimize=minimize,
        aggregate=aggregate,
        id_to_bit=id_to_bit,
        compile_workers=compile_workers,
    )
    return odfa