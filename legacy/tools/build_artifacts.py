# tools/build_artifacts.py
from __future__ import annotations
import argparse, sys, inspect, time, re, hmac, hashlib, json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Tuple, List, Dict

# ============================ 基本工具 ============================

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

def _die(msg: str, code: int = 2) -> None:
    print(f"[error] {msg}", file=sys.stderr, flush=True)
    sys.exit(code)

def _import(mod: str) -> Any:
    import importlib
    try:
        return importlib.import_module(mod)
    except Exception as e:
        _die(f"cannot import module '{mod}': {e}")

def _pick(funcs: List[Tuple[str, str]]) -> Callable[..., Any]:
    last_err: Exception | None = None
    for mod, fn in funcs:
        try:
            m = _import(mod)
            if hasattr(m, fn):
                return getattr(m, fn)
        except Exception as e:
            last_err = e
            continue
    names = [f"{m}.{f}" for m, f in funcs]
    _die(f"no suitable function found among: {', '.join(names)}{f' (last err: {last_err})' if last_err else ''}")

def _call_flex(fn: Callable[..., Any], *args, **kwargs) -> Any:
    sig = inspect.signature(fn)
    ba_kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}
    bound_pos: List[Any] = []
    i = 0
    for p in sig.parameters.values():
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD):
            if i < len(args):
                bound_pos.append(args[i]); i += 1
            else:
                break
        else:
            break
    return fn(*bound_pos, **ba_kwargs)

def _coerce_int(x, default=0) -> int:
    try:
        return int(x)
    except Exception:
        v = getattr(x, "value", None)
        try:
            return int(v)
        except Exception:
            return default

def _count_states_from_dfa_trans(dfa_trans) -> int:
    if isinstance(dfa_trans, (list, tuple)):
        return len(dfa_trans)
    if isinstance(dfa_trans, dict):
        for k in ("rows", "states", "table"):
            v = dfa_trans.get(k) if isinstance(dfa_trans, dict) else None
            if isinstance(v, (list, tuple)):
                return len(v)
    return 0

# ============================ 規則清理/規範化 ============================

def _write_abp_clean_copy(src: Path) -> Path:
    """
    產生去 header/註解 的清單副本，只用這份來載入。
    """
    dst = Path("out") / (src.stem + ".clean.txt")
    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open("r", encoding="utf-8", errors="ignore") as fin, dst.open("w", encoding="utf-8") as fout:
        for raw in fin:
            s = raw.strip()
            if not s:                 # 空行
                continue
            if s.startswith("!"):     # 註解
                continue
            if s.startswith("[" ):    # header: [Adblock Plus 2.0]
                continue
            if not raw.endswith("\n"):
                raw += "\n"           # 重要：確保結尾換行，不讓最後一條被吞
            fout.write(raw)
    return dst

_SANITIZE_REPLACEMENTS = [
    (re.compile(r"\(\?:", re.M), "("),
    (re.compile(r"\(\?P<[^>]+>", re.M), "("),
    (re.compile(r"\(\?[aiLmsux-]*\)", re.M), ""),
    (re.compile(r"\(\?[aiLmsux-]*:", re.M), "("),
]
def _sanitize_pattern_for_dfa(p: str) -> str:
    s = p
    for rx, rep in _SANITIZE_REPLACEMENTS:
        s = rx.sub(rep, s)
    return s

@dataclass
class RuleLite:
    pattern: str
    flags: int = 0
    attack_id: int = 0
    action: str = "BLOCK"
    label: str | None = None
    ignore_case: bool = False
    dotall: bool = False
    anchored: bool = False
    def sanity_check(self) -> None:
        if not isinstance(self.pattern, str):
            self.pattern = str(self.pattern)
        # flags 規整
        if not isinstance(self.flags, int):
            v = getattr(self.flags, "value", None)
            try:
                self.flags = int(v) if isinstance(v, int) else int(self.flags)
            except Exception:
                self.flags = 0
        if self.ignore_case:
            self.flags |= re.IGNORECASE
        if self.dotall:
            self.flags |= re.DOTALL
        if self.action not in ("BLOCK", "ALLOW"):
            self.action = "BLOCK"
        try:
            self.attack_id = int(self.attack_id)
        except Exception:
            self.attack_id = 0
        self.pattern = _sanitize_pattern_for_dfa(self.pattern)

def _sanitize_specs_for_dfa(specs: List[Any]) -> List[RuleLite]:
    out: List[RuleLite] = []
    for i, s in enumerate(specs):
        raw_flags = getattr(s, "flags", 0)
        flags = raw_flags if isinstance(raw_flags, int) else _coerce_int(raw_flags, 0)
        if getattr(s, "ignore_case", False):
            flags |= re.IGNORECASE
        if getattr(s, "dotall", False):
            flags |= re.DOTALL
        rl = RuleLite(
            pattern=_sanitize_pattern_for_dfa(getattr(s, "pattern")),
            flags=flags,
            attack_id=i + 1,
            action=str(getattr(s, "action", "BLOCK") or "BLOCK"),
            label=getattr(s, "label", None),
            ignore_case=bool(getattr(s, "ignore_case", False)),
            dotall=bool(getattr(s, "dotall", False)),
            anchored=bool(getattr(s, "anchored", False)),
        )
        rl.sanity_check()
        out.append(rl)
    return out

def _prefilter_specs(specs: List[Any], interval: int = 1000, profile: bool = True) -> List[Any]:
    """
    先試編譯，剔除爛 regex；統計速度；把失敗寫入 out/invalid_rules.txt。
    另外收集粗略 S_total/E_total 與 RAM 估算值（只抓量級，避免驚慌）。
    """
    compile_regex_to_dfa = _pick([
        ("src.server.offline.rules_to_dfa.regex_to_dfa", "compile_regex_to_dfa"),
    ])
    out: List[Any] = []
    bad: List[tuple[int, str, str]] = []

    # 粗估資源
    S_total = 0     # 各單獨 DFA 的狀態數加總（只為估算）
    E_total = 0     # 各單獨 DFA 的邊數加總（只為估算）
    S_max = 0
    worst_pat = None

    def _count_edges_of_row(row) -> int:
        if isinstance(row, dict):
            return len(row)
        edges = getattr(row, "edges", None) or getattr(row, "transitions", None)
        if isinstance(edges, dict):
            return len(edges)
        if isinstance(edges, (list, tuple, set)):
            return len(edges)
        return 0

    total = len(specs)
    print(f"[filter] pre-compiling {total} rules ...", flush=True)
    t0 = time.time()
    for idx, s in enumerate(specs, 1):
        pat_raw = getattr(s, "pattern", "")
        pat = _sanitize_pattern_for_dfa(pat_raw)
        flags = getattr(s, "flags", 0)
        if not flags:
            if getattr(s, "ignore_case", False): flags |= re.IGNORECASE
            if getattr(s, "dotall", False):      flags |= re.DOTALL
        aid = int(getattr(s, "attack_id", idx))
        try:
            dfa = compile_regex_to_dfa(pat, flags=flags, minimize=False)
            out.append(s)

            if profile:
                trans = getattr(dfa, "trans", None)
                if isinstance(trans, (list, tuple)):
                    Si = len(trans)
                    Ei = 0
                    for row in trans:
                        Ei += _count_edges_of_row(row)
                    S_total += Si
                    E_total += Ei
                    if Si > S_max:
                        S_max = Si
                        worst_pat = pat_raw
            del dfa
        except Exception as e:
            bad.append((aid, pat_raw, repr(e)))

        if (idx % interval) == 0 or idx == total:
            dt = time.time() - t0
            rate = idx / dt if dt > 0 else 0.0
            print(f"[filter] {idx}/{total} ok={len(out)} drop={len(bad)} ({rate:.1f}/s)", flush=True)

    if profile and total > 0:
        # 很保守的 64-bit CPython 估算：狀態 ~100B、邊 ~250B（order-of-magnitude only）
        est_bytes = S_total * 100 + E_total * 250
        est_mb = est_bytes / (1024 * 1024)
        # print(f"[profile] S_total={S_total}  E_total={E_total}  worst_S={S_max}", flush=True)
        # if worst_pat:
        #     print(f"[profile] worst pattern example: {worst_pat}", flush=True)
        # print(f"[profile] rough RAM if single-DFAs kept simultaneously ≈ {est_mb:.1f} MB", flush=True)

    if bad:
        log = Path("out/invalid_rules.txt"); log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("w", encoding="utf-8") as f:
            for aid, pat_raw, err in bad:
                f.write(f"{aid}\t{pat_raw}\t{err}\n")
        print(f"[filter] compiled {len(out)}/{total}; skipped {len(bad)} invalid → {log}", flush=True)
    else:
        print(f"[filter] all {total} rules compiled", flush=True)
    if not out: _die("all rules failed to compile; see out/invalid_rules.txt")
    return out

# ============================ AID 抽取/合併 ============================

def _get_attr_or_key(obj, *names):
    for n in names:
        if isinstance(obj, dict) and n in obj: return obj[n]
        if hasattr(obj, n): return getattr(obj, n)
    return None

def _iter_edges_from_dfa_trans(dfa_trans):
    """盡量通用地把 dfa_trans 展平成 (src_state, edge_obj)。"""
    if isinstance(dfa_trans, (list, tuple)):
        for s, row in enumerate(dfa_trans):
            edges = _get_attr_or_key(row, "edges", "transitions", "items", "values")
            if callable(edges):
                try: edges = list(edges())
                except Exception: edges = None
            if edges is None:
                edges = row.values() if isinstance(row, dict) else []
            for e in edges:
                yield s, e
    elif isinstance(dfa_trans, dict):
        rows = _get_attr_or_key(dfa_trans, "rows", "states", "table")
        if isinstance(rows, (list, tuple)):
            for s, row in enumerate(rows):
                es = _get_attr_or_key(row, "edges", "transitions") or []
                for e in es:
                    yield s, e

def _edge_dst(e):
    v = _get_attr_or_key(e, "to", "dst", "next", "next_state")
    return None if v is None else _coerce_int(v, None)

def _edge_aid(e):
    v = _get_attr_or_key(e, "aid", "attack_id", "accept_id", "rule_id")
    iv = _coerce_int(v, 0)
    return iv if iv > 0 else 0

def _infer_state_aids_from_dfa_trans(dfa_trans, num_states: int):
    """掃轉移，把「指向目標狀態的邊上的 AID」當作該目標狀態的 AID。"""
    row_aids = [0] * int(num_states)
    for _src, e in _iter_edges_from_dfa_trans(dfa_trans):
        dst = _edge_dst(e); aid = _edge_aid(e)
        if dst is None: continue
        if 0 <= dst < num_states and aid > 0 and row_aids[dst] == 0:
            row_aids[dst] = aid
    return row_aids

def _extract_state_aids_from_odfa(odfa) -> List[int]:
    n = _coerce_int(getattr(odfa, "num_states", 0), 0)
    if n <= 0: return []
    for name in ("accept_ids", "row_aids", "aid_by_state", "accept_map", "accepting", "accept"):
        v = getattr(odfa, name, None)
        if isinstance(v, (list, tuple)) and len(v) == n:
            arr = [_coerce_int(x, 0) for x in v]
            if any(a > 0 for a in arr): return arr
        if isinstance(v, dict):
            arr = [_coerce_int(v.get(i, 0), 0) for i in range(n)]
            if any(a > 0 for a in arr): return arr
    rows = getattr(odfa, "rows", None)
    if rows and len(rows) == n:
        arr = [0]*n
        for i, row in enumerate(rows):
            for k in ("attack_id","aid","accept_id","rule_id"):
                if hasattr(row, k):
                    iv = _coerce_int(getattr(row, k), 0)
                    if iv > 0: arr[i] = iv; break
        if any(a > 0 for a in arr): return arr
    return [0]*n

def _build_tagged_dfa(specs_clean: List[RuleLite], *, minimize=True):
    ch = _import("src.server.offline.rules_to_dfa.chain_rules")
    compile_regex_to_dfa = getattr(ch, "compile_regex_to_dfa")
    _union_dfas = getattr(ch, "_union_dfas")
    minimize_tagged_dfa = getattr(ch, "minimize_tagged_dfa")
    compiled = []
    for r in specs_clean:
        d = compile_regex_to_dfa(r.pattern, flags=r.flags, minimize=False)
        compiled.append((d, int(r.attack_id)))
    td = _union_dfas(compiled)
    if minimize: td = minimize_tagged_dfa(td)
    return td

def _extract_state_aids_from_tagged_dfa(td) -> List[int]:
    trans = getattr(td, "trans", None)
    n = len(trans) if isinstance(trans, (list, tuple)) else _coerce_int(getattr(td, "num_states", 0), 0)
    out = [0]*n
    for name in ("state_tags","tags_by_state","accept_tags","accept_map","tags"):
        m = getattr(td, name, None)
        if isinstance(m, dict):
            hit = 0
            for s, tags in m.items():
                si = _coerce_int(s, -1)
                if not (0 <= si < n): continue
                lst: List[int] = []
                if isinstance(tags,(set,list,tuple)):
                    lst=[_coerce_int(t,0) for t in tags if _coerce_int(t,0)>0]
                else:
                    ti=_coerce_int(tags,0)
                    if ti>0: lst=[ti]
                if lst:
                    out[si] = min(lst)
                    hit += 1
            if hit: return out
    states = getattr(td, "states", None) or getattr(td, "nodes", None)
    if isinstance(states,(list,tuple)) and len(states)==n:
        for i, st in enumerate(states):
            for k in ("tag","aid","attack_id","accept_id","rule_id"):
                if hasattr(st,k):
                    iv=_coerce_int(getattr(st,k),0)
                    if iv>0: out[i]=iv; break
        if any(a>0 for a in out): return out
    for name in ("tags_of_state","get_tags","get_state_tags"):
        fn = getattr(td,name,None)
        if callable(fn):
            for s in range(n):
                tags = fn(s)
                lst=[]
                if isinstance(tags,(set,list,tuple)):
                    lst=[_coerce_int(t,0) for t in tags if _coerce_int(t,0)>0]
                else:
                    ti=_coerce_int(tags,0)
                    if ti>0: lst=[ti]
                if lst: out[s]=min(lst)
            if any(a>0 for a in out): return out
    return out

def _merge_row_aids(a_odfa: List[int], a_tag: List[int]) -> List[int]:
    n = max(len(a_odfa or []), len(a_tag or []))
    out = [0]*n
    for i in range(n):
        t = a_tag[i] if i < len(a_tag) else 0
        o = a_odfa[i] if i < len(a_odfa) else 0
        out[i] = t or o
    return out

# ============================ RowAlphabet 寫出 ============================

def _write_row_alphabet(outdir: Path, num_rows: int, cols_per_row: List[int], table_bytes: bytes) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "row_alph.json").write_text(
        json.dumps(
            {"num_rows": int(num_rows), "cols_per_row": list(map(int, cols_per_row)), "format": "single8"},
            ensure_ascii=False, indent=2
        ),
        encoding="utf-8"
    )
    (outdir / "row_alph.bin").write_bytes(table_bytes)

def _extract_row_alphabet(ra_ret: Any) -> tuple[List[int], bytes, int]:
    if isinstance(ra_ret, list) and ra_ret and hasattr(ra_ret[0], "byte_to_col"):
        cols_per_row: List[int] = []
        pieces: List[bytes] = []
        for i, row in enumerate(ra_ret):
            btc = list(getattr(row, "byte_to_col"))
            cols = list(getattr(row, "columns"))
            if len(btc) != 256: _die(f"row {i}: byte_to_col length {len(btc)} != 256")
            m = len(cols)
            if m <= 0 or m > 256: _die(f"row {i}: columns count out of range: {m}")
            for v in btc:
                iv = int(v)
                if iv < 0 or iv >= m:
                    _die(f"row {i}: mapping out of range: {iv} (m={m})")
            cols_per_row.append(m)
            pieces.append(bytes(int(v) & 0xFF for v in btc))
        table_bytes = b"".join(pieces)
        return cols_per_row, table_bytes, len(cols_per_row)
    _die("unexpected return from build_row_alphabets_from_dfa_trans")

# ============================ 進度追蹤（hook） ============================

def _install_compile_tracker(interval: int):
    """
    暫時替換 compile_regex_to_dfa 以印出進度；嘗試兩個常見位置。
    回傳 uninstall() 以還原；沒補到就回傳 no-op。
    """
    state = {"n": 0, "t0": time.time()}
    patched: List[tuple[object, str, object]] = []

    def _wrap(orig):
        def _wrapped(*a, **kw):
            state["n"] += 1
            n = state["n"]
            if n == 1 or (interval > 0 and n % interval == 0):
                dt = max(time.time() - state["t0"], 1e-9)
                print(f"[odfa] regex→DFA {n} ({n/dt:.1f}/s)", flush=True)
            return orig(*a, **kw)
        return _wrapped

    def _try_patch(mod_name: str, attr: str = "compile_regex_to_dfa"):
        try:
            mod = _import(mod_name)
            orig = getattr(mod, attr)
            if callable(orig):
                wrapped = _wrap(orig)
                setattr(mod, attr, wrapped)
                patched.append((mod, attr, orig))
        except Exception:
            pass

    _try_patch("src.server.offline.rules_to_dfa.regex_to_dfa")
    _try_patch("src.server.offline.rules_to_dfa.chain_rules")

    def uninstall():
        for mod, attr, orig in patched:
            try: setattr(mod, attr, orig)
            except Exception: pass
    return uninstall if patched else (lambda: None)

# ============================ 主程式 ============================

def main() -> None:
    ap = argparse.ArgumentParser(description="Build GDFA artifacts directly from EasyList (cleaned ABP)")
    ap.add_argument("--easylist", required=True, help="Path to EasyList (.txt/.abp)")
    ap.add_argument("--outdir", default="artifacts", help="Output directory")
    ap.add_argument("--format", choices=["container", "jsonbin"], default="container")
    ap.add_argument("--gzip-header", action="store_true", dest="gzip_header")
    ap.add_argument("--cmax", type=int, default=1)
    ap.add_argument("--aid-bits", type=int, default=16)
    ap.add_argument("--master-key-hex")
    ap.add_argument("--gk-from-master-hex", dest="gk_from_master_hex")
    ap.add_argument("--gk-bytes", type=int, default=32)
    ap.add_argument("--progress-interval", type=int, default=200, help="print every N regex→DFA compiles")
    ap.add_argument("--stats-only", action="store_true",
                    help="只跑到輸出 ODFA/DFA state 數就終止（不產生 gdfa.bin）")
    ap.add_argument("--mp", type=int, default=1, help="Process_workers for regex→DFA compilation (default 1)")

    def _outmax_arg(s: str):
        s = s.strip().lower()
        if s == "auto":
            return "auto"
        try:
            return int(s)
        except Exception:
            raise argparse.ArgumentTypeError("`--outmax` must be an integer or 'auto'")
        
    ap.add_argument("--outmax", type=_outmax_arg, default="auto", help='max groups per row; use "auto" to infer from RowAlphabet')

    args = ap.parse_args()

    # imports / function picks
    rule_loader = _import("src.server.io.rule_loader")
    LoaderConfig = getattr(rule_loader, "LoaderConfig", None) or getattr(rule_loader, "LoadRulesConfig", None)
    load_rules = getattr(rule_loader, "load_rules")

    rules_to_odfa_and_dfa_trans = _pick([
        ("src.server.offline.dfa_combiner", "rules_to_odfa_and_dfa_trans"),
        ("src.server.offline.rules_to_odfa", "rules_to_odfa_and_dfa_trans"),
        ("src.server.offline.rules_to_odfa", "compile_to_odfa_and_trans"),
    ])
    build_row_alph = _pick([
        ("src.server.offline.dfa_optimizer.char_grouping", "build_row_alphabets_from_dfa_trans"),
        ("src.server.offline.dfa_optimizer.alphabet", "build_row_alphabets_from_dfa_trans"),
    ])
    build_gdfa_stream = _pick([
        ("src.server.offline.gdfa_builder", "build_gdfa_stream"),
        ("src.server.offline.gdfa.builder", "build_gdfa_stream"),
    ])
    params_mod = _import("src.common.odfa.params")
    SecurityParams = getattr(params_mod, "SecurityParams")
    SparsityParams = getattr(params_mod, "SparsityParams")
    packager = _import("src.server.offline.export.gdfa_packager")
    write_container = getattr(packager, "write_container", None)
    write_jsonbin  = getattr(packager, "write_jsonbin", None)

    easylist = Path(args.easylist)
    if not easylist.exists():
        _die(f"EasyList not found: {easylist}")

    # 只用清單副本
    cleaned = _write_abp_clean_copy(easylist)
    print(f"[stage] load_rules from {cleaned}", flush=True)
    specs = load_rules([str(cleaned)], LoaderConfig())
    if not specs: _die("no rules loaded (check EasyList)")
    print(f"[stage] loaded {len(specs)} specs", flush=True)

    # 預過濾 + 規範化 + 粗估 S/E
    specs = _prefilter_specs(specs, interval=args.progress_interval, profile=True)
    specs_clean: List[RuleLite] = _sanitize_specs_for_dfa(specs)

    # 編譯進度追蹤（hook 覆蓋）
    uninstall = _install_compile_tracker(args.progress_interval)

    print("[stage] rules → ODFA + DFA transitions ...", flush=True)
    odfa, dfa_trans = _call_flex(
        rules_to_odfa_and_dfa_trans, specs_clean,
        outmax=args.outmax, cmax=args.cmax, aid_bits=args.aid_bits, compile_workers=args.mp
    )
    uninstall()
    print("[stage] ODFA/dfa_trans built", flush=True)

    # ------ States 統計（你要的重點）------
    odfa_states = int(getattr(odfa, "num_states", 0)) or _count_states_from_dfa_trans(dfa_trans)
    dfa_states  = _count_states_from_dfa_trans(dfa_trans)
    print(f"[stats] ODFA states = {odfa_states}", flush=True)
    print(f"[stats] DFA  states = {dfa_states}", flush=True)

    if args.stats_only:
        print("[ok] stats-only mode: stop here (no GDFA packaging).", flush=True)
        return

    # AID 抽取與合併
    ra_odfa = _extract_state_aids_from_odfa(odfa)
    nz_odfa = sum(1 for a in ra_odfa if a > 0)
    print(f"[stage] extracted state AIDs from ODFA: {nz_odfa} accepting states", flush=True)
    try:
        td = _build_tagged_dfa(specs_clean, minimize=True)
        ra_tag = _extract_state_aids_from_tagged_dfa(td)
        nz_tag = sum(1 for a in ra_tag if a > 0)
        print(f"[stage] extracted AIDs from TaggedDFA: {nz_tag} accepting states", flush=True)
    except Exception as e:
        ra_tag = []; nz_tag = 0
        print(f"[warn] failed to extract AIDs from TaggedDFA: {e}", flush=True)
    row_aids = _merge_row_aids(ra_odfa, ra_tag)
    nz = sum(1 for a in row_aids if a > 0)
    print(f"[stage] merged AIDs: {nz} accepting states", flush=True)

    # 若還不足，再用 dfa_trans 反推出目標狀態 AID 補位
    if nz < len(specs_clean):
        try:
            from_trans = _infer_state_aids_from_dfa_trans(dfa_trans, getattr(odfa, "num_states", 0))
            row_aids = [ra if ra > 0 else (from_trans[i] if i < len(from_trans) else 0) for i, ra in enumerate(row_aids)]
            nz = sum(1 for a in row_aids if a > 0)
            print(f"[stage] after dfa_trans inference: {nz} accepting states", flush=True)
        except Exception as e:
            print(f"[warn] dfa_trans inference failed: {e}", flush=True)

    if nz > 0:
        setattr(odfa, "accept_ids", row_aids)

    # RowAlphabet
    print("[stage] DFA transitions → RowAlphabet ...", flush=True)

    # 把 "auto" 轉成很大的 int；函式內部只會拿來當上限比大小
    if args.outmax == "auto":
        _hint_outmax = 2**31 - 1   # 或 10**9，總之給很大即可
    else:
        _hint_outmax = int(args.outmax)

    # 傳 int 進去，避免 'auto' 進函式
    ra_ret = _call_flex(build_row_alph, dfa_trans, outmax=_hint_outmax, cmax=args.cmax)
    cols_per_row, tbl_bytes, num_rows = _extract_row_alphabet(ra_ret)
    print(f"[stage] RowAlphabet ready (rows={len(cols_per_row)})", flush=True)

    # --- Auto outmax from RowAlphabet ---
    # 以每列的非空群組數最大值作為 outmax（論文做法）
    inferred_outmax = max(int(c) for c in cols_per_row) if cols_per_row else 1

    if args.outmax == "auto":
        args.outmax = inferred_outmax
        print(f"[auto] outmax={args.outmax}", flush=True)
    else:
        args.outmax = int(args.outmax)  # 正常化，後面 SparsityParams 要用到

    # Security params / sparsity
    k_bits = int(args.gk_bytes) * 8
    sec = SecurityParams(k_bits=k_bits, kprime_bits=k_bits, kappa=128, alphabet_size=256)
    spa = SparsityParams(outmax=args.outmax, cmax=args.cmax)
    print(f"[stage] SecurityParams: k_bits={k_bits} (k_bytes={k_bits//8})", flush=True)

    # pad_seed：與線上 engine 一致（master key -> GK(row) -> seed_from_gk）
    from src.common.odfa.seed_rules import seed_from_gk
    def _make_pad_seed_fn_from_master(master_hex: str, *, gk_bytes: int = 32, row_endian: str = "little"):
        mk = bytes.fromhex(master_hex)
        def rb(row: int) -> bytes:
            return int(row).to_bytes(4, "little" if row_endian=="little" else "big", signed=False)
        def derive_gk(row: int) -> bytes:
            base = hmac.new(mk, b"ZIDS|GK|row" + rb(row), hashlib.sha256).digest()
            if gk_bytes <= len(base): return base[:gk_bytes]
            out = bytearray(); ctr = 0
            while len(out) < gk_bytes:
                out.extend(hmac.new(mk, b"ZIDS|GK|row" + rb(row) + bytes([ctr]), hashlib.sha256).digest()); ctr += 1
            return bytes(out[:gk_bytes])
        def pad_seed_fn(new_row: int, col: int, k_bytes: int) -> bytes:
            return seed_from_gk(derive_gk(new_row), new_row, col, k_bytes)
        return pad_seed_fn

    pad_seed_fn = None
    master_hex = args.gk_from_master_hex or args.master_key_hex
    if master_hex:
        pad_seed_fn = _make_pad_seed_fn_from_master(master_hex, gk_bytes=args.gk_bytes, row_endian="little")

    # GDFA stream
    print("[stage] ODFA → GDFA stream ...", flush=True)
    stream = _call_flex(
        build_gdfa_stream, odfa, sec, spa,
        aid_bits=args.aid_bits,
        pad_seed_fn=pad_seed_fn,
        permute=False,
    )
    print("[stage] GDFA stream ready", flush=True)

    # 將 row_aids 映射到 PER(new_row) 空間並掛回 stream（若 builder 未處理）
    perm = getattr(stream.public, "permutation", None)
    if isinstance(perm, list) and len(perm) == len(row_aids):
        row_aids_per = [row_aids[old] for old in perm]
    else:
        row_aids_per = row_aids
    setattr(stream, "row_aids", row_aids_per)
    nz_per = sum(1 for a in row_aids_per if a > 0)
    print(f"[stage] attached row_aids to stream (PER): {nz_per} nonzero", flush=True)

    # 輸出 RowAlphabet 檔案
    print("[stage] write row_alphabet ...", flush=True)
    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    _write_row_alphabet(outdir, getattr(stream.public, "num_states", num_rows), cols_per_row, tbl_bytes)

    # 打包
    if args.format == "container":
        if write_container is None:
            _die("export.gdfa_packager.write_container not found; try --format jsonbin")
        out_path = outdir / "gdfa.bin"
        print(f"[stage] write container → {out_path}", flush=True)

        # 向下相容：有的版本支援 row_aids，有的沒有
        sig = inspect.signature(write_container)
        params = list(sig.parameters.keys())
        if len(params) >= 4 or 'row_aids' in params:
            write_container(str(out_path), stream.public, stream.rows, getattr(stream, "row_aids", None))
        else:
            write_container(str(out_path), stream.public, stream.rows)

        print(f"[write] {out_path}", flush=True)
    else:
        if write_jsonbin is None:
            _die("export.gdfa_packager.write_jsonbin not found")
        print("[stage] write jsonbin files ...", flush=True)

        sig = inspect.signature(write_jsonbin)
        kwargs: Dict[str, Any] = {}
        if 'gzip_header' in sig.parameters:
            kwargs['gzip_header'] = args.gzip_header
        if 'row_aids' in sig.parameters:
            kwargs['row_aids'] = getattr(stream, "row_aids", None)

        write_jsonbin(str(outdir), stream.public, stream.rows, **kwargs)
        print(f"[write] {outdir/'rows.bin'}, {outdir/'header.json'}{'.gz' if args.gzip_header else ''}", flush=True)

    print(f"[ok] artifacts built under: {outdir}", flush=True)

if __name__ == "__main__":
    main()