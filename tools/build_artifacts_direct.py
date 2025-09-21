# tools/build_artifacts_direct.py
from __future__ import annotations

import argparse
import sys
import inspect
from pathlib import Path
from typing import Any, Callable, Tuple, List

# 讓 src/** 可匯入
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

def _die(msg: str, code: int = 2) -> None:
    print(f"[error] {msg}", file=sys.stderr, flush=True); sys.exit(code)

def _import(mod: str) -> Any:
    import importlib
    try:
        return importlib.import_module(mod)
    except Exception as e:
        _die(f"cannot import module '{mod}': {e}")

def _pick(funcs: list[Tuple[str, str]]) -> Callable[..., Any]:
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
    bound_pos = []
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

# ---- 專案構件 ----
rule_loader = _import("src.server.io.rule_loader")
LoaderConfig = getattr(rule_loader, "LoaderConfig")
load_rules = getattr(rule_loader, "load_rules")

rules_to_odfa_and_dfa_trans = _pick([
    ("src.server.offline.dfa_combiner", "rules_to_odfa_and_dfa_trans"),
    ("src.server.offline.rules_to_odfa", "rules_to_odfa_and_dfa_trans"),
    ("src.server.offline.rules_to_odfa", "compile_to_odfa_and_trans"),
])
compile_regex_to_dfa = _pick([
    ("src.server.offline.rules_to_dfa.regex_to_dfa", "compile_regex_to_dfa"),
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

def _write_row_alphabet(outdir: Path, num_rows: int, cols_per_row: List[int], table_bytes: bytes) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "row_alph.json").write_text(
        __import__("json").dumps(
            {"num_rows": int(num_rows), "cols_per_row": list(map(int, cols_per_row)), "format": "single8"},
            ensure_ascii=False, indent=2
        ),
        encoding="utf-8"
    )
    (outdir / "row_alph.bin").write_bytes(table_bytes)

def _prefilter_specs(specs: List[Any]) -> List[Any]:
    out: List[Any] = []
    bad: List[tuple[int, str, str]] = []
    total = len(specs)
    print(f"[filter] pre-compiling {total} rules ...", flush=True)
    for idx, s in enumerate(specs, 1):
        pat = getattr(s, "pattern", "")
        flags = getattr(s, "flags", None)
        aid = int(getattr(s, "attack_id", -1))
        try:
            compile_regex_to_dfa(pat, flags=flags, minimize=False)  # 型檢查用；快速路徑
            out.append(s)
        except Exception as e:
            bad.append((aid, pat, repr(e)))
        if (idx % 1000) == 0 or idx == total:
            print(f"[filter] {idx}/{total} done (ok={len(out)}, drop={len(bad)})", flush=True)
    if bad:
        log = Path("out/invalid_rules.txt")
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("w", encoding="utf-8") as f:
            for aid, pat, err in bad:
                f.write(f"{aid}\t{pat}\t{err}\n")
        print(f"[filter] compiled {len(out)}/{total}; skipped {len(bad)} invalid → {log}", flush=True)
    else:
        print(f"[filter] all {total} rules compiled", flush=True)
    if not out:
        _die("all rules failed to compile; see out/invalid_rules.txt")
    return out

def main() -> None:
    ap = argparse.ArgumentParser(description="Direct builder: EasyList -> GDFA artifacts (verbose/progress)")
    ap.add_argument("--easylist", required=True, help="Path to EasyList (.txt)")
    ap.add_argument("--outdir", default="artifacts", help="Output directory")
    ap.add_argument("--format", choices=["container", "jsonbin"], default="container")
    ap.add_argument("--gzip-header", action="store_true", dest="gzip_header")
    ap.add_argument("--outmax", type=int, default=128)
    ap.add_argument("--cmax", type=int, default=1)
    ap.add_argument("--aid-bits", type=int, default=16)
    ap.add_argument("--master-key-hex")
    ap.add_argument("--gk-from-master-hex", dest="gk_from_master_hex")
    ap.add_argument("--gk-bytes", type=int, default=32)
    args = ap.parse_args()

    easylist = Path(args.easylist)
    if not easylist.exists():
        _die(f"EasyList not found: {easylist}")

    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)

    print(f"[stage] load_rules from {easylist}", flush=True)
    specs = load_rules([str(easylist)], LoaderConfig())
    if not specs:
        _die("no rules loaded (check EasyList)")
    print(f"[stage] loaded {len(specs)} specs", flush=True)

    specs_ok = _prefilter_specs(specs)

    print("[stage] rules → ODFA + DFA transitions ...", flush=True)
    odfa, dfa_trans = _call_flex(
        rules_to_odfa_and_dfa_trans, specs_ok,
        outmax=args.outmax, cmax=args.cmax, aid_bits=args.aid_bits
    )
    print("[stage] ODFA/dfa_trans built", flush=True)

    print("[stage] DFA transitions → RowAlphabet ...", flush=True)
    ra_ret = _call_flex(build_row_alph, dfa_trans, outmax=args.outmax, cmax=args.cmax)
    if not (isinstance(ra_ret, tuple) and len(ra_ret) == 2):
        _die("unexpected return from build_row_alphabets_from_dfa_trans")
    a, b = ra_ret
    if isinstance(a, (list, tuple)) and isinstance(b, (bytes, bytearray)):
        cols_per_row = list(map(int, a)); tbl_bytes = bytes(b)
    else:
        meta = a
        cols_per_row = list(map(int, getattr(meta, "cols_per_row", [])))
        tbl_bytes = bytes(b)
    print(f"[stage] RowAlphabet ready (rows={len(cols_per_row)})", flush=True)

    print("[stage] ODFA → GDFA stream ...", flush=True)
    sec = SecurityParams(k=args.outmax, kprime=args.outmax, kappa=args.outmax)  # 先用 outmax 餵；實際由模組決定用法
    spa = SparsityParams(outmax=args.outmax, cmax=args.cmax, aid_bits=args.aid_bits)
    gdfa_header, gdfa_stream = _call_flex(
        build_gdfa_stream, odfa, sec, spa,
        gk_from_master_hex=args.gk_from_master_hex,
        master_key_hex=args.master_key_hex,
        gk_bytes=args.gk_bytes
    )
    print("[stage] GDFA stream ready", flush=True)

    print("[stage] write row_alphabet ...", flush=True)
    _write_row_alphabet(outdir, getattr(gdfa_header, "num_states", len(cols_per_row)), cols_per_row, tbl_bytes)

    if args.format == "container":
        if write_container is None:
            _die("export.gdfa_packager.write_container not found; try --format jsonbin")
        out_path = outdir / "gdfa.bin"
        print(f"[stage] write container → {out_path}", flush=True)
        _call_flex(write_container, gdfa_header, gdfa_stream, out_path=str(out_path))
        print(f"[write] {out_path}", flush=True)
    else:
        if write_jsonbin is None:
            _die("export.gdfa_packager.write_jsonbin not found")
        print("[stage] write jsonbin files ...", flush=True)
        _call_flex(write_jsonbin, gdfa_header, gdfa_stream, out_dir=str(outdir), gzip_header=args.gzip_header)
        print(f"[write] {outdir/'rows.bin'}, {outdir/'header.json'}{'.gz' if args.gzip_header else ''}", flush=True)

    print(f"[ok] artifacts built under: {outdir}", flush=True)

if __name__ == "__main__":
    main()