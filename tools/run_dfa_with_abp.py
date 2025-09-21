# tools/run_dfa_with_abp.py
from __future__ import annotations
import argparse, json, re, sys, importlib
from pathlib import Path
from typing import List, Tuple, Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.common.abp_canonicalize import canonicalize_for_abp
from src.client.online.abp_decide import load_id_to_action, decide_from_rule_ids
from src.server.io.rule_loader import load_rules, LoadRulesConfig

# -------- regex 路徑 --------
def compile_rules_to_regex(easylist_path: str) -> List[Tuple[re.Pattern, int]]:
    specs = load_rules([easylist_path], LoadRulesConfig())
    compiled: List[Tuple[re.Pattern, int]] = []
    for i, s in enumerate(specs):
        flags = 0
        if getattr(s, "ignore_case", False):
            flags |= re.IGNORECASE
        if getattr(s, "dotall", False):
            flags |= re.DOTALL
        try:
            rx = re.compile(s.pattern, flags)
        except re.error as e:
            print(f"[skip] regex compile failed: {getattr(s, 'label', f'rule#{i}')}: {e}\npattern={s.pattern}", flush=True)
            continue
        compiled.append((rx, i))
    print(f"[compiled] {len(compiled)} regex from EasyList", flush=True)
    return compiled

def evaluate_rule_ids_by_regex(payload: str, compiled_rules: List[Tuple[re.Pattern, int]]) -> List[int]:
    return [rid for rx, rid in compiled_rules if rx.search(payload)]

# -------- 引擎路徑 --------
def _normalize_engine_result(res: Any) -> tuple[List[int], tuple[int, int] | None]:
    if isinstance(res, tuple) and len(res) == 2 and all(isinstance(x, (int, bool)) for x in res):
        return [], (int(res[0]), int(res[1]))
    if isinstance(res, (list, set, tuple)) and all(isinstance(x, int) for x in res):
        return list(int(x) for x in res), None
    if isinstance(res, int):
        return [int(res)], None
    if isinstance(res, dict):
        if {"allow_bit", "block_bit"} <= set(res.keys()):
            return [], (int(res["allow_bit"]), int(res["block_bit"]))
        for k in ("rule_ids", "ids", "matches"):
            v = res.get(k)
            if isinstance(v, (list, set, tuple)) and all(isinstance(x, int) for x in v):
                return list(int(x) for x in v), None
        if "rule_id" in res and isinstance(res["rule_id"], int):
            return [int(res["rule_id"])], None
    if hasattr(res, "allow_bit") or hasattr(res, "block_bit"):
        return [], (int(getattr(res, "allow_bit", 0)), int(getattr(res, "block_bit", 0)))
    for k in ("rule_ids", "ids", "matches"):
        if hasattr(res, k):
            seq = getattr(res, k)
            if isinstance(seq, (list, set, tuple)) and all(isinstance(x, int) for x in seq):
                return list(int(x) for x in seq), None
    raise RuntimeError(f"cannot normalize engine result type={type(res)}: {res!r}")

def _load_init_cfg(engine_init: str | None, engine_init_file: str | None) -> dict | None:
    if engine_init_file:
        # 支援帶 BOM 的 UTF-8
        text = Path(engine_init_file).read_text(encoding="utf-8-sig")
        return json.loads(text)
    if engine_init:
        p = Path(engine_init)
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8-sig"))
        return json.loads(engine_init)
    return None

def _maybe_bootstrap_engine(mod, cfg: dict | None):
    if not cfg:
        return
    if hasattr(mod, "init_for_cli"):
        mod.init_for_cli(cfg)  # type: ignore[attr-defined]
        return
    if hasattr(mod, "bootstrap_for_cli"):
        mod.bootstrap_for_cli(cfg)  # type: ignore[attr-defined]
        return
    if hasattr(mod, "set_engine") and "engine" in cfg:
        mod.set_engine(cfg["engine"])  # type: ignore[attr-defined]
        return
    raise SystemExit("engine module has no init_for_cli()/bootstrap_for_cli(), and no 'engine' provided.")

def evaluate_rule_ids_via_engine(payload: str, engine_module: str, cfg: dict | None) -> tuple[List[int], tuple[int, int] | None]:
    mod = importlib.import_module(engine_module)
    _maybe_bootstrap_engine(mod, cfg)
    for fname in ("eval_rule_ids", "evaluate_rule_ids", "evaluate", "run", "query"):
        if hasattr(mod, fname):
            res = getattr(mod, fname)(payload)
            return _normalize_engine_result(res)
    raise AttributeError(f"engine module '{mod.__name__}' has none of eval_rule_ids/evaluate_rule_ids/evaluate/run/query")

# -------- main --------
def main():
    ap = argparse.ArgumentParser(description="Run ABP payload via regex or real engine, then decide by id_to_action.json")
    ap.add_argument("--idmap", required=True, help="out/id_to_action.json")
    ap.add_argument("--one", required=True, help="req_url|doc_url|type")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--easylist", help="Path to EasyList (regex mode).")
    g.add_argument("--engine", help="Engine module, e.g. src.client.online.engine")
    ap.add_argument("--engine-init", help="JSON string or path to JSON (engine bootstrap).", default=None)
    ap.add_argument("--engine-init-file", help="Path to JSON file (engine bootstrap).", default=None)
    args = ap.parse_args()

    # 也用 utf-8-sig 讀，避免 idmap 帶 BOM
    id_to_action = load_id_to_action(json.loads(Path(args.idmap).read_text(encoding="utf-8-sig")))

    req, doc, typ = (args.one.split("|") + ["other"])[:3]
    payload = canonicalize_for_abp(req.strip(), doc.strip(), typ.strip())

    if args.easylist:
        compiled = compile_rules_to_regex(args.easylist)
        rule_ids = evaluate_rule_ids_by_regex(payload, compiled)
        bits = None
    else:
        cfg = _load_init_cfg(args.engine_init, args.engine_init_file)
        rule_ids, bits = evaluate_rule_ids_via_engine(payload, args.engine, cfg)

    if bits is not None:
        allow_bit, block_bit = bits
        verdict = "ALLOW" if allow_bit else ("BLOCK" if block_bit else "NOMATCH")
        hits = []
    else:
        verdict, hits = decide_from_rule_ids(rule_ids, id_to_action)

    print(json.dumps({"verdict": verdict, "hits": hits[:16], "num_hits": len(hits)}, ensure_ascii=False))

if __name__ == "__main__":
    main()