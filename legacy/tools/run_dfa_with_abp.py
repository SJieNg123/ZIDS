# tools/run_dfa_with_abp.py
from __future__ import annotations
import argparse, json, re, sys, importlib
from pathlib import Path
from typing import List, Tuple, Any, Dict
from src.common.urlnorm import canonicalize

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from src.common.abp_canonicalize import canonicalize_for_abp
except Exception:
    def canonicalize_for_abp(req_url: str, doc_url: str, typ: str) -> str:
        sep = "⟨SEP⟩"
        host_doc = doc_url.split("://", 1)[-1].split("/", 1)[0]
        host_req = req_url.split("://", 1)[-1].split("/", 1)[0]
        path_req = req_url.split("://", 1)[-1].split("/", 1)[1] if "/" in req_url.split("://", 1)[-1] else ""
        return f"ST{host_doc}{sep}⟨DOM⟩{host_req}{sep}{sep}{path_req or ''}"

def _normalize_action(s: str) -> str:
    s = (s or "").strip().upper()
    return "ALLOW" if s == "ALLOW" else ("BLOCK" if s == "BLOCK" else "BLOCK")

def load_id_to_action_from_file(path: str | Path) -> Dict[str, str]:
    text = Path(path).read_text(encoding="utf-8-sig")
    obj  = json.loads(text)
    out: Dict[str, str] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out[str(k)] = _normalize_action(v if isinstance(v, str) else str(v))
    else:
        raise ValueError("id_to_action.json must be a JSON object")
    return out

def decide_from_rule_ids(rule_ids: List[int], idmap: Dict[str, str]) -> Tuple[str, List[int]]:
    uniq = sorted(set(int(x) for x in rule_ids))
    known = [x for x in uniq if str(x) in idmap]
    if any(idmap[str(x)] == "ALLOW" for x in known):
        return "ALLOW", known
    if any(idmap[str(x)] == "BLOCK" for x in known):
        return "BLOCK", known
    return "NOMATCH", []

def _get_loader():
    try:
        import src.server.io.rule_loader as rl
        LoaderCfg = getattr(rl, "LoadRulesConfig", None) or getattr(rl, "LoaderConfig", None)
        if LoaderCfg is None or not hasattr(rl, "load_rules"):
            raise RuntimeError("rule_loader missing LoadRulesConfig/load_rules")
        return rl.load_rules, LoaderCfg
    except Exception as e:
        raise SystemExit(f"[error] cannot import rule_loader: {e}")

def compile_rules_to_regex(easylist_path: str) -> List[Tuple[re.Pattern, int]]:
    load_rules, LoaderCfg = _get_loader()
    specs = load_rules([easylist_path], LoaderCfg())
    compiled: List[Tuple[re.Pattern, int]] = []
    for i, s in enumerate(specs, 1):  # 1-based IDs
        flags = 0
        if getattr(s, "ignore_case", False): flags |= re.IGNORECASE
        if getattr(s, "dotall", False):      flags |= re.DOTALL
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

def _normalize_engine_result(res: Any) -> tuple[List[int], tuple[int, int] | None]:
    if isinstance(res, tuple) and len(res) == 2 and all(isinstance(x, (int, bool)) for x in res):
        return [], (int(res[0]), int(res[1]))
    if isinstance(res, (list, set, tuple)) and all(isinstance(x, int) for x in res):
        return [int(x) for x in res], None
    if isinstance(res, int):
        return [int(res)], None
    if isinstance(res, dict):
        if {"allow_bit", "block_bit"} <= set(res.keys()):
            return [], (int(res["allow_bit"]), int(res["block_bit"]))
        for k in ("rule_ids", "ids", "matches"):
            v = res.get(k)
            if isinstance(v, (list, set, tuple)) and all(isinstance(x, int) for x in v):
                return [int(x) for x in v], None
        if "rule_id" in res and isinstance(res["rule_id"], int):
            return [int(res["rule_id"])], None
    if hasattr(res, "allow_bit") or hasattr(res, "block_bit"):
        return [], (int(getattr(res, "allow_bit", 0)), int(getattr(res, "block_bit", 0)))
    for k in ("rule_ids", "ids", "matches"):
        if hasattr(res, k):
            seq = getattr(res, k)
            if isinstance(seq, (list, set, tuple)) and all(isinstance(x, int) for x in seq):
                return [int(x) for x in seq], None
    raise RuntimeError(f"cannot normalize engine result type={type(res)}: {res!r}")

def _load_init_cfg(engine_init: str | None, engine_init_file: str | None) -> dict | None:
    if engine_init_file:
        text = Path(engine_init_file).read_text(encoding="utf-8-sig")
        return json.loads(text)
    if engine_init:
        p = Path(engine_init)
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8-sig"))
        return json.loads(engine_init)
    return None

def _maybe_bootstrap_engine(mod, cfg: dict | None):
    if not cfg: return
    if hasattr(mod, "init_for_cli"): mod.init_for_cli(cfg); return  # type: ignore[attr-defined]
    if hasattr(mod, "bootstrap_for_cli"): mod.bootstrap_for_cli(cfg); return  # type: ignore[attr-defined]
    if hasattr(mod, "set_engine") and "engine" in cfg: mod.set_engine(cfg["engine"]); return  # type: ignore[attr-defined]
    raise SystemExit("engine module has no init_for_cli()/bootstrap_for_cli(), and no 'engine' provided.")

def evaluate_rule_ids_via_engine(payload: str, engine_module: str, cfg: dict | None) -> tuple[List[int], tuple[int, int] | None]:
    mod = importlib.import_module(engine_module)
    _maybe_bootstrap_engine(mod, cfg)
    for fname in ("eval_rule_ids", "evaluate_rule_ids", "evaluate", "run", "query"):
        if hasattr(mod, fname):
            res = getattr(mod, fname)(payload)
            return _normalize_engine_result(res)
    raise AttributeError(f"engine module '{mod.__name__}' has none of eval_rule_ids/evaluate_rule_ids/evaluate/run/query")

def _make_payload(args) -> str:
    """
    將 --one 轉成 payload。
    - feed=url  → 只用 request URL；沒 scheme 就補 https://
    - feed=abp  → 使用 ABP 規則的 canonical payload（req|doc|type）
    """
    s = (args.one or "").strip()
    feed = getattr(args, "feed", None) or "abp"

    if feed == "url":
        # 只取第一段當作 request URL（就算使用者誤放了 req|doc 也忽略後面）
        req = s.split("|", 1)[0].strip()
        # 沒有 schema 則補 https://
        import re
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', req):
            req = "https://" + req
        return req

    # feed=abp（或預設）
    parts = s.split("|")
    req = (parts[0] if len(parts) > 0 else "").strip()
    doc = (parts[1] if len(parts) > 1 else "").strip()
    typ = (parts[2] if len(parts) > 2 else "other").strip() or "other"
    from src.common.abp_canonicalize import canonicalize_for_abp
    return canonicalize_for_abp(req, doc, typ)


def main():
    ap = argparse.ArgumentParser(description="Run ABP payload via regex or real engine, then decide by id_to_action.json")
    ap.add_argument("--idmap", required=True, help="out/id_to_action.json")
    ap.add_argument("--one", required=True, help="req_url|doc_url|type")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--easylist", help="Path to EasyList (regex mode)")
    g.add_argument("--engine", help="Engine module, e.g. src.client.online.engine")
    ap.add_argument("--engine-init", help="JSON string or path to JSON (engine bootstrap)", default=None)
    ap.add_argument("--engine-init-file", help="Path to JSON file (engine bootstrap)", default=None)
    ap.add_argument("--print-payload", action="store_true", dest="print_payload")
    ap.add_argument("--explain", action="store_true", help="Print id->action for each hit to stderr")
    ap.add_argument("--feed", choices=["abp","url"], default="abp")
    args = ap.parse_args()

    id_to_action = load_id_to_action_from_file(args.idmap)
    payload = _make_payload(args)

    if args.print_payload:
        print("[PAYLOAD]", payload if isinstance(payload, str) else payload.decode("utf-8","ignore"), flush=True)

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
        hits: List[int] = []
    else:
        verdict, hits = decide_from_rule_ids(rule_ids, id_to_action)

    if args.explain and hits:
        import sys as _sys
        pairs = [(h, id_to_action.get(str(h), "UNKNOWN")) for h in hits]
        print(f"[explain] hits -> {pairs}", file=_sys.stderr, flush=True)

    print(json.dumps({"verdict": verdict, "hits": hits, "num_hits": len(hits)}, ensure_ascii=False))

if __name__ == "__main__":
    main()