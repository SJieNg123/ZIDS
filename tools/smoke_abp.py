# tools/smoke_abp.py
from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from typing import List, Tuple

from src.server.io.easylist_loader import parse_easylist, is_abp_file
from src.common.abp_canonicalize import canonicalize_for_abp

@dataclass
class CompiledRule:
    rx: re.Pattern
    action: str   # "ALLOW" or "BLOCK"
    label: str

def load_rules_easylist(path: str, ignore_case_default: bool = True) -> List[CompiledRule]:
    if not is_abp_file(path):
        raise SystemExit(f"{path} doesn't look like an Adblock/EasyList file")
    specs = parse_easylist(path, default_case_insensitive=ignore_case_default)

    compiled: List[CompiledRule] = []
    for s in specs:
        flags = 0
        if s.ignore_case:
            flags |= re.IGNORECASE
        if s.dotall:
            flags |= re.DOTALL
        try:
            rx = re.compile(s.pattern, flags)
        except re.error as e:
            # 不讓一條垃圾規則拖垮整體
            print(f"[skip] regex compile failed: {s.label}: {e}\npattern={s.pattern}", flush=True)
            continue
        compiled.append(CompiledRule(rx=rx, action=s.action, label=s.label or "unnamed"))
    return compiled

def decide_allow_block(payload: str, rules: List[CompiledRule]) -> Tuple[str, List[str]]:
    """
    ABP 優先序：若任何 ALLOW 命中 → ALLOW；否則若任何 BLOCK 命中 → BLOCK；否則 NOMATCH
    備註：這裡用 OR 語義（有命中即成立），與 ABP 的行為一致（不中立序）。
    """
    hits_allow: List[str] = []
    hits_block: List[str] = []
    for r in rules:
        if r.rx.search(payload):
            if r.action == "ALLOW":
                hits_allow.append(r.label)
            else:
                hits_block.append(r.label)
    if hits_allow:
        return "ALLOW", hits_allow
    if hits_block:
        return "BLOCK", hits_block
    return "NOMATCH", []

def main():
    ap = argparse.ArgumentParser(description="Smoke-test ABP matching on canonicalized META+URL string")
    ap.add_argument("--easylist", required=True, help="Path to EasyList file (.txt)")
    ap.add_argument("--input", required=False, help="JSONL of requests: {req_url, doc_url, type}")
    ap.add_argument("--one", required=False, help="Single test: req_url|doc_url|type")
    ap.add_argument("--print-payload", action="store_true", help="Print canonicalized payload for debugging")
    args = ap.parse_args()

    rules = load_rules_easylist(args.easylist)
    print(f"[loaded] {len(rules)} compiled rules", flush=True)

    tests: List[Tuple[str, str, str | None]] = []
    if args.one:
        req, doc, typ = (args.one.split("|") + ["other"])[:3]
        tests.append((req.strip(), doc.strip(), typ.strip()))
    elif args.input:
        with open(args.input, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                obj = json.loads(line)
                tests.append((obj["req_url"], obj["doc_url"], obj.get("type")))
    else:
        raise SystemExit("Provide --one req|doc|type or --input JSONL")

    for (req, doc, typ) in tests:
        payload = canonicalize_for_abp(req_url=req, doc_url=doc, req_type=typ)
        if args.print_payload:
            # 把不可見分隔符顯示成可讀符號
            vis = payload.replace("\x1f", "⟨SEP⟩").replace("\x1e", "⟨DOM⟩")
            print(f"[PAYLOAD] {vis}")

        verdict, labels = decide_allow_block(payload, rules)
        print(json.dumps({
            "req_url": req,
            "doc_url": doc,
            "type": typ,
            "verdict": verdict,
            "hits": labels[:8],  # 打太多沒人在乎
        }, ensure_ascii=False))

if __name__ == "__main__":
    main()