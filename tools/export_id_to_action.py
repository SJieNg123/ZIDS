# tools/export_id_to_action.py
from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path

# 讓 src/** 可被匯入
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.server.io.rule_loader import load_rules, LoadRulesConfig  # type: ignore

def main():
    ap = argparse.ArgumentParser(description="Export rule_id→action map from EasyList (in load order).")
    ap.add_argument("--easylist", required=True, help="Path to EasyList (full .txt).")
    ap.add_argument("--out", default="out/id_to_action.json", help="Output JSON path.")
    args = ap.parse_args()

    specs = load_rules([args.easylist], LoadRulesConfig())
    id_to_action = {str(i): (s.action if getattr(s, "action", None) else "BLOCK") for i, s in enumerate(specs)}

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(id_to_action, f, ensure_ascii=False, indent=2)

    print(f"[exported] {len(id_to_action)} entries → {out_path}")

if __name__ == "__main__":
    main()