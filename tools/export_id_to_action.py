# tools/export_id_to_action.py
from __future__ import annotations
import argparse, json
from pathlib import Path

def main():
    ap = argparse.ArgumentParser(description="Export id->action from ABP file (1-based, @@ => ALLOW).")
    ap.add_argument("--easylist", required=True, help="ABP/EasyList file")
    ap.add_argument("--out", required=True, help="Output JSON path")
    args = ap.parse_args()

    src = Path(args.easylist)
    lines = src.read_text(encoding="utf-8", errors="ignore").splitlines()

    actions = []
    for raw in lines:
        s = raw.strip()
        if not s or s.startswith("!") or s.startswith("["):
            continue
        # 以 ABP 原始語法為準
        act = "ALLOW" if s.startswith("@@") else "BLOCK"
        actions.append(act)

    # 1-based ID 映射
    idmap = {str(i): act for i, act in enumerate(actions, 1)}

    outp = Path(args.out); outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(json.dumps(idmap, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[exported] {len(idmap)} entries → {outp}")

if __name__ == "__main__":
    main()