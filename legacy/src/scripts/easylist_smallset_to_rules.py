# src/scripts/easylist_smallset_to_rules.py
from __future__ import annotations
import os, re, json, argparse
from urllib.parse import urlparse

def esc(s: str) -> str:
    return re.escape(s)

def path_frag(u) -> str:
    p = u.path or "/"
    if p.endswith("/"):
        p = p[:-1]
    seg = p.rsplit("/", 1)[-1]
    return seg or "/"

def rule_from_item(item: dict, base_aid: int) -> tuple[int, str]:
    """
    將 tests.json 的一筆轉為 (aid, regex)
    策略（簡化、為了先跑得動）：
      - domain_anchor：匹配 Host 領域即可
      - scheme_anchor：匹配 Host 並帶一個 path 片段
      - substring    ：直接匹配該子字串（做 regex escape）
    注意：離線建置時請加 --default-dotall 讓 '.' 跨行。
    """
    typ = item["type"]
    url = item["positive_url"]
    u = urlparse(url)
    host = u.netloc or "example.com"
    frag = path_frag(u)
    # 預設讓大小寫不敏感：在建置時用 --default-dotall + regex_to_dfa 的 ignore_case 選項可再擴
    if typ == "domain_anchor":
        regex = rf"Host:\s*([^.]+\.)*{esc(host)}"
    elif typ == "scheme_anchor":
        # Host + 路徑片段（跨行用 .*, 建置時請 --default-dotall）
        if frag and frag != "/":
            regex = rf"Host:\s*{esc(host)}.*{esc(frag)}"
        else:
            regex = rf"Host:\s*{esc(host)}"
    elif typ == "substring":
        # 直接匹配子字串（範圍寬，足以驗證管線）
        raw = item["rule"]
        # 從 rule 字串取出片段；fallback 用 path 片段
        sub = raw.strip("|")
        sub = sub.replace("^", "/")
        sub = sub.strip()
        if not sub or sub.startswith(("||","|http://","|https://","/")):
            sub = frag or "ads"
        regex = esc(sub)
    else:
        # 不支援的類型，退化成匹配 host
        regex = rf"Host:\s*{esc(host)}"

    aid = base_aid
    return aid, regex

def main():
    ap = argparse.ArgumentParser(description="Convert smallset tests.json to ZIDS regex rules")
    ap.add_argument("--tests", required=True, help="Path to dist/urltests/tests.json")
    ap.add_argument("--out", default="rules/easylist_small.rules", help="Output rules file")
    ap.add_argument("--base-aid", type=int, default=5000, help="Starting AID")
    args = ap.parse_args()

    with open(args.tests, "rb") as f:
        items = json.load(f)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    lines = []
    aid = args.base_aid
    for it in items:
        a, rx = rule_from_item(it, aid)
        lines.append(f"aid:{a} {rx}")
        aid += 1

    with open(args.out, "wb") as f:
        f.write(("\n".join(lines) + "\n").encode("utf-8"))

    print(f"[OK] wrote {len(lines)} rules to {args.out}")

if __name__ == "__main__":
    main()