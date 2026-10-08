# src/scripts/easylist_make_smallset.py
from __future__ import annotations
import os, re, json, random, argparse
from urllib.parse import urlparse

# ------------------ 基本 ABP 規則處理（簡化版） ------------------

class Rule:
    def __init__(self, raw: str):
        self.raw = raw
        self.is_exception = raw.startswith("@@")
        self.has_opts = "$" in raw
        self.is_regex = (len(raw) >= 2 and raw[0] == "/" and raw.rfind("/") > 0 and raw[1] != "/")
        self.type = self._classify()

    def _classify(self) -> str:
        s = self.raw
        if self.is_exception or self.has_opts or self.is_regex:
            return "unsupported"
        if s.startswith("||"):
            return "domain_anchor"   # 例如 "||example.com^"
        if s.startswith("|http://") or s.startswith("|https://"):
            return "scheme_anchor"   # 例如 "|https://cdn.example.com/ads/"
        if s.startswith("|") or s.endswith("|"):
            return "anchored"        # 超過最小範圍，先跳過
        # 剩下視為「純字串子路徑」類，如 "ads.js"
        return "substring"

    def cleaned(self) -> str:
        # 去掉 ABP 轉義：目前只處理 ^ （分隔符）→ "/"，其他保持
        s = self.raw
        s = s.replace("^", "/")
        return s

# ------------------ URL 生成邏輯（最小可用） ------------------

def pos_neg_for_rule(r: Rule) -> tuple[str, str] | None:
    """
    給一條 Rule（已篩選簡單類型），生成：
      - 正例 URL：應該匹配該規則
      - 反例 URL：應該不匹配該規則
    """
    s = r.cleaned()

    if r.type == "domain_anchor":
        # 例： "||example.com^" → 匹配 example.com 及其子域名
        # 生成正例： https://sub.example.com/ads.js
        # 反例： https://examplex.com/
        m = re.match(r"^\|\|([A-Za-z0-9.-]+)", s)
        if not m:
            return None
        dom = m.group(1).strip(".")
        if not dom:
            return None
        pos = f"https://sub.{dom}/ads.js"
        neg = f"https://{dom}x/"
        return pos, neg

    if r.type == "scheme_anchor":
        # 例： "|https://cdn.example.com/ads/" → 以此為前綴
        # 正例： 就用它 + "x"
        # 反例： 換個主機名
        if s.startswith("|"):
            s2 = s[1:]
        else:
            s2 = s
        # 把 ^ 改過後，確保結尾合法
        if not s2.endswith("/"):
            s2 = s2 + "/"
        pos = s2 + "x"
        try:
            u = urlparse(s2)
            host = u.netloc or "example.com"
            neg = f"{u.scheme}://not-{host}/"
        except Exception:
            neg = "https://not-example.com/"
        return pos, neg

    if r.type == "substring":
        # 例： "ads.js" → 任何含此片段的 URL
        frag = s.strip("|")
        if not frag:
            return None
        pos = f"https://example.com/path/{frag}"
        # 反例：避免誤匹配（例如把 "." 換成 "_" 或在中間插入字元）
        neg = f"https://example.com/path/{frag.replace('.', '_') + 'x'}"
        return pos, neg

    # 其他類型先不處理
    return None

def to_http_request_bytes(url: str) -> bytes:
    """
    把 URL 轉成最小的 HTTP/1.1 GET request（供你的 ZIDS engine 使用）
    GET /path HTTP/1.1
    Host: example.com
    User-Agent: zids-test

    """
    u = urlparse(url)
    host = u.netloc or "example.com"
    path = u.path or "/"
    if u.query:
        path = path + "?" + u.query
    req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: zids-test\r\n\r\n"
    return req.encode("utf-8", errors="ignore")

# ------------------ 主流程 ------------------

def load_rules(path: str) -> list[Rule]:
    out: list[Rule] = []
    with open(path, "rb") as f:
        for raw in f:
            s = raw.decode("utf-8", errors="ignore").strip()
            if not s or s.startswith("!") or s.startswith("[Adblock"):
                continue
            r = Rule(s)
            out.append(r)
    return out

def sample_simple_rules(rules: list[Rule], k: int = 10) -> list[Rule]:
    # 只挑「容易轉 URL」的類型
    simple = [r for r in rules if r.type in ("domain_anchor","scheme_anchor","substring")]
    random.shuffle(simple)
    return simple[:k]

def main():
    ap = argparse.ArgumentParser(description="Make a tiny URL test set from easylist.txt")
    ap.add_argument("--easylist", required=True, help="Path to easylist.txt")
    ap.add_argument("--outdir", default="dist/urltests", help="Output directory")
    ap.add_argument("--count", type=int, default=10, help="How many rules to sample")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    reqdir = os.path.join(args.outdir, "requests")
    os.makedirs(reqdir, exist_ok=True)

    rules = load_rules(args.easylist)
    picked = sample_simple_rules(rules, args.count)

    tests = []
    for idx, r in enumerate(picked, 1):
        pair = pos_neg_for_rule(r)
        if not pair:
            continue
        pos, neg = pair
        # 輸出 HTTP 請求檔
        pos_req = to_http_request_bytes(pos)
        neg_req = to_http_request_bytes(neg)
        pos_path = os.path.join(reqdir, f"pos_{idx:02d}.req")
        neg_path = os.path.join(reqdir, f"neg_{idx:02d}.req")
        with open(pos_path, "wb") as f: f.write(pos_req)
        with open(neg_path, "wb") as f: f.write(neg_req)

        tests.append({
            "index": idx,
            "rule": r.raw,
            "type": r.type,
            "positive_url": pos,
            "negative_url": neg,
            "positive_req": os.path.relpath(pos_path, args.outdir),
            "negative_req": os.path.relpath(neg_path, args.outdir),
        })

    with open(os.path.join(args.outdir, "tests.json"), "wb") as f:
        f.write(json.dumps(tests, indent=2, ensure_ascii=False).encode("utf-8"))

    print(f"[OK] Generated {len(tests)} tests at {args.outdir}")
    for t in tests:
        print(f"  - #{t['index']:02d} {t['type']:12s} :: {t['positive_url']}")

if __name__ == "__main__":
    main()