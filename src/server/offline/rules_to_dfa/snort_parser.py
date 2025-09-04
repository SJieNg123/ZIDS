# src/server/offline/rules_to_dfa/snort_parser.py
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple, Optional, Iterable, Dict
import re

from src.server.offline.rules_to_dfa.chain_rules import RuleSpec
from src.server.offline.rules_to_dfa.regex_to_dfa import RegexFlags

# =========================
# 公用：位元組與正則轉換
# =========================

_REGEX_META = set(r'.^$*+?{}[]\|()')

def _is_printable_ascii(b: int) -> bool:
    return 32 <= b <= 126

def _escape_regex_char(ch: str) -> str:
    return ("\\" + ch) if ch in _REGEX_META else ch

def _bytes_to_regex_literal(bs: bytes, *, prefer_ascii: bool = True) -> str:
    r"""
    把 bytes 轉成 regex 字面值：
      - 可列印 ASCII 且非 regex meta -> 原字元（meta 會跳脫）
      - 其他 -> \xHH
    注意：若之後要做 ignore_case，保留 'A'..'Z'/'a'..'z' 當作字元（不要 \xHH），
          讓我們的 RegexFlags(ignore_case=True) 能在 tokenizer 階段做 ASCII 摺疊。
    """
    out = []
    for b in bs:
        if prefer_ascii and _is_printable_ascii(b):
            ch = chr(b)
            if ch in ('\\',):   # 基本跳脫
                out.append('\\\\')
            elif ch in ('"',):
                out.append('\\"')
            else:
                out.append(_escape_regex_char(ch))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


# =========================
# 解析 content:"..."; 與十六進位塊 |AA BB|
# =========================

_HEX_PAIR = re.compile(r'^[0-9A-Fa-f]{2}$')

def _parse_content_payload(s: str) -> bytes:
    r"""
    解析 Snort content 字串內的 payload：
      - 普通字元
      - 跳脫：\\, \", \n, \r, \t, \xHH
      - 十六進位塊：|AA BB CC|（空白允許；必須為偶數個 hex）
    備註：這個函式只處理 content 字串內容，不含兩側引號。
    """
    out = bytearray()
    i = 0
    L = len(s)
    while i < L:
        ch = s[i]
        if ch == '|':
            # 進入 hex 區塊
            i += 1
            start = i
            block = []
            while i < L and s[i] != '|':
                i += 1
            if i >= L:
                raise ValueError("unterminated hex block in content")
            chunk = s[start:i].strip()
            if chunk:
                parts = [p for p in chunk.replace('\t', ' ').split(' ') if p != ""]
                for p in parts:
                    if not _HEX_PAIR.match(p):
                        raise ValueError(f"invalid hex byte '{p}' in |..| block")
                    block.append(int(p, 16))
            out.extend(block)
            i += 1  # skip closing '|'
            continue

        if ch == '\\':
            i += 1
            if i >= L:
                raise ValueError("dangling backslash in content")
            esc = s[i]
            if esc == 'n':
                out.append(0x0A)
            elif esc == 'r':
                out.append(0x0D)
            elif esc == 't':
                out.append(0x09)
            elif esc == '"':
                out.append(0x22)
            elif esc == '\\':
                out.append(0x5C)
            elif esc == 'x':
                if i + 2 >= L:
                    raise ValueError("incomplete \\xHH in content")
                hh = s[i+1:i+3]
                try:
                    out.append(int(hh, 16))
                except ValueError:
                    raise ValueError(f"invalid hex in \\xHH: {hh}")
                i += 2
            else:
                # 其他字元照字面加入（Snort 對許多跳脫是直通）
                out.append(ord(esc) & 0xFF)
            i += 1
            continue

        # 一般字元
        out.append(ord(ch) & 0xFF)
        i += 1

    return bytes(out)


# =========================
# 規則資料結構（部分）
# =========================

@dataclass
class ParsedRule:
    sid: Optional[int]
    contents: List[Tuple[bytes, bool]]      # (payload, nocase)
    pcres: List[Tuple[str, str]]            # (pattern_without_slashes, flags_str)
    # 可再擴：offset/depth/distance/within 等


_SNORT_OPT_SPLIT = re.compile(r';\s*')  # 分隔 () 內的 options，以 ';' 為界

def _unquote(s: str) -> str:
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s

def _parse_rule_options(opts_str: str) -> ParsedRule:
    """
    解析 (...) 內的 options 子集：
      - content:"..."; [nocase;]  -> (payload, nocase)
      - pcre:"/pat/flags";
      - sid:<int>;
    """
    contents: List[Tuple[bytes, bool]] = []
    pcres: List[Tuple[str, str]] = []
    sid: Optional[int] = None

    # 用一個「最近 content index」機制，讓 'nocase;' 作用在上一個 content
    last_content_idx: Optional[int] = None

    # 以 ';' 分段，但注意 pcre/content 內部也可能有 ';'？（Snort 規則內部通常不會）
    parts = [p.strip() for p in _SNORT_OPT_SPLIT.split(opts_str) if p.strip() != ""]
    for p in parts:
        # 形式如：key:value
        if ':' in p:
            key, val = p.split(':', 1)
            key = key.strip()
            val = val.strip()
            if key == 'content':
                # content:"..."; 允許雙引號內帶 |..|，由 _parse_content_payload 處理
                inner = _unquote(val)
                payload = _parse_content_payload(inner)
                contents.append((payload, False))
                last_content_idx = len(contents) - 1
            elif key == 'pcre':
                # pcre:"/pattern/flags"
                inner = _unquote(val)
                if len(inner) < 2 or inner[0] != '/' or inner.rfind('/') <= 0:
                    raise ValueError("invalid pcre format; expected /pat/flags")
                j = inner.rfind('/')
                pat = inner[1:j]
                flags = inner[j+1:]
                pcres.append((pat, flags))
                last_content_idx = None
            elif key == 'sid':
                try:
                    sid = int(val.strip())
                except ValueError:
                    # 允許 "sid: 123" 與 "sid:123"
                    sid = int(val.strip().split()[0])
                last_content_idx = None
            else:
                # 其他 key 先忽略（offset/depth/distance/within/uricontent/...）
                last_content_idx = None
        else:
            # 無冒號的單字選項
            opt = p
            if opt == 'nocase':
                if last_content_idx is None:
                    # 孤立的 nocase，忽略
                    continue
                pl, _ = contents[last_content_idx]
                contents[last_content_idx] = (pl, True)
            else:
                # 其他單詞選項（rawbytes, fast_pattern 等）先忽略
                pass

    return ParsedRule(sid=sid, contents=contents, pcres=pcres)


# =========================
# 高階 API：Snort 規則 -> RuleSpec 清單
# =========================

@dataclass
class ParseConfig:
    combine_contents: bool = False   # 把同一條規則的多個 content 串成一個正則（用 .{0,gap} 連接）
    content_gap_max: int = 512       # combine 模式下 content 之間允許的最大間隔
    default_dotall: bool = True      # pcre 無 's' 時，是否預設 dotall（與我們引擎默認一致）
    default_attack_id_base: int = 10_000  # 無 sid 時用的起始 attack_id 基數

class SnortParser:
    """
    將 Snort/Suricata 規則（子集）轉成 RuleSpec 清單。
    解析 header 後的 (...) options，支援 content 與 pcre。
    """
    def __init__(self, cfg: Optional[ParseConfig] = None):
        self.cfg = cfg or ParseConfig()
        self._next_attack_id = self.cfg.default_attack_id_base

    def _alloc_attack_id(self) -> int:
        self._next_attack_id += 1
        return self._next_attack_id

    def parse_rule_line(self, line: str) -> List[RuleSpec]:
        """
        解析單行（或已合併成一行）的規則字串。
        回傳該規則等價的 RuleSpec 清單（OR）。
        """
        # 去註解
        line = line.strip()
        if not line or line.startswith('#'):
            return []

        # 找到 options 部分：(...) 最後一組括號
        lpar = line.find('(')
        rpar = line.rfind(')')
        if lpar < 0 or rpar < 0 or rpar <= lpar:
            return []  # 非規則行；忽略

        opts_str = line[lpar+1:rpar].strip()
        parsed = _parse_rule_options(opts_str)

        attack_id = parsed.sid if parsed.sid is not None else self._alloc_attack_id()

        specs: List[RuleSpec] = []

        # 1) pcre
        for pat, flags_s in parsed.pcres:
            f = RegexFlags(
                ignore_case=('i' in flags_s),
                dotall=('s' in flags_s) or self.cfg.default_dotall,
                anchored=('A' in flags_s),
            )
            # 直接用 pcre 的內容（PCRE 語法超出子集不保證完全相容；常見用法足夠）
            specs.append(RuleSpec(pattern=pat, attack_id=attack_id, flags=f))

        # 2) content
        if self.cfg.combine_contents and parsed.contents:
            # 將同一條規則的多個 content 串接為單一 regex（粗糙近似）
            gap = max(0, int(self.cfg.content_gap_max))
            # flags：若任一 content 有 nocase -> ignore_case=True
            any_nocase = any(nc for _, nc in parsed.contents)
            f = RegexFlags(ignore_case=any_nocase, dotall=self.cfg.default_dotall, anchored=False)
            parts = []
            for payload, _nc in parsed.contents:
                parts.append(_bytes_to_regex_literal(payload, prefer_ascii=True))
            pat = (rf"(?:.{0,{gap}})".join(parts)) if len(parts) > 1 else parts[0]
            specs.append(RuleSpec(pattern=pat, attack_id=attack_id, flags=f))
        else:
            # 各 content -> 各自獨立規則（OR）
            for payload, nocase in parsed.contents:
                f = RegexFlags(ignore_case=nocase, dotall=self.cfg.default_dotall, anchored=False)
                pat = _bytes_to_regex_literal(payload, prefer_ascii=True)
                specs.append(RuleSpec(pattern=pat, attack_id=attack_id, flags=f))

        return specs

    def parse_rules_text(self, text: str) -> List[RuleSpec]:
        """
        解析多行文字。簡單的行合併策略：
          - 將以反斜線結尾 '\' 的行與下一行合併
          - 將行內括號未閉合的，持續串接到下一行直到配對
        """
        lines = text.splitlines()
        merged: List[str] = []
        buf = ""
        open_parens = 0

        def flush_buf():
            nonlocal buf, open_parens
            if buf.strip():
                merged.append(buf.strip())
            buf = ""
            open_parens = 0

        for raw in lines:
            s = raw.strip()
            if not s or s.startswith('#'):
                flush_buf();  # 結束前一條
                continue
            # 統一行續接
            if buf:
                buf += " " + s
            else:
                buf = s
            # 更新括號狀態
            open_parens += s.count('(') - s.count(')')
            # 行末續接符
            cont = s.endswith('\\')
            if cont:
                buf = buf[:-1].rstrip()
                continue
            if open_parens <= 0:
                flush_buf()

        if buf.strip():
            merged.append(buf.strip())

        specs: List[RuleSpec] = []
        for m in merged:
            specs.extend(self.parse_rule_line(m))
        return specs


# =========================
# 便利函式：檔案/字串 -> RuleSpec[]
# =========================

def parse_snort_file(path: str, *, cfg: Optional[ParseConfig] = None) -> List[RuleSpec]:
    with open(path, "rb") as f:
        text = f.read().decode("utf-8", errors="ignore")
    return SnortParser(cfg).parse_rules_text(text)


# =========================
# smoke test
# =========================

if __name__ == "__main__":
    sample = r'''
# 簡單範例
alert tcp any any -> any 80 (msg:"HTTP GET"; content:"GET "; nocase; sid:1001;)
alert tcp any any -> any 80 (content:"/admin"; sid:1002;)
alert tcp any any -> any 80 (content:"User-Agent: "; content:"curl/"; nocase; sid:1003;)
alert tcp any any -> any 80 (pcre:"/GET\s+\/login\.php/i"; sid:1004;)
alert tcp any any -> any 80 (content:"A|0d 0a|B"; sid:1005;)
'''
    cfg = ParseConfig(combine_contents=False)
    parser = SnortParser(cfg)
    specs = parser.parse_rules_text(sample)
    for s in specs:
        print(f"- sid/aid={s.attack_id}  flags(i={s.flags.ignore_case}, s={s.flags.dotall}, A={s.flags.anchored})  pat={s.pattern!r}")

    print("\n[combine mode]")
    cfg2 = ParseConfig(combine_contents=True, content_gap_max=256)
    specs2 = SnortParser(cfg2).parse_rules_text(sample)
    for s in specs2:
        print(f"- COMBINED sid/aid={s.attack_id} pat={s.pattern!r}")
