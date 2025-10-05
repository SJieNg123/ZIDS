# src/server/io/easylist_loader.py
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Iterable, List
import os

# 你專案內真正的 RuleSpec 位置如果不同，改這個 import
try:
    from src.server.offline.rules_to_dfa.rule_spec import RuleSpec  # type: ignore
except Exception:
    @dataclass
    class RuleSpec:  # 最小備援
        pattern: str
        flags: int = 0
        ignore_case: bool = True
        dotall: bool = False
        anchored: bool = False
        action: str = "BLOCK"  # "BLOCK" / "ALLOW"
        label: str | None = None

HEADER_PAT = re.compile(r"^\s*\[Adblock", re.I)
COMMENT_PAT = re.compile(r"^\s*!", re.I)
BLANK_PAT = re.compile(r"^\s*$")

def is_abp_file(path: str, sniff_lines: int = 32) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".abp":
        return True
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if i >= sniff_lines:
                    break
                s = line.strip()
                if not s:
                    continue
                if s.startswith("[Adblock"):
                    return True
                if s.startswith("!"):   # 註解
                    continue
                if s.startswith("@@") or s.startswith("||") or s.startswith("|") or \
                   "##" in s or "#@#" in s or "$" in s or "##+js" in s:
                    return True
        return False
    except FileNotFoundError:
        raise
    except Exception:
        return False

def _skip_line(line: str) -> bool:
    s = line.strip()
    if not s: return True
    if HEADER_PAT.match(s): return True   # ← 關鍵：header 不是規則
    if COMMENT_PAT.match(s): return True  # 以 "!" 開頭的註解
    if s.startswith("#"): return True     # 額外保險
    return False

# 很簡化的 ABP→regex；你的專案已經有更完整版本就用原來的，這裡只保證 header/註解不會變規則
def _abp_rule_to_regex(s: str) -> tuple[str, int]:
    """
    回傳 (pattern, flags)。僅處理最常見子集：
      - 開頭 '@@' → whitelist（我們在 parse 時設 action=ALLOW）
      - '||example.com^' → domain 匹配
      - 其他行：直接當 substring；做 re.escape，再用 '.*' 連接
    """
    s = s.strip()
    flags = re.IGNORECASE
    if s.startswith("@@"):
        s = s[2:].lstrip()
    # 簡單處理 '||host^'
    if s.startswith("||"):
        body = s[2:]
        # 去尾端修飾
        body = body.split("$", 1)[0]
        body = body.rstrip("^")
        host = re.escape(body)
        # 簡單允許子網域
        pat = rf".*://([^.]+\.)*{host}(/|$)"
        return pat, flags
    # 萬用：當 substring
    core = s.split("$", 1)[0]
    pat = re.escape(core)
    return rf".*{pat}.*", flags

def parse_easylist(path: str, *, default_case_insensitive: bool = True) -> List[RuleSpec]:
    specs: List[RuleSpec] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if _skip_line(line):
                continue
            action = "BLOCK"
            if line.startswith("@@"):     # whitelist
                action = "ALLOW"
            # 你的完整轉換器若已有，這裡可以直接呼叫；沒有就用簡版
            pat, flags = _abp_rule_to_regex(line)
            if not default_case_insensitive:
                flags &= ~re.IGNORECASE
            specs.append(RuleSpec(
                pattern=pat,
                flags=flags,
                ignore_case=bool(flags & re.IGNORECASE),
                dotall=False,
                anchored=False,
                action=action,
                label=f"{path}:{lineno}"
            ))
    if not specs:
        raise ValueError(f"no ABP rules parsed from {path}")
    return specs