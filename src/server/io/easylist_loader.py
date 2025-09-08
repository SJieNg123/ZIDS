# -*- coding: utf-8 -*-
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List, Iterable

# 近似 ABP 的 ^（分隔符）
SEPARATOR_CLASS = r"[^A-Za-z0-9_\-\.%]"

@dataclass
class ELRule:
    pattern: str     # 转换后的正则
    label: str       # 原行文本
    is_regex: bool   # 是否 /.../ 规则

def _abp_to_regex(line: str) -> str:
    s = line.strip()
    # /.../ 规则：拒绝 PCRE 的后顾/反向引用等非正则构造
    if len(s) >= 2 and s[0] == '/' and s[-1] == '/':
        body = s[1:-1]
        if re.search(r"\(\?[!<=>]", body) or r"\K" in body:
            raise ValueError("unsupported PCRE constructs in /.../ rule")
        return body

    # 去掉 $options
    if '$' in s:
        s = s.split('$', 1)[0]

    anchor_start = s.startswith('|') and not s.startswith('||')
    anchor_end   = s.endswith('|')
    if anchor_start: s = s[1:]
    if anchor_end:   s = s[:-1]

    prefix = ""
    if s.startswith('||'):
        s = s[2:]
        # scheme://[sub.]domain
        prefix = r"^(?:[a-zA-Z][a-zA-Z0-9+\-.]*:)?//(?:[^/]*\.)?"

    buf = []
    for c in s:
        if c == '*':
            buf.append('.*')
        elif c == '.':
            buf.append(r'\.')
        elif c == '^':
            buf.append(SEPARATOR_CLASS)
        elif c in '?+()[]{}|$':
            buf.append('\\' + c)
        else:
            buf.append(re.escape(c))
    body = ''.join(buf)
    if anchor_start:
        body = '^' + body
    if anchor_end:
        body = body + '$'
    return prefix + body

def parse_easylist(lines: Iterable[str], max_rules: int | None = None) -> List[ELRule]:
    rules: List[ELRule] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith('!'):
            continue
        if line.startswith('@@'):          # 白名单：MVP 先忽略
            continue
        if '##' in line or '#@#' in line:  # 化妆规则：忽略
            continue
        try:
            if line.startswith('/') and line.endswith('/'):
                pat = _abp_to_regex(line)
                rules.append(ELRule(pattern=pat, label=line, is_regex=True))
            else:
                pat = _abp_to_regex(line.lower())
                rules.append(ELRule(pattern=pat, label=line, is_regex=False))
        except ValueError:
            # 不支持的直接跳过
            continue
        if max_rules and len(rules) >= max_rules:
            break
    return rules