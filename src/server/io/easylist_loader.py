# src/server/io/easylist_loader.py
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import List, Tuple

# 共用常數（嚴格與 canonicalize 對齊）
from src.common.abp_canonicalize import SEP, DOMSTART, META_SEP, TYPE_CODE

# === RuleSpec 型別 ===
try:
    from src.server.offline.rules_to_dfa.rule_spec import RuleSpec  # type: ignore
except Exception:
    @dataclass
    class RuleSpec:  # type: ignore
        pattern: str
        ignore_case: bool = True
        dotall: bool = False
        anchored: bool = False
        action: str = "BLOCK"      # "BLOCK" or "ALLOW"
        label: str | None = None

# === 對外介面 ===

def is_abp_file(path: str, sniff_lines: int = 16) -> bool:
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
                if s.startswith("! Title:") or s.startswith("! Version:") or "Adblock" in s:
                    return True
        return False
    except FileNotFoundError:
        raise

def parse_easylist(path: str, default_case_insensitive: bool = True) -> List[RuleSpec]:
    specs: List[RuleSpec] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("!"):
                continue
            if "##" in line or "#@#" in line:  # cosmetic 規則：略過
                continue
            try:
                rs = _abp_line_to_rulespecs(
                    line=line,
                    default_case_insensitive=default_case_insensitive,
                    src_label=f"{os.path.basename(path)}:{lineno}",
                )
                specs.extend(rs)
            except _SkipRule:
                continue
    return specs

# === 內部實作 ===

class _SkipRule(Exception):
    pass

_SPECIALS = r".^$+?{}[]()|\\"  # regex 需跳脫

def _esc_lit(ch: str) -> str:
    return ("\\" + ch) if ch in _SPECIALS else ch

def _split_filter_and_modifiers(s: str) -> Tuple[str, dict]:
    if "$" not in s:
        return s, {}
    pat, mod_str = s.split("$", 1)
    mods: dict[str, str | bool] = {}
    for token in mod_str.split(","):
        token = token.strip()
        if not token:
            continue
        if "=" in token:
            k, v = token.split("=", 1)
            mods[k.strip().lower()] = v.strip()
        else:
            mods[token.lower()] = True
    return pat, mods

def _abp_body_to_regex(body: str) -> str:
    r"""
    ABP 主體（不含 @@/$mods）→ regex 片段。
    假設 URL 已 canonicalize 為：DOMSTART + host + SEP + path?query(SEP化)
    支援：
      - * → .*
      - ^ → SEP
      - | 起/訖 → ^ / $
      - ||domain → ^DOMSTART (subdomain.)* domain，之後視情況插入 1 個邊界 SEP
      - /raw-regex/ → 原樣（忽略尾部 flags）
      - path 中的 /?:&= 統一映成 SEP（canonicalize 已把這些變 SEP）
      - 孤兒 '\'（行尾）自動變成 '\\'，避免 re 的 bad escape
    """
    body = body.strip()

    # ==== 1) 原生 ABP 正則：/ ... /flags? ====
    if len(body) >= 2 and body[0] == "/" and body.count("/") >= 2:
        # 找到最後一個分隔符（簡化處理：EasyList 規則結尾基本都是未跳脫的 /）
        last = body.rfind("/")
        if last <= 0:
            pat = body[1:]
        else:
            pat = body[1:last]
        # 若內文以孤兒 '\' 結尾，補上一個 '\'
        if pat.endswith("\\"):
            pat += "\\"
        return pat

    # ==== 2) 非 raw 的 | 錨/|| 網域錨 ====
    anchor_end = body.endswith("|") and not body.endswith(r"\|")
    if anchor_end:
        body = body[:-1]

    def emit_rest(rest: str, out: list[str]) -> None:
        i = 0
        while i < len(rest):
            c = rest[i]
            # ABP 的跳脫：'\x' → 字面 x；孤兒 '\' → '\\'
            if c == "\\":
                if i + 1 < len(rest):
                    out.append(re.escape(rest[i + 1]))
                    i += 2
                    continue
                else:
                    out.append(r"\\")
                    i += 1
                    continue
            if c == "*":
                out.append(".*")
            elif c == "^":
                out.append(re.escape(SEP))
            elif c in "/?:&=":
                out.append(re.escape(SEP))
            elif c == ".":
                out.append(r"\.")
            elif c == "|":
                out.append(r"\|")
            else:
                out.append(_esc_lit(c))
            i += 1

    # '||' 網域錨（優先處理）
    if body.startswith("||"):
        rem = body[2:]
        m = re.match(r"([A-Za-z0-9.-]+)", rem)
        domain = m.group(1) if m else ""
        rest = rem[len(domain):] if m else rem

        out: list[str] = []
        out.append(re.escape(DOMSTART))
        out.append(r"(?:[^" + re.escape(SEP) + r".]*\.)*")
        if domain:
            out.append(re.escape(domain))
        # 若 rest 不以 ABP 分隔符 '^' 開頭，插入 1 個 host/path 邊界 SEP
        if rest and not rest.startswith("^"):
            out.append(re.escape(SEP))
        emit_rest(rest, out)
        if anchor_end:
            out.append("$")
        pat = "".join(out)
        if pat.endswith("\\"):
            pat += "\\"
        return pat

    # 單首錨 '|'
    anchor_start = body.startswith("|")
    if anchor_start:
        body = body[1:]

    out2: list[str] = []
    if anchor_start:
        out2.append("^")
    emit_rest(body, out2)
    if anchor_end:
        out2.append("$")
    pat = "".join(out2)
    if pat.endswith("\\"):
        pat += "\\"
    return pat

def _mods_to_classes_and_domains(mods: dict, default_case_insensitive: bool):
    # type class
    if any(k in TYPE_CODE for k in mods.keys()):
        tset = {TYPE_CODE[k] for k in mods.keys() if k in TYPE_CODE}
        type_class = "[" + "".join(sorted(tset)) + "]"
    else:
        all_types = "".join(sorted(set(TYPE_CODE.values())))
        type_class = "[" + all_types + "]"

    # party class
    if "third-party" in mods:
        party_class = "[T]"
    elif "first-party" in mods:
        party_class = "[F]"
    else:
        party_class = "[FT]"

    # domain lists
    pos_domains: List[str] = []
    neg_domains: List[str] = []
    if "domain" in mods:
        for d in str(mods["domain"]).split("|"):
            d = d.strip().lower()
            if not d:
                continue
            if d.startswith("~"):
                neg_domains.append(d[1:])
            else:
                pos_domains.append(d)

    ignore_case = default_case_insensitive
    if "match-case" in mods:
        ignore_case = False

    return type_class, party_class, pos_domains, neg_domains, ignore_case

def _docdomain_any_regex() -> str:
    return r"[^" + re.escape(SEP) + r"]+"

def _domain_to_alt_regex(domain: str) -> str:
    # 匹配 docdomain 欄位： (subdomain.)*domain
    esc = re.escape(domain)
    return r"(?:[^.\x1f]*\.)*" + esc  # 不吃 SEP 與 dot 以外的 label 分隔

def _build_meta_prefix(type_class: str, party_class: str, docdomain_alt: str | None) -> str:
    docre = _docdomain_any_regex() if docdomain_alt is None else docdomain_alt
    return "^" + type_class + party_class + docre + re.escape(META_SEP)

def _abp_line_to_rulespecs(*, line: str, default_case_insensitive: bool, src_label: str) -> List[RuleSpec]:
    action = "BLOCK"
    s = line
    if s.startswith("@@"):
        action = "ALLOW"
        s = s[2:]

    body, mods = _split_filter_and_modifiers(s)
    url_regex = _abp_body_to_regex(body)
    type_class, party_class, pos_domains, neg_domains, ignore_case = _mods_to_classes_and_domains(
        mods, default_case_insensitive
    )

    rules: List[RuleSpec] = []

    # 正向 domain 白名單（若有）
    if pos_domains:
        alt = "|".join(_domain_to_alt_regex(d) for d in pos_domains)
        meta = _build_meta_prefix(type_class, party_class, "(?:" + alt + ")")
        rules.append(RuleSpec(pattern=meta + url_regex, ignore_case=ignore_case, action=action, label=src_label))
    else:
        meta = _build_meta_prefix(type_class, party_class, None)
        rules.append(RuleSpec(pattern=meta + url_regex, ignore_case=ignore_case, action=action, label=src_label))

    # 負向 domain：對 BLOCK 規則產生 ALLOW 覆蓋
    if action == "BLOCK" and neg_domains:
        for d in neg_domains:
            meta = _build_meta_prefix(type_class, party_class, _domain_to_alt_regex(d))
            rules.append(RuleSpec(pattern=meta + url_regex, ignore_case=ignore_case, action="ALLOW",
                                  label=src_label + " (domain-except)"))

    return rules