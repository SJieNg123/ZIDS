# src/server/io/rule_loader.py
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional, Iterable
import os

from src.server.offline.rules_to_dfa.snort_parser import parse_snort_file, ParseConfig
from src.server.offline.rules_to_dfa.chain_rules import RuleSpec
from src.server.offline.rules_to_dfa.regex_to_dfa import RegexFlags

@dataclass(frozen=True)
class LoaderConfig:
    combine_contents: bool = False
    content_gap_max: int = 512
    default_dotall: bool = True

def _load_regex_txt(path: str, *, ignore_case_default=False, anchored=False, dotall=True) -> List[RuleSpec]:
    specs: List[RuleSpec] = []
    with open(path, "rb") as f:
        for ln, raw in enumerate(f, 1):
            s = raw.decode("utf-8", errors="ignore").strip()
            if not s or s.startswith("#"):
                continue
            # 行格式支援： "pattern" 或 "aid:123 |pattern|"（簡單拓展，沒有就自動分配）
            aid = None
            if s.startswith("aid:"):
                try:
                    head, rest = s.split(None, 1)
                except ValueError:
                    raise ValueError(f"{path}:{ln}: expected 'aid:<int> <pattern>'")
                aid = int(head.split(":",1)[1])
                s = rest
            flags = RegexFlags(ignore_case=ignore_case_default, dotall=dotall, anchored=anchored)
            specs.append(RuleSpec(pattern=s, attack_id=(aid or 0), flags=flags))
    # 把 0 的 attack_id 用遞增填上（和 snort_parser 一致的策略）
    next_id = 10_000
    out: List[RuleSpec] = []
    for r in specs:
        if r.attack_id <= 0:
            out.append(RuleSpec(r.pattern, next_id, r.flags))
            next_id += 1
        else:
            out.append(r)
    return out

def load_rules(paths: Iterable[str], cfg: Optional[LoaderConfig] = None) -> List[RuleSpec]:
    """
    支援多檔案來源：*.rules (Snort/Suricata) 與 *.txt（純 regex 行）。
    回傳 RuleSpec[]（OR 集合）。
    """
    cfg = cfg or LoaderConfig()
    all_specs: List[RuleSpec] = []
    for p in paths:
        ext = os.path.splitext(p)[1].lower()
        if ext in (".rules", ".snort", ".suricata"):
            scfg = ParseConfig(
                combine_contents=cfg.combine_contents,
                content_gap_max=cfg.content_gap_max,
                default_dotall=cfg.default_dotall,
            )
            all_specs.extend(parse_snort_file(p, cfg=scfg))
        elif ext in (".txt", ".re", ".regex"):
            all_specs.extend(_load_regex_txt(p, ignore_case_default=False, anchored=False, dotall=cfg.default_dotall))
        else:
            raise ValueError(f"unsupported rule file type: {p}")
    return all_specs
