# src/server/io/rule_loader.py
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional, Iterable, Any
import os

# 既有型別（你 repo 已有）
from src.server.offline.rules_to_dfa.chain_rules import RuleSpec
from src.server.offline.rules_to_dfa.regex_to_dfa import RegexFlags

# EasyList 解析器（你 repo 已有；不同分支有「吃路徑」或「吃行迭代器」兩種版本）
from src.server.io.easylist_loader import parse_easylist as _parse_easylist

# ---- 相容：離線建置器會匯入這個 ----
@dataclass(frozen=True)
class LoaderConfig:
    combine_contents: bool = False   # Snort 用；EasyList 忽略
    content_gap_max: int = 512       # Snort 用；EasyList 忽略
    default_dotall: bool = False     # URL/ABP 一般不需要 DOTALL
# 舊名相容
LoadRulesConfig = LoaderConfig

def _looks_like_abp(path: str, sniff: int = 32) -> bool:
    """輕量偵測 ABP/EasyList 檔頭。"""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if i >= sniff:
                    break
                s = line.strip()
                if not s:
                    continue
                if s.startswith("[Adblock"):
                    return True
                if s.startswith("! Title:") or s.startswith("! Version:"):
                    return True
                if "Adblock" in s:
                    return True
        return False
    except FileNotFoundError:
        raise
    except Exception:
        return False

# -- 兼容兩種 parse_easylist 介面：優先「吃路徑」，退回「吃檔案物件」 --
def _parse_easylist_flex(path: str) -> List[Any]:
    # 先嘗試當作「路徑」呼叫
    try:
        return _parse_easylist(path)  # type: ignore[arg-type]
    except TypeError:
        # 有些版本吃行迭代器；退回用檔案物件
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return _parse_easylist(f)  # type: ignore[arg-type]

def _load_easylist(path: str) -> List[RuleSpec]:
    """
    把 EasyList 轉 RuleSpec[]；AID=載入序（從 1 開始），確保與 id_to_action.json 對齊。
    允許 parse_easylist 回傳各種結構：我們只取出 `pattern` 與可選 `is_regex`。
    """
    el_rules = _parse_easylist_flex(path)
    specs: List[RuleSpec] = []
    for idx, r in enumerate(el_rules, 1):
        if isinstance(r, str):
            pattern = r
            is_regex = False
        else:
            pattern = getattr(r, "pattern", None) or str(r)
            is_regex = bool(getattr(r, "is_regex", False))
        flags = RegexFlags(ignore_case=(not is_regex), dotall=False, anchored=False)
        specs.append(RuleSpec(pattern=pattern, attack_id=idx, flags=flags))
    return specs

def _load_regex_txt(path: str, *, ignore_case_default: bool, anchored: bool, dotall: bool) -> List[RuleSpec]:
    """每行一條 regex 的純文字檔。"""
    specs: List[RuleSpec] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            pattern = line
            if anchored:
                if not pattern.startswith("^"):
                    pattern = "^" + pattern
                if not pattern.endswith("$"):
                    pattern = pattern + "$"
            flags = RegexFlags(ignore_case=ignore_case_default, dotall=dotall, anchored=anchored)
            specs.append(RuleSpec(pattern=pattern, attack_id=0, flags=flags))
    # 回填 AID（載入序，從 1）
    out: List[RuleSpec] = []
    for i, r in enumerate(specs, 1):
        aid = r.attack_id if r.attack_id > 0 else i
        out.append(RuleSpec(r.pattern, aid, r.flags))
    return out

# def _try_load_snort(path: str, cfg: LoaderConfig) -> List[RuleSpec]:
#     """只有在 snort_parser 存在時才啟用；否則友善退出。"""
#     try:
#         from src.server.offline.rules_to_dfa.snort_parser import parse_snort_file, ParseConfig
#     except Exception:
#         raise SystemExit(
#             f"Snort parser not available but got Snort-like file: {path}. "
#             f"Remove .rules from inputs or restore snort_parser."
#         )
#     scfg = ParseConfig(
#         combine_contents=cfg.combine_contents,
#         content_gap_max=cfg.content_gap_max,
#         default_dotall=cfg.default_dotall,
#     )
#     return parse_snort_file(path, cfg=scfg)

def load_rules(paths: Iterable[str], cfg: Optional[LoaderConfig] = None) -> List[RuleSpec]:
    """
    - EasyList/ABP：自動偵測 → 轉 regex
    - .txt/.re/.regex：每行一條 regex
    - .rules/.snort/.suricata：如果 snort_parser 存在才支援
    """
    cfg = cfg or LoaderConfig()
    all_specs: List[RuleSpec] = []
    for p in paths:
        ext = os.path.splitext(p)[1].lower()
        if _looks_like_abp(p):
            all_specs.extend(_load_easylist(p))
        elif ext in (".txt", ".re", ".regex"):
            all_specs.extend(_load_regex_txt(
                p,
                ignore_case_default=False,
                anchored=False,
                dotall=cfg.default_dotall,
            ))
        # elif ext in (".rules", ".snort", ".suricata"):
        #     all_specs.extend(_try_load_snort(p, cfg))
        else:
            raise ValueError(f"unsupported rule file type: {p}")
    if not all_specs:
        raise ValueError("no rules loaded (check inputs)")
    return all_specs