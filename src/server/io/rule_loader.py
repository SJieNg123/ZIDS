# src/server/io/rule_loader.py
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable, List

# EasyList 解析器與偵測（單一真相來源）
from src.server.io.easylist_loader import parse_easylist, is_abp_file  # 需存在

# === RuleSpec 型別 ===
# TODO: 如果你的 RuleSpec 在別處，改這行 import 即可。
try:
    # 你專案裡已經在離線管線用這個型別；調整為實際路徑
    from src.server.offline.rules_to_dfa.rule_spec import RuleSpec  # type: ignore
except Exception:
    # 後備：最小可用結構，與離線管線常用欄位對齊
    @dataclass
    class RuleSpec:  # type: ignore
        pattern: str             # 轉好的 regex（含錨點）
        ignore_case: bool = False
        dotall: bool = False
        anchored: bool = False
        action: str = "BLOCK"    # "BLOCK" 或 "ALLOW"
        label: str | None = None # 可選：規則標籤/來源

# ===================== 公開設定 =====================

@dataclass
class LoadRulesConfig:
    """
    規則載入行為設定。不要把 Snort 的垃圾放回來。
    """
    default_dotall: bool = False          # 每條 regex 預設 DOTALL（ABP 通常不需要）
    default_ignore_case: bool = True      # URL 規則幾乎都大小寫不敏感（host 一定不敏感）
    anchored: bool = False                # 純 regex 檔案是否自動錨到 ^...$（預設否）

# ===================== 入口 =====================

def load_rules(paths: Iterable[str], cfg: LoadRulesConfig | None = None) -> List[RuleSpec]:
    """
    讀一組路徑，輸出 RuleSpec[]。
    - EasyList / ABP：自動偵測，交給 parse_easylist()
    - 純 regex：每行一條，支援空行/註解，走 _load_regex_txt()
    """
    if cfg is None:
        cfg = LoadRulesConfig()

    all_specs: List[RuleSpec] = []
    for p in paths:
        ext = os.path.splitext(p)[1].lower()
        if is_abp_file(p):
            # ABP / EasyList
            specs = parse_easylist(p, default_case_insensitive=cfg.default_ignore_case)
            # 解析器已把 $script/$domain/@@ 等語義摺進 pattern 與 action
            all_specs.extend(specs)
        elif ext in (".txt", ".re", ".regex"):
            # 每行一條 regex 的純文本
            specs = _load_regex_txt(
                p,
                ignore_case_default=cfg.default_ignore_case,
                anchored=cfg.anchored,
                dotall=cfg.default_dotall,
            )
            all_specs.extend(specs)
        else:
            raise ValueError(f"unsupported rule file type (Snort removed): {p}")

    if not all_specs:
        raise ValueError("no rules loaded (check inputs)")

    return all_specs

# ===================== 幫手 =====================

def _load_regex_txt(
    path: str,
    *,
    ignore_case_default: bool = False,
    anchored: bool = False,
    dotall: bool = False,
) -> List[RuleSpec]:
    """
    載入「每行一條 regex」的簡單檔案。
    支援：
      - 空行、'#' 開頭註解
      - 前綴 'label:'（可選）用於標籤，例如 'aid:123 | ^/ads/.*\\.js$'
      - 內嵌錨點/旗標請自行在 pattern 寫清楚；這裡不魔改字串
    """
    specs: List[RuleSpec] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            label: str | None = None
            pattern = line

            # 粗糙但好用的 label 語法： "aid:xxx | <regex>" 或 "label:xxx | <regex>"
            if "|" in line:
                left, right = line.split("|", 1)
                left = left.strip()
                right = right.strip()
                if left.lower().startswith(("aid:", "label:")):
                    label = left.split(":", 1)[1].strip() or None
                    pattern = right

            if anchored:
                # 只在沒有明確錨點時加；別硬把已經錨了的二次包起來
                if not pattern.startswith("^"):
                    pattern = "^" + pattern
                if not pattern.endswith("$"):
                    pattern = pattern + "$"

            spec = RuleSpec(
                pattern=pattern,
                ignore_case=ignore_case_default,
                dotall=dotall,
                anchored=anchored,
                action="BLOCK",
                label=label or f"{os.path.basename(path)}:{lineno}",
            )
            specs.append(spec)

    return specs