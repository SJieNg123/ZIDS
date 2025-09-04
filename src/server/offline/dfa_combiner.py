# src/server/offline/dfa_combiner.py
from __future__ import annotations
from typing import Iterable, Optional, Dict, List, Tuple

from src.common.odfa.matrix import ODFA
from src.server.offline.rules_to_dfa.chain_rules import (
    RuleSpec,
    compile_regex_to_dfa,
    RegexFlags,
    _union_dfas,            # 聯集多條 DFA（帶 attack_id tag）
    minimize_tagged_dfa,    # 可選最小化（保留 tags）
    tagged_dfa_to_odfa,     # 轉成 ODFA（含 aggregate 策略）
    TaggedDFA,              # 具 tag 的 DFA 結構
)

def rules_to_odfa_and_dfa_trans(
    rules: Iterable[RuleSpec],
    *,
    minimize: bool = True,
    aggregate: str = "min",                 # or "bitmask16"
    id_to_bit: Optional[Dict[int, int]] = None,
) -> Tuple[ODFA, List[Dict[int, int]]]:
    """
    將多條規則合成單一 ODFA，並同時回傳對應的 DFA 轉移表 (state -> {byte -> next_state})。
    這份 DFA 轉移表可直接提供給 char_grouping 產生 RowAlphabet。
    """
    rule_list = list(rules)
    if not rule_list:
        # 空集合：建立一個空機器
        td = _union_dfas([])  # 會回傳單一非接受起始態
        odfa = tagged_dfa_to_odfa(td, aggregate=aggregate, id_to_bit=id_to_bit)
        return odfa, td.trans

    # 個別編成 DFA，並配上各自的 attack_id
    compiled: List[Tuple[object, int]] = []
    for r in rule_list:
        r.sanity_check()
        d = compile_regex_to_dfa(r.pattern, flags=r.flags, minimize=True)
        compiled.append((d, r.attack_id))

    # 聯集 +（選擇性）最小化（保留 tags）
    td: TaggedDFA = _union_dfas(compiled)
    if minimize:
        td = minimize_tagged_dfa(td)

    # 轉 ODFA（選擇 attack_id 聚合策略）
    odfa: ODFA = tagged_dfa_to_odfa(td, aggregate=aggregate, id_to_bit=id_to_bit)

    # 回傳 DFA 轉移表供後續 char_grouping 使用
    dfa_trans: List[Dict[int, int]] = td.trans
    return odfa, dfa_trans


# 舊介面：保留相容性（若只要 ODFA）
def rules_to_odfa(
    rules: Iterable[RuleSpec],
    *,
    minimize: bool = True,
    aggregate: str = "min",
    id_to_bit: Optional[Dict[int, int]] = None,
) -> ODFA:
    odfa, _ = rules_to_odfa_and_dfa_trans(
        rules,
        minimize=minimize,
        aggregate=aggregate,
        id_to_bit=id_to_bit,
    )
    return odfa