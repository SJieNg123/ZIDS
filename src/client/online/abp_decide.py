# src/client/engine/abp_decide.py
from __future__ import annotations
from typing import Iterable, Dict, Tuple, List

def load_id_to_action(json_dict: Dict[str, str]) -> Dict[int, str]:
    """把 JSON 內的字串 key 轉成 int key。"""
    return {int(k): v.upper() for k, v in json_dict.items()}

def decide_from_rule_ids(rule_ids: Iterable[int], id_to_action: Dict[int, str]) -> Tuple[str, List[int]]:
    """
    ABP 優先序：命中任何 ALLOW → ALLOW；否則命中任何 BLOCK → BLOCK；否則 NOMATCH。
    回傳 (verdict, 命中的 rule_id 列表)。
    """
    hits_allow: List[int] = []
    hits_block: List[int] = []
    for rid in rule_ids:
        act = id_to_action.get(int(rid), "BLOCK")
        if act == "ALLOW":
            hits_allow.append(int(rid))
        elif act == "BLOCK":
            hits_block.append(int(rid))
    if hits_allow:
        return "ALLOW", hits_allow
    if hits_block:
        return "BLOCK", hits_block
    return "NOMATCH", []