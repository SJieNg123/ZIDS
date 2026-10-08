# src/server/offline/rules_to_dfa/chain_rules.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple, Iterable, Optional, FrozenSet

# 依賴我們剛做好的 regex 編譯器與共用 ODFA 型別
from src.server.offline.rules_to_dfa.regex_to_dfa import (
    compile_regex_to_dfa,
    RegexFlags,
    DFA as SingleDFA,
)
from src.common.odfa.matrix import ODFA, ODFARow, ODFAEdge

ALPHABET = list(range(256))


# =========================
# 使用者規則規格
# =========================

@dataclass(frozen=True)
class RuleSpec:
    """
    一條 ZIDS 規則的最小描述：
      - pattern: byte 級 regex；若你是 content 固定字串，請事先轉成等價正則（例如用 re.escape 或直轉位元組）
      - attack_id: 觸發時輸出的代碼（非 0）
      - flags: 編譯旗標（ignore_case / dotall / anchored）
    """
    pattern: str
    attack_id: int
    flags: RegexFlags = RegexFlags()

    def sanity_check(self) -> None:
        if not isinstance(self.pattern, str) or self.pattern == "":
            raise ValueError("RuleSpec.pattern must be a non-empty string")
        if not isinstance(self.attack_id, int) or self.attack_id <= 0:
            raise ValueError("RuleSpec.attack_id must be a positive integer")


# =========================
# 多 DFA 聯集為單一 DFA（攜帶 tag 集合）
# =========================

@dataclass
class TaggedDFA:
    """
    DFA with per-state tag set (attack_id set).
      - trans[s]: {byte -> t}
      - accept[s]: True/False
      - tags[s]: frozenset of attack_ids (empty if non-accepting)
    """
    start: int
    trans: List[Dict[int, int]]
    accept: Set[int]
    tags: List[FrozenSet[int]]


def _union_dfas(dfas: List[Tuple[SingleDFA, int]]) -> TaggedDFA:
    """
    多 DFA 聯集，並把 (dfa_i 的接受態) 標上對應 attack_id。
    輸入: [(dfa_i, attack_id_i), ...]
    做法: 集合構造（狀態 = 多個 (i, qi) pair 的集合）
    """
    if not dfas:
        # 空集合 -> 單一不可接受的起始狀態
        return TaggedDFA(start=0, trans=[{}], accept=set(), tags=[frozenset()])

    # 起始組合態：所有 DFA 的 start
    start_set: Set[Tuple[int, int]] = set((i, d.start) for i, (d, _) in enumerate(dfas))

    # BFS over subset states
    idx_of: Dict[FrozenSet[Tuple[int, int]], int] = {}
    states: List[Set[Tuple[int, int]]] = []
    trans: List[Dict[int, int]] = []
    accept: Set[int] = set()
    tags: List[FrozenSet[int]] = []

    def _index_of(sset: Set[Tuple[int, int]]) -> int:
        key = frozenset(sset)
        if key in idx_of:
            return idx_of[key]
        idx = len(states)
        idx_of[key] = idx
        states.append(set(sset))
        trans.append({})
        # 決定是否為接受態與其 tag 集合
        tagset: Set[int] = set()
        for (i, qi) in sset:
            d, attack_id = dfas[i]
            if qi in d.accept:
                tagset.add(attack_id)
        if tagset:
            accept.add(idx)
            tags.append(frozenset(tagset))
        else:
            tags.append(frozenset())
        return idx

    start_idx = _index_of(start_set)
    queue = [start_idx]
    seen = {start_idx}

    while queue:
        si = queue.pop(0)
        S = states[si]
        # 對每個 byte 做移動
        for b in ALPHABET:
            T: Set[Tuple[int, int]] = set()
            for (i, qi) in S:
                d, _ = dfas[i]
                t = d.trans[qi].get(b)
                if t is not None:
                    T.add((i, t))
            if not T:
                continue
            ti = _index_of(T)
            trans[si][b] = ti
            if ti not in seen:
                seen.add(ti)
                queue.append(ti)

    return TaggedDFA(start=start_idx, trans=trans, accept=accept, tags=tags)


# =========================
# 以 tag 分群的 Hopcroft 最小化
# =========================

def minimize_tagged_dfa(dfa: TaggedDFA) -> TaggedDFA:
    """
    Hopcroft 最小化，但「初始劃分」以 tag 集合為準：
      - 不接受態：tag = ∅
      - 接受態：依照 tagSet 精確相等才能被合併
    這樣可保證不同 attack_id 集合的狀態不會被錯誤合併。
    """
    n = len(dfa.trans)
    # 初始分割：依 tag 集合劃分
    from collections import defaultdict
    blocks_map: Dict[FrozenSet[int], Set[int]] = defaultdict(set)
    for s in range(n):
        blocks_map[dfa.tags[s]].add(s)
    P: List[Set[int]] = [set(block) for block in blocks_map.values() if block]  # partition
    # 待處理工作集
    W: List[Set[int]] = [set(block) for block in P]

    # 構建逆遷移 (per byte)
    inv: List[Dict[int, Set[int]]] = [dict() for _ in range(256)]
    for s, mp in enumerate(dfa.trans):
        for b, t in mp.items():
            inv[b].setdefault(t, set()).add(s)

    while W:
        Aset = W.pop()
        for b in ALPHABET:
            # X = 所有在 byte b 上可到 Aset 的前驅
            X = set()
            for q in Aset:
                preds = inv[b].get(q)
                if preds:
                    X |= preds
            if not X:
                continue
            newP: List[Set[int]] = []
            for Y in P:
                i1 = Y & X
                i2 = Y - X
                if i1 and i2:
                    newP.extend([i1, i2])
                    if Y in W:
                        W.remove(Y)
                        W.extend([i1, i2])
                    else:
                        # 維持 Hopcroft 的啟發式：加入較小的那塊
                        W.append(i1 if len(i1) <= len(i2) else i2)
                else:
                    newP.append(Y)
            P = newP

    # 映射 old->new
    new_index: Dict[int, int] = {}
    idx = 0
    for block in P:
        if not block:
            continue
        for s in block:
            new_index[s] = idx
        idx += 1

    new_n = idx
    new_trans: List[Dict[int, int]] = [dict() for _ in range(new_n)]
    new_accept: Set[int] = set()
    new_tags: List[FrozenSet[int]] = [frozenset() for _ in range(new_n)]

    for block in P:
        if not block:
            continue
        rep = min(block)
        ni = new_index[rep]
        # tags：整塊相同（按我們的初始分割），取代表的即可
        new_tags[ni] = dfa.tags[rep]
        if new_tags[ni]:
            new_accept.add(ni)
        # 遷移：用代表的遷移
        for b, t in dfa.trans[rep].items():
            new_trans[ni][b] = new_index[t]

    new_start = new_index[dfa.start]
    return TaggedDFA(start=new_start, trans=new_trans, accept=new_accept, tags=new_tags)


# =========================
# TaggedDFA -> ODFA（攻擊代碼聚合）
# =========================

def _aggregate_tagset(tagset: FrozenSet[int], mode: str, *, id_to_bit: Optional[Dict[int, int]] = None) -> int:
    """
    把 {attack_id,...} 聚合成單一整數：
      - mode="min"        : 選最小的 id（簡單、符合 aid_bits 輕鬆）
      - mode="bitmask16"  : 以位元集合編碼（需要 id_to_bit 或 id∈[0..15]）
    """
    if not tagset:
        return 0
    if mode == "min":
        return min(tagset)
    if mode == "bitmask16":
        mask = 0
        if id_to_bit is None:
            # 直接拿 id 當 bit 位置
            for tid in tagset:
                if not (0 <= tid < 16):
                    raise ValueError("bitmask16 mode requires attack_id in [0..15] or provide id_to_bit mapping")
                mask |= (1 << tid)
        else:
            for tid in tagset:
                pos = id_to_bit.get(tid)
                if pos is None or not (0 <= pos < 16):
                    raise ValueError(f"id {tid} not mapped to a 0..15 bit in id_to_bit")
                mask |= (1 << pos)
        return mask
    raise ValueError(f"unknown aggregate mode: {mode}")


def tagged_dfa_to_odfa(
    dfa: TaggedDFA,
    *,
    aggregate: str = "min",
    id_to_bit: Optional[Dict[int, int]] = None,
) -> ODFA:
    """
    產生稀疏 ODFA。
    - aggregate: 當一個狀態有多個 attack_id 時如何聚合（min|bitmask16）
    """
    num_states = len(dfa.trans)
    rows: List[ODFARow] = []
    accepting_map: Dict[int, int] = {}

    for s in range(num_states):
        # 分組 bytes -> next_state
        mp = dfa.trans[s]
        next_to_bytes: Dict[int, List[int]] = {}
        for b, t in mp.items():
            next_to_bytes.setdefault(t, []).append(b)
        # 穩定排序（視覺/重現性）
        edges: List[ODFAEdge] = []
        for gid, (t, blist) in enumerate(sorted(next_to_bytes.items(), key=lambda kv: min(kv[1]))):
            # 攻擊代碼寫在「來源列」上（與我們其餘模組一致）
            aid = _aggregate_tagset(dfa.tags[s], aggregate, id_to_bit=id_to_bit)
            edges.append(ODFAEdge(group_id=gid, next_state=t, attack_id=aid))
        rows.append(ODFARow(edges=edges))

        if dfa.tags[s]:
            accepting_map[s] = _aggregate_tagset(dfa.tags[s], aggregate, id_to_bit=id_to_bit)

    start_state = dfa.start
    return ODFA(num_states=num_states, start_state=start_state, accepting=accepting_map, rows=rows)


# =========================
# 對外 API：多條規則 -> ODFA
# =========================

def compile_rules_to_odfa(
    rules: Iterable[RuleSpec],
    *,
    minimize: bool = True,
    aggregate: str = "min",                 # "min" 或 "bitmask16"
    id_to_bit: Optional[Dict[int, int]] = None,
) -> ODFA:
    """
    把多條規則（各自有 attack_id 與 flags）合成單一 ODFA。
    """
    rule_list = list(rules)
    if not rule_list:
        # 空集合：產生一個沒有接受態的空機器
        empty = TaggedDFA(start=0, trans=[{}], accept=set(), tags=[frozenset()])
        return tagged_dfa_to_odfa(empty, aggregate=aggregate, id_to_bit=id_to_bit)

    # 個別編成 DFA
    compiled: List[Tuple[SingleDFA, int]] = []
    for r in rule_list:
        r.sanity_check()
        d = compile_regex_to_dfa(r.pattern, flags=r.flags, minimize=True)
        compiled.append((d, r.attack_id))

    # 聯集 + 最小化（保留 tags）
    td = _union_dfas(compiled)
    if minimize:
        td = minimize_tagged_dfa(td)

    # 轉 ODFA，選擇 tag 聚合策略
    return tagged_dfa_to_odfa(td, aggregate=aggregate, id_to_bit=id_to_bit)


# =========================
# Smoke test
# =========================

if __name__ == "__main__":
    # 兩條規則：一個大小寫不敏感 "attack"，一個十六進位序列 \x90{4,}
    r1 = RuleSpec(pattern=r"attack", attack_id=3, flags=RegexFlags(ignore_case=True, anchored=False))
    r2 = RuleSpec(pattern=r"\x90{4,}", attack_id=7, flags=RegexFlags(anchored=False))

    odfa = compile_rules_to_odfa([r1, r2], aggregate="min")
    print("[chain] num_states:", odfa.num_states, "avg_outdeg:", odfa.avg_outdeg())
    # 也試 bitmask：把 attack_id -> bit 位置
    odfa2 = compile_rules_to_odfa([r1, r2], aggregate="bitmask16", id_to_bit={3: 0, 7: 1})
    print("[chain] (bitmask) num_states:", odfa2.num_states)
