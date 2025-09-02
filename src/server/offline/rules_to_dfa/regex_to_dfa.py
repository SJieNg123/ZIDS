# src/server/offline/rules_to_dfa/regex_to_dfa.py
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Set, Tuple, Optional
import itertools

from src.common.odfa.matrix import ODFA, ODFARow, ODFARow, ODFARow, ODFAEdge  # type: ignore
from src.common.odfa.matrix import ODFA, ODFARow, ODFAEdge  # 正確匯入

# =========================
# Flags & helpers
# =========================

@dataclass(frozen=True)
class RegexFlags:
    ignore_case: bool = False   # ASCII-only case fold
    dotall: bool = True         # '.' matches \n if True
    anchored: bool = False      # if False: match anywhere

ALPHABET = list(range(256))
ALPHABET_SET = set(ALPHABET)

def _ascii_fold_bytes(bs: Set[int]) -> Set[int]:
    out = set(bs)
    for b in list(bs):
        if 65 <= b <= 90: out.add(b + 32)
        elif 97 <= b <= 122: out.add(b - 32)
    return out

# =========================
# Tokens & shunting-yard
# =========================

LITERAL = "LIT"       # value: int (byte)
CLASS   = "CLS"       # value: Set[int]
DOT     = "DOT"
LPAREN  = "("
RPAREN  = ")"
ALT     = "|"
STAR    = "*"
PLUS    = "+"
QMARK   = "?"
REPEAT  = "REP"       # value: (m, n) where n=None means {m,}
CONCAT  = "·"

@dataclass(frozen=True)
class Tok:
    kind: str
    val: object = None

def _hex2byte(hh: str) -> int:
    v = int(hh, 16)
    if not (0 <= v <= 255): raise ValueError("hex byte out of range")
    return v

def _parse_class(src: str, i: int, flags: RegexFlags) -> Tuple[Tok, int]:
    i += 1  # skip '['
    if i >= len(src): raise ValueError("unterminated character class")
    neg = False
    if src[i] == "^":
        neg = True; i += 1
    elems: Set[int] = set()
    while i < len(src):
        ch = src[i]
        if ch == "]":
            i += 1; break
        if ch == "\\":
            i += 1
            if i >= len(src): raise ValueError("dangling escape in class")
            esc = src[i]
            if esc == "x":
                if i + 2 >= len(src): raise ValueError("incomplete \\xHH in class")
                b = _hex2byte(src[i+1:i+3]); i += 2; cur = b
            elif esc == "n": cur = 10
            elif esc == "r": cur = 13
            elif esc == "t": cur = 9
            else:            cur = ord(esc) & 0xFF
        else:
            cur = ord(ch) & 0xFF
        # range?
        if i + 1 < len(src) and src[i+1] == "-" and (i + 2) < len(src) and src[i+2] != "]":
            start_b = cur; i += 2
            if src[i] == "\\":
                i += 1
                if i >= len(src): raise ValueError("dangling escape at range end")
                esc2 = src[i]
                if esc2 == "x":
                    if i + 2 >= len(src): raise ValueError("incomplete \\xHH at range end")
                    end_b = _hex2byte(src[i+1:i+3]); i += 2
                elif esc2 == "n": end_b = 10
                elif esc2 == "r": end_b = 13
                elif esc2 == "t": end_b = 9
                else:             end_b = ord(esc2) & 0xFF
            else:
                end_b = ord(src[i]) & 0xFF
            if end_b < start_b: raise ValueError("invalid range in class")
            for v in range(start_b, end_b + 1): elems.add(v)
        else:
            elems.add(cur)
        i += 1
    else:
        raise ValueError("unterminated character class")
    if neg: elems = ALPHABET_SET - elems
    if flags.ignore_case: elems = _ascii_fold_bytes(elems)
    return Tok(CLASS, elems), i

def _inject_concat(tokens: List[Tok]) -> List[Tok]:
    res: List[Tok] = []
    for i, t in enumerate(tokens):
        if i > 0:
            prev = tokens[i-1]
            if (prev.kind in (LITERAL, CLASS, DOT, RPAREN, STAR, PLUS, QMARK, REPEAT)
                and t.kind   in (LITERAL, CLASS, DOT, LPAREN)):
                res.append(Tok(CONCAT))
        res.append(t)
    return res

def _to_postfix(tokens: List[Tok]) -> List[Tok]:
    prec = {ALT:1, CONCAT:2, STAR:3, PLUS:3, QMARK:3, REPEAT:3}
    right_assoc = {STAR, PLUS, QMARK, REPEAT}
    out: List[Tok] = []; st: List[Tok] = []
    for t in tokens:
        k = t.kind
        if k in (LITERAL, CLASS, DOT): out.append(t)
        elif k == LPAREN: st.append(t)
        elif k == RPAREN:
            while st and st[-1].kind != LPAREN: out.append(st.pop())
            if not st: raise ValueError("unmatched ')'")
            st.pop()
        elif k in (ALT, CONCAT, STAR, PLUS, QMARK, REPEAT):
            while st and st[-1].kind != LPAREN:
                top = st[-1]
                if (prec[top.kind] > prec[k]) or (prec[top.kind] == prec[k] and k not in right_assoc):
                    out.append(st.pop())
                else: break
            st.append(t)
        else:
            raise ValueError(f"unknown token: {t}")
    while st:
        top = st.pop()
        if top.kind in (LPAREN, RPAREN): raise ValueError("unmatched '('")
        out.append(top)
    return out

def _tokenize(pattern: str, flags: RegexFlags) -> List[Tok]:
    i = 0; toks: List[Tok] = []
    while i < len(pattern):
        ch = pattern[i]
        if ch == ".": toks.append(Tok(DOT)); i += 1
        elif ch == "|": toks.append(Tok(ALT)); i += 1
        elif ch == "(": toks.append(Tok(LPAREN)); i += 1
        elif ch == ")": toks.append(Tok(RPAREN)); i += 1
        elif ch in "*+?": toks.append(Tok(ch)); i += 1
        elif ch == "{":
            j = i + 1
            while j < len(pattern) and pattern[j].isdigit(): j += 1
            if j == i + 1: raise ValueError("expected m in {m,n}")
            m = int(pattern[i+1:j]); n: Optional[int] = None
            if j < len(pattern) and pattern[j] == ",":
                j += 1; k = j
                while j < len(pattern) and pattern[j].isdigit(): j += 1
                if j > k: n = int(pattern[k:j])
            if j >= len(pattern) or pattern[j] != "}": raise ValueError("missing '}' in {m,n}")
            toks.append(Tok(REPEAT, (m, n))); i = j + 1
        elif ch == "[": tok, i = _parse_class(pattern, i, flags); toks.append(tok)
        elif ch == "\\":
            i += 1
            if i >= len(pattern): raise ValueError("dangling escape")
            esc = pattern[i]
            if esc == "x":
                if i + 2 >= len(pattern): raise ValueError("incomplete \\xHH")
                b = _hex2byte(pattern[i+1:i+3]); i += 2; v = b
            elif esc == "n": v = 10
            elif esc == "r": v = 13
            elif esc == "t": v = 9
            else: v = ord(esc) & 0xFF
            toks.append(Tok(LITERAL, v)); i += 1
        else:
            b = ord(ch) & 0xFF
            if flags.ignore_case and 97 <= b <= 122:
                toks.append(Tok(CLASS, _ascii_fold_bytes({b})))
            elif flags.ignore_case and 65 <= b <= 90:
                toks.append(Tok(CLASS, _ascii_fold_bytes({b})))
            else:
                toks.append(Tok(LITERAL, b))
            i += 1
    toks = _inject_concat(toks)
    dot_set = ALPHABET_SET if flags.dotall else (ALPHABET_SET - {10})
    toks = [Tok(CLASS, dot_set) if t.kind == DOT else t for t in toks]
    return toks

# =========================
# NFA (Thompson)
# =========================

@dataclass
class NFAState:
    eps: Set[int]
    trans: Dict[frozenset, Set[int]]  # label -> dest set

@dataclass
class NFA:
    start: int
    accept: int
    states: List[NFAState]

def _new_state(states: List[NFAState]) -> int:
    states.append(NFAState(set(), {})); return len(states) - 1

def _add_edge(states: List[NFAState], s: int, label: Optional[Set[int]], t: int) -> None:
    if label is None:
        states[s].eps.add(t)
    else:
        key = frozenset(label)
        states[s].trans.setdefault(key, set()).add(t)

@dataclass
class Frag:
    s: int
    f: int
    is_atom: bool
    atom_label: Optional[Set[int]]  # only valid when is_atom=True

def _frag_for_atom(states: List[NFAState], label: Set[int]) -> Frag:
    s = _new_state(states); f = _new_state(states)
    _add_edge(states, s, set(label), f)
    return Frag(s, f, True, set(label))

def _frag_from_tok_atom(states: List[NFAState], t: Tok) -> Frag:
    if t.kind == LITERAL:
        return _frag_for_atom(states, {int(t.val)})
    elif t.kind == CLASS:
        return _frag_for_atom(states, set(int(x) for x in t.val))
    else:
        raise ValueError(f"unexpected atom token {t.kind}")

def _concat(states: List[NFAState], a: Frag, b: Frag) -> Frag:
    _add_edge(states, a.f, None, b.s)
    return Frag(a.s, b.f, False, None)

def _alt(states: List[NFAState], a: Frag, b: Frag) -> Frag:
    s = _new_state(states); f = _new_state(states)
    _add_edge(states, s, None, a.s); _add_edge(states, s, None, b.s)
    _add_edge(states, a.f, None, f); _add_edge(states, b.f, None, f)
    return Frag(s, f, False, None)

def _star(states: List[NFAState], a: Frag) -> Frag:
    s = _new_state(states); f = _new_state(states)
    _add_edge(states, s, None, a.s); _add_edge(states, s, None, f)
    _add_edge(states, a.f, None, a.s); _add_edge(states, a.f, None, f)
    return Frag(s, f, False, None)

def _plus(states: List[NFAState], a: Frag) -> Frag:
    s = _new_state(states); f = _new_state(states)
    _add_edge(states, s, None, a.s)
    _add_edge(states, a.f, None, a.s); _add_edge(states, a.f, None, f)
    return Frag(s, f, False, None)

def _qmark(states: List[NFAState], a: Frag) -> Frag:
    s = _new_state(states); f = _new_state(states)
    _add_edge(states, s, None, a.s); _add_edge(states, s, None, f)
    _add_edge(states, a.f, None, f)
    return Frag(s, f, False, None)

def _repeat_atom(states: List[NFAState], a: Frag, m: int, n: Optional[int]) -> Frag:
    assert a.is_atom and a.atom_label is not None
    label = set(a.atom_label)
    # base epsilon if m==0 and n==0
    def _epsilon() -> Frag:
        s = _new_state(states); f = _new_state(states); _add_edge(states, s, None, f); return Frag(s, f, False, None)

    # chain of t copies
    def _chain(t: int) -> Optional[Frag]:
        if t == 0: return None
        fr = _frag_for_atom(states, label)
        for _ in range(t - 1):
            fr = _concat(states, fr, _frag_for_atom(states, label))
        return fr

    if n is None:
        # {m,} = chain(m) · (atom)*
        base = _chain(m)
        star = _star(states, _frag_for_atom(states, label))
        return star if base is None else _concat(states, base, star)
    else:
        if m == 0 and n == 0:
            return _epsilon()
        base = _chain(m)  # may be None if m==0
        k = n - m
        cur = base
        for _ in range(k):
            opt = _qmark(states, _frag_for_atom(states, label))
            cur = opt if cur is None else _concat(states, cur, opt)
        assert cur is not None
        return cur

def _postfix_to_nfa(post: List[Tok], flags: RegexFlags) -> NFA:
    states: List[NFAState] = []
    st: List[Frag] = []
    for t in post:
        k = t.kind
        if k in (LITERAL, CLASS):
            st.append(_frag_from_tok_atom(states, t))
        elif k == CONCAT:
            b = st.pop(); a = st.pop(); st.append(_concat(states, a, b))
        elif k == ALT:
            b = st.pop(); a = st.pop(); st.append(_alt(states, a, b))
        elif k == STAR:
            a = st.pop(); st.append(_star(states, a))
        elif k == PLUS:
            a = st.pop(); st.append(_plus(states, a))
        elif k == QMARK:
            a = st.pop(); st.append(_qmark(states, a))
        elif k == REPEAT:
            a = st.pop(); m, n = t.val  # type: ignore
            if not a.is_atom:
                raise ValueError("repeat {m,n} is only supported on a single atom/character class")
            st.append(_repeat_atom(states, a, int(m), (None if n is None else int(n))))
        else:
            raise ValueError(f"unexpected postfix token {t}")
    if len(st) != 1:
        raise ValueError("malformed regex (stack not singleton)")
    start, accept = st[0].s, st[0].f

    # Not anchored: prefix with (any)* to allow match anywhere
    if not flags.anchored:
        s0 = _new_state(states); f0 = _new_state(states)
        any_set = ALPHABET_SET  # 邏輯上「任意位置」要允許任何位元組
        s_any = _new_state(states); f_any = _new_state(states)
        _add_edge(states, s_any, None, f_any)
        _add_edge(states, s_any, any_set, s_any)
        _add_edge(states, s0, None, s_any)
        _add_edge(states, f_any, None, start)
        _add_edge(states, accept, None, f0)
        start, accept = s0, f0

    return NFA(start=start, accept=accept, states=states)

# =========================
# NFA -> DFA -> minimize
# =========================

@dataclass
class DFA:
    start: int
    accept: Set[int]
    trans: List[Dict[int, int]]

def _epsilon_closure(nfa: NFA, starts: Set[int]) -> Set[int]:
    stack = list(starts); seen = set(starts)
    while stack:
        u = stack.pop()
        for v in nfa.states[u].eps:
            if v not in seen: seen.add(v); stack.append(v)
    return seen

def _move(nfa: NFA, S: Set[int], b: int) -> Set[int]:
    dest = set()
    for u in S:
        for label_set, dsts in nfa.states[u].trans.items():
            if b in label_set: dest.update(dsts)
    return dest

def nfa_to_dfa(nfa: NFA) -> DFA:
    start_set = _epsilon_closure(nfa, {nfa.start})
    dstate_map: Dict[frozenset, int] = {frozenset(start_set): 0}
    dstates: List[Set[int]] = [start_set]
    trans: List[Dict[int, int]] = [dict()]
    accept: Set[int] = set()
    if nfa.accept in start_set: accept.add(0)
    i = 0
    while i < len(dstates):
        S = dstates[i]
        for b in ALPHABET:
            U = _epsilon_closure(nfa, _move(nfa, S, b))
            if not U: continue
            key = frozenset(U)
            if key not in dstate_map:
                dstate_map[key] = len(dstates)
                dstates.append(set(U)); trans.append(dict())
                if nfa.accept in U: accept.add(dstate_map[key])
            trans[i][b] = dstate_map[key]
        i += 1
    return DFA(start=0, accept=accept, trans=trans)

def minimize_dfa(dfa: DFA) -> DFA:
    n = len(dfa.trans)
    A = dfa.accept; nonA = set(range(n)) - A
    P: List[Set[int]] = [set(A), set(nonA)]
    W: List[Set[int]] = [set(A), set(nonA)]
    inv: List[Dict[int, Set[int]]] = [dict() for _ in range(256)]
    for s, mp in enumerate(dfa.trans):
        for b, t in mp.items():
            inv[b].setdefault(t, set()).add(s)
    while W:
        Aset = W.pop()
        for b in ALPHABET:
            X = set()
            for q in Aset:
                preds = inv[b].get(q)
                if preds: X |= preds
            if not X: continue
            newP: List[Set[int]] = []
            for Y in P:
                i1 = Y & X; i2 = Y - X
                if i1 and i2:
                    newP.extend([i1, i2])
                    if Y in W:
                        W.remove(Y); W.extend([i1, i2])
                    else:
                        W.append(i1 if len(i1) <= len(i2) else i2)
                else:
                    newP.append(Y)
            P = newP
    new_index = {}
    idx = 0
    for block in P:
        if not block: continue
        for s in block: new_index[s] = idx
        idx += 1
    new_n = idx
    new_trans: List[Dict[int,int]] = [dict() for _ in range(new_n)]
    new_accept: Set[int] = set()
    for block in P:
        if not block: continue
        rep = min(block); ni = new_index[rep]
        if any(s in dfa.accept for s in block): new_accept.add(ni)
        for b, t in dfa.trans[rep].items():
            new_trans[ni][b] = new_index[t]
    new_start = new_index[dfa.start]
    return DFA(start=new_start, accept=new_accept, trans=new_trans)

# =========================
# DFA -> ODFA (sparse)
# =========================

def dfa_to_odfa(dfa: DFA, *, attack_id: int = 1) -> ODFA:
    num_states = len(dfa.trans)
    rows: List[ODFARow] = []
    for s in range(num_states):
        mp = dfa.trans[s]
        next_to_bytes: Dict[int, List[int]] = {}
        for b, t in mp.items():
            next_to_bytes.setdefault(t, []).append(b)
        edges: List[ODFAEdge] = []
        for gid, (t, blist) in enumerate(sorted(next_to_bytes.items(), key=lambda kv: min(kv[1]))):
            edges.append(ODFAEdge(group_id=gid, next_state=t, attack_id=(attack_id if s in dfa.accept else 0)))
        rows.append(ODFARow(edges=edges))
    start_state = dfa.start
    accepting = {s: attack_id for s in dfa.accept}
    return ODFA(num_states=num_states, start_state=start_state, accepting=accepting, rows=rows)

# =========================
# Top-level helpers
# =========================

def compile_regex_to_dfa(pattern: str, *, flags: Optional[RegexFlags] = None, minimize: bool = True) -> DFA:
    flags = flags or RegexFlags()
    toks = _tokenize(pattern, flags)
    post = _to_postfix(toks)
    nfa = _postfix_to_nfa(post, flags)
    dfa = nfa_to_dfa(nfa)
    return minimize_dfa(dfa) if minimize else dfa

def compile_regex_to_odfa(pattern: str, *, flags: Optional[RegexFlags] = None, attack_id: int = 1, minimize: bool = True) -> ODFA:
    dfa = compile_regex_to_dfa(pattern, flags=flags, minimize=minimize)
    return dfa_to_odfa(dfa, attack_id=attack_id)

if __name__ == "__main__":
    # smoke
    f = RegexFlags(ignore_case=True, anchored=False)
    for pat in [r"abc", r"a|b", r"a.+c", r"[A-Fa-f0-9]{2}", r"\x41+", r"[^\r\n]{0,80}attack"]:
        dfa = compile_regex_to_dfa(pat, flags=f)
        print(pat, "-> states", len(dfa.trans))
    # 這個應該報錯（複合子式重複）
    try:
        compile_regex_to_dfa(r"(ab){2}", flags=RegexFlags())
    except Exception as e:
        print("[expected] error:", e)