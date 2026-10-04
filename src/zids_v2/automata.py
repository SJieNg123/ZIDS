"""Thompson construction, byte determinization and output refinement."""
from functools import lru_cache
from time import perf_counter
from re import _parser as parser, _constants as C

from .contracts import ProtocolError
from .dfa import DFA, NOMATCH, BLOCK, ALLOW

ALL = (1 << 256)-1
URL_BYTES = sum(1 << c for c in range(32, 127))
HOST_BYTES = sum(1 << c for c in b'abcdefghijklmnopqrstuvwxyz0123456789_.-:[]')
CHARACTER_OPS = (C.LITERAL, C.NOT_LITERAL, C.ANY, C.IN)


class CompileLimit(ProtocolError):
    pass


class RegexUnsupported(ProtocolError):
    pass


def bits(mask):
    while mask:
        bit = mask & -mask
        yield bit.bit_length()-1
        mask ^= bit


class NFA:
    def __init__(self, *, max_nfa=None, max_dfa=None, seconds=None, progress=None):
        self.max_nfa, self.max_dfa = max_nfa, max_dfa
        self.deadline = None if seconds is None else perf_counter()+seconds
        self.edges, self.eps, self.begin, self.end, self.outputs = [], [], [], [], []
        self.dominance = {}
        self.progress = progress
        self.progress_stage, self.progress_counts = 'construction', {}
        self.next_progress = 0

    def check(self, **counts):
        if self.deadline is None and self.progress is None:
            return
        now = perf_counter()
        if self.deadline is not None and now >= self.deadline:
            raise CompileLimit('compiler time limit exceeded')
        if self.progress is not None:
            self.progress_counts.update(counts)
            if now >= self.next_progress:
                self.progress(dict(stage=self.progress_stage, nfa_states=len(self.edges),
                                   **self.progress_counts))
                self.next_progress = now+10

    def phase(self, stage, **counts):
        self.progress_stage, self.progress_counts = stage, counts
        self.next_progress = 0
        self.check()

    def state(self):
        if self.max_nfa is not None and len(self.edges) >= self.max_nfa:
            raise CompileLimit('NFA state limit exceeded')
        self.check()
        self.edges.append([])
        self.eps.append([])
        self.begin.append([])
        self.end.append([])
        self.outputs.append(0)
        return len(self.edges)-1

    def edge(self, a, b, mask):
        if mask:
            self.edges[a].append((mask, b))

    def char(self, mask):
        a, b = self.state(), self.state()
        self.edge(a, b, mask)
        return a, b

    def literal(self, data):
        a = b = self.state()
        for byte in data:
            c = self.state()
            self.edge(b, c, 1 << byte)
            b = c
        return a, b

    def join(self, fragments):
        if not fragments:
            a = self.state()
            return a, a
        for left, right in zip(fragments, fragments[1:]):
            self.eps[left[1]].append(right[0])
        return fragments[0][0], fragments[-1][1]

    def loop(self, mask):
        a = self.state()
        self.edge(a, a, mask)
        return a, a

    def regex(self, source, *, match_case=False):
        return self.sequence(self.parse_regex(source), match_case)

    @staticmethod
    def parse_regex(source):
        # Python's bell escape has a different meaning in JavaScript regexes.
        if '\\a' in source:
            raise RegexUnsupported('non-portable regex escape')
        tree = parser.parse(source, flags=C.SRE_FLAG_ASCII)
        if tree.state.flags != C.SRE_FLAG_ASCII:
            raise RegexUnsupported('inline regex flags are outside the profile')
        return tree

    def regex_union(self, sources, *, match_case=False):
        # Identical context/action rules share URL prefixes and the matched suffix.
        # Otherwise subset construction needlessly remembers which rule matched.
        trie = [{'edges':{}, 'final':False}]
        for source in sources:
            self.check()
            current = 0
            for token in self.parse_regex(source):
                key = repr(token)
                edges = trie[current]['edges']
                if key not in edges:
                    if self.max_nfa is not None and len(trie) >= self.max_nfa:
                        raise CompileLimit('regex prefix trie exceeds NFA bound')
                    edges[key] = (token,len(trie))
                    trie.append({'edges':{},'final':False})
                current = edges[key][1]
            trie[current]['final'] = True
        start, end = self.state(), self.state()
        pending = [(0,start)]
        while pending:
            index, state = pending.pop()
            if trie[index]['final']:
                self.eps[state].append(end)
            for token, child in trie[index]['edges'].values():
                if token[0] in CHARACTER_OPS:
                    right = self.state()
                    self.edge(state,right,self.character_mask(*token,match_case))
                else:
                    left, right = self.sequence([token],match_case)
                    self.eps[state].append(left)
                pending.append((child,right))
        return start, end

    def character_mask(self, op, value, case):
        if op == C.ANY:
            charset = ALL ^ (1 << 10)
        elif op == C.IN:
            charset = self.charset(value)
        else:
            if value > 255:
                raise RegexUnsupported('non-byte regex literal')
            charset = 1 << value
            if op == C.NOT_LITERAL:
                charset ^= ALL
        # ABP lowercases the pattern AND the input, including regex escapes.
        return sum(1 << b for b in range(32,127)
                   if charset & (1 << (b+32 if not case and 65 <= b <= 90 else b)))

    def sequence(self, nodes, case):
        fragments = []
        for op, value in nodes:
            if op in CHARACTER_OPS:
                fragments.append(self.char(self.character_mask(op,value,case)))
            elif op == C.SUBPATTERN:
                _, add, remove, child = value
                if add or remove:
                    raise RegexUnsupported('inline regex flags are outside the profile')
                fragments.append(self.sequence(child, case))
            elif op == C.BRANCH:
                a, b = self.state(), self.state()
                for branch in value[1]:
                    left, right = self.sequence(branch, case)
                    self.eps[a].append(left)
                    self.eps[right].append(b)
                fragments.append((a, b))
            elif op in (C.MAX_REPEAT, C.MIN_REPEAT):
                low, high, child = value
                if self.max_nfa is not None and (low > self.max_nfa or (high != C.MAXREPEAT and high > self.max_nfa)):
                    raise CompileLimit('regex repetition exceeds NFA bound')
                parts = [self.sequence(child, case) for _ in range(low)]
                a, b = self.join(parts)
                if high == C.MAXREPEAT:
                    left, right = self.sequence(child, case)
                    final = self.state()
                    self.eps[b].extend((left, final))
                    self.eps[right].extend((left, final))
                    b = final
                else:
                    for _ in range(high-low):
                        left, right = self.sequence(child, case)
                        self.eps[b].extend((left, right))
                        b = right
                fragments.append((a, b))
            elif op == C.AT:
                a, b = self.state(), self.state()
                if value in (C.AT_BEGINNING, C.AT_BEGINNING_STRING):
                    self.begin[a].append(b)
                elif value in (C.AT_END, C.AT_END_STRING):
                    self.end[a].append(b)
                else:
                    raise RegexUnsupported('word boundaries are outside the profile')
                fragments.append((a, b))
            else:
                raise RegexUnsupported('unsupported regex operation: '+str(op))
        return self.join(fragments)

    @staticmethod
    def charset(items):
        mask, negate = 0, False
        categories = {
            C.CATEGORY_DIGIT: set(range(48, 58)),
            C.CATEGORY_SPACE: set(b' \t\n\r\f\v'),
            C.CATEGORY_WORD: set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'),
        }
        negative = {C.CATEGORY_NOT_DIGIT:C.CATEGORY_DIGIT,
                    C.CATEGORY_NOT_SPACE:C.CATEGORY_SPACE, C.CATEGORY_NOT_WORD:C.CATEGORY_WORD}
        for op, value in items:
            if op == C.NEGATE:
                negate = True
            elif op == C.LITERAL and value < 256:
                mask |= 1 << value
            elif op == C.RANGE and value[1] < 256:
                mask |= sum(1 << b for b in range(value[0], value[1]+1))
            elif op == C.CATEGORY and value in categories.keys() | negative.keys():
                chars = categories[negative.get(value, value)]
                part = sum(1 << b for b in chars)
                mask |= ALL ^ part if value in negative else part
            else:
                raise RegexUnsupported('unsupported regex character class')
        return ALL ^ mask if negate else mask

    def determinize(self, start):
        self.phase('alphabet_index')
        # Globally equivalent input bytes are evaluated once per DFA state.
        partitions = [ALL]
        masks = {mask for edges in self.edges for mask, _ in edges} | {1, 1 << 4}
        for mask in masks:
            partitions = [part for old in partitions for part in (old & mask, old & (ALL ^ mask)) if part]
        symbols = [next(bits(p)) for p in partitions]
        indexed = [[(tuple(i for i, b in enumerate(symbols) if mask & (1 << b)), dest)
                    for mask, dest in edges] for edges in self.edges]

        @lru_cache(maxsize=8192)
        def closure(states, beginning=False, ending=False):
            found = states
            todo = list(bits(states))
            while todo:
                s = todo.pop()
                destinations = self.eps[s]
                if beginning:
                    destinations = destinations+self.begin[s]
                if ending:
                    destinations = destinations+self.end[s]
                for dest in destinations:
                    bit = 1 << dest
                    if not found & bit:
                        found |= bit
                        todo.append(dest)
            # Once a same-policy URL pattern has matched, its suffix accepts every
            # remaining URL byte. Earlier alternatives cannot add another output.
            for marker, redundant in self.dominance.items():
                if found & marker:
                    found &= ~redundant
            return found

        initial = (closure(1 << start), False)
        states, indices, rows, outputs = [initial], {initial:0}, [], []
        self.phase('determinization', dfa_states=1, processed_states=0)
        for subset, beginning in states:
            self.check(dfa_states=len(states), processed_states=len(rows))
            flags = 0
            for s in bits(subset):
                flags |= self.outputs[s]
            outputs.append(ALLOW if flags & 4 else BLOCK if flags & 2 or (flags & 1 and not flags & 8) else NOMATCH)
            ordinary = closure(subset, beginning)
            ending = closure(subset, beginning, True)
            destinations = [0]*len(symbols)
            for s in bits(ordinary):
                for classes, dest in indexed[s]:
                    bit = 1 << dest
                    for i in classes:
                        destinations[i] |= bit
            # End assertions are zero-width and only see the URL delimiter.
            end_index = next(i for i, b in enumerate(symbols) if b == 0)
            for s in bits(ending & ~ordinary):
                for mask, dest in self.edges[s]:
                    if mask & 1:
                        destinations[end_index] |= 1 << dest
            row = [0]*256
            for i, move in enumerate(destinations):
                key = (closure(move), symbols[i] == 4 and bool(move))
                if key not in indices:
                    if self.max_dfa is not None and len(states) >= self.max_dfa:
                        raise CompileLimit('DFA state limit exceeded')
                    indices[key] = len(states)
                    states.append(key)
                for byte in bits(partitions[i]):
                    row[byte] = indices[key]
            rows.append(tuple(row))
        self.symbols = symbols
        return DFA(tuple(rows), tuple(outputs)), len(partitions)


def minimize(dfa, *, check=lambda: None, symbols=range(256)):
    """Moore refinement preserves all three terminal labels, not just acceptance."""
    classes = list(dfa.outputs)
    reduced_rows = [tuple(row[b] for b in symbols) for row in dfa.transitions]
    while True:
        check()
        signatures, revised = {}, []
        for row, output in zip(reduced_rows, dfa.outputs):
            signature = (output, tuple(classes[d] for d in row))
            revised.append(signatures.setdefault(signature, len(signatures)))
        if revised == classes:
            break
        classes = revised
    representatives = {}
    for s, block in enumerate(classes):
        representatives.setdefault(block, s)
    return DFA(tuple(tuple(classes[d] for d in dfa.transitions[s]) for s in representatives.values()),
               tuple(dfa.outputs[s] for s in representatives.values()), classes[dfa.start])
