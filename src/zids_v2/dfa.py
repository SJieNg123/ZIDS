"""Server-private total byte DFA and globally deduplicated character groups."""
from dataclasses import dataclass

from .contracts import ProtocolError, bounded_int

NOMATCH, BLOCK, ALLOW = 0, 1, 2
LABELS = ("NOMATCH", "BLOCK", "ALLOW")


@dataclass(frozen=True)
class DFA:
    transitions: tuple
    outputs: tuple
    start: int = 0

    def __post_init__(self):
        q = len(self.transitions)
        if q < 1 or len(self.outputs) != q:
            raise ProtocolError("invalid DFA dimensions")
        bounded_int(self.start, 0, q-1, "start state")
        for row in self.transitions:
            if len(row) != 256:
                raise ProtocolError("DFA must use total 256-byte alphabet")
            for dest in row:
                bounded_int(dest, 0, q-1, "destination")
        for output in self.outputs:
            bounded_int(output, 0, 2, "output label")

    @property
    def q(self):
        return len(self.transitions)

    def evaluate(self, data):
        state = self.start
        for byte in data:
            state = self.transitions[state][byte]
        return self.outputs[state]

    def padded(self):
        if self.q >= 2:
            return self
        return DFA(self.transitions + (tuple([1]*256),), self.outputs+(NOMATCH,), self.start)


@dataclass(frozen=True)
class Groups:
    catalog: tuple
    edges: tuple
    containing: tuple
    outmax: int
    cmax: int


def group_characters(dfa):
    catalog, indices, edges = [], {}, []
    for row in dfa.transitions:
        partitions = {}
        for byte, dest in enumerate(row):
            partitions[dest] = partitions.get(dest, 0) | (1 << byte)
        state_edges = []
        for dest, bitset in sorted(partitions.items()):
            if bitset not in indices:
                indices[bitset] = len(catalog)
                catalog.append(bitset)
            state_edges.append((indices[bitset], dest))
        edges.append(tuple(state_edges))
    containing = tuple(tuple(i for i, bits in enumerate(catalog) if (bits >> byte) & 1)
                       for byte in range(256))
    return Groups(tuple(catalog), tuple(edges), containing,
                  max(map(len, edges)), max(map(len, containing)))


def literal_search(pattern: bytes, output=BLOCK):
    """Small exact reference DFA with an absorbing matched state for tests."""
    if not pattern:
        return DFA((tuple([0]*256),), (output,))
    rows = []
    for state in range(len(pattern)):
        row = []
        for byte in range(256):
            text = pattern[:state] + bytes([byte])
            size = min(len(pattern), len(text))
            while size and not text.endswith(pattern[:size]):
                size -= 1
            row.append(size)
        rows.append(tuple(row))
    rows.append(tuple([len(pattern)]*256))
    return DFA(tuple(rows), (NOMATCH,)*len(pattern)+(output,))
