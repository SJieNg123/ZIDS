"""Compact alphabet-class transitions with a total 256-byte sequence view."""
from array import array
from collections.abc import Sequence

from .contracts import ProtocolError


class PackedRow(Sequence):
    def __init__(self, table, state):
        self.table, self.offset = table,state*table.columns

    def __len__(self):
        return 256

    def __getitem__(self, byte):
        if isinstance(byte,slice):
            return tuple(self[i] for i in range(*byte.indices(256)))
        return self.table.data[self.offset+self.table.mapping[byte]]

    def __eq__(self, other):
        return tuple(self) == tuple(other)


class PackedTransitions(Sequence):
    def __init__(self, mapping, data=None):
        self.mapping = bytes(mapping)
        if len(self.mapping) != 256:
            raise ProtocolError('invalid compact alphabet')
        self.columns = max(self.mapping)+1
        if set(self.mapping) != set(range(self.columns)):
            raise ProtocolError('noncontiguous compact alphabet')
        self.data = array('Q') if data is None else data
        if self.data.itemsize != 8 or len(self.data) % self.columns:
            raise ProtocolError('invalid packed transition dimensions')

    def __len__(self):
        return len(self.data)//self.columns

    def __getitem__(self, state):
        if isinstance(state,slice):
            return tuple(self[i] for i in range(*state.indices(len(self))))
        if state < 0:
            state += len(self)
        if not 0 <= state < len(self):
            raise IndexError(state)
        return PackedRow(self,state)

    def compact_row(self, state):
        return memoryview(self.data)[state*self.columns:(state+1)*self.columns]

    def append(self, row):
        if len(row) != self.columns:
            raise ProtocolError('invalid compact row width')
        self.data.extend(row)

    def validate(self, q):
        if len(self) != q or any(dest >= q for dest in self.data):
            raise ProtocolError('invalid packed transition target')

    def __eq__(self, other):
        if isinstance(other,PackedTransitions) and self.mapping == other.mapping:
            return self.data == other.data
        return len(self) == len(other) and all(a == b for a,b in zip(self,other))
