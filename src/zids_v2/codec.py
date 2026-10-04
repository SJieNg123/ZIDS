"""One canonical bit layout for both parties. No format guessing."""
from dataclasses import dataclass
import secrets

from .contracts import ProtocolError, bounded_int


@dataclass(frozen=True)
class Params:
    n: int
    q: int
    outmax: int
    cmax: int
    k: int = 128

    def __post_init__(self):
        bounded_int(self.n, 1, 65536, "input byte length")
        bounded_int(self.q, 2, 2**32-1, "state count")
        bounded_int(self.outmax, 1, 256, "outmax")
        bounded_int(self.cmax, 1, self.q*256, "cmax")
        if type(self.k) is not int or self.k != 128:
            raise ProtocolError("this suite fixes k=128")

    @property
    def state_bits(self):
        return (self.q-1).bit_length()

    @property
    def width(self):
        return 2*self.k+self.state_bits

    @property
    def key_bytes(self):
        return (self.width+7)//8

    @property
    def cell_bytes(self):
        return (self.outmax*self.width+7)//8

    @property
    def bundle_bytes(self):
        return self.cmax*self.key_bytes

    @property
    def matrix_bytes(self):
        return self.n*self.q*self.cell_bytes

    def estimate(self):
        return {"gdfa_bytes": self.matrix_bytes,
                "ot_plain_bundle_bytes": self.n*256*self.bundle_bytes,
                "base_transfers": 8*self.n,
                "server_row_bytes": self.q*self.cell_bytes}

    def enforce_limits(self, *, max_matrix_bytes=1024**3, max_row_bytes=64*1024**2,
                       max_ot_bytes=1024**3):
        if self.matrix_bytes > max_matrix_bytes:
            raise ProtocolError(f"GDFA resource limit: {self.matrix_bytes} bytes")
        if self.q*self.cell_bytes > max_row_bytes:
            raise ProtocolError("GDFA row resource limit")
        if self.n*256*self.bundle_bytes > max_ot_bytes:
            raise ProtocolError("OT bundle resource limit")


def random_permutation(q):
    permutation = list(range(q))
    secrets.SystemRandom().shuffle(permutation)
    return tuple(permutation)


def inverse_permutation(permutation):
    if sorted(permutation) != list(range(len(permutation))):
        raise ProtocolError("not a permutation")
    inverse = [0]*len(permutation)
    for original, permuted in enumerate(permutation):
        inverse[permuted] = original
    return tuple(inverse)


def pack_entries(entries, params):
    if len(entries) != params.outmax:
        raise ProtocolError("wrong entry count")
    value = 0
    for entry in entries:
        bounded_int(entry, 0, (1 << params.width)-1, "entry")
        value = (value << params.width) | entry
    return value.to_bytes(params.cell_bytes, "big")


def unpack_entries(data, params):
    if len(data) != params.cell_bytes:
        raise ProtocolError("invalid cell length")
    value = int.from_bytes(data, "big")
    if value >> (params.width*params.outmax):
        raise ProtocolError("noncanonical cell alignment")
    mask = (1 << params.width)-1
    return tuple((value >> ((params.outmax-1-i)*params.width)) & mask
                 for i in range(params.outmax))


def transition_entry(state, pad, params):
    bounded_int(state, 0, params.q-1, "next state")
    if len(pad) != params.k//8:
        raise ProtocolError("invalid pad length")
    return ((state << params.k) | int.from_bytes(pad, "big")) << params.k


def terminal_entry(label, params):
    bounded_int(label, 0, 2, "final label")
    return label << params.k


def decode_entry(value, params, *, terminal=False):
    if value >> params.width or value < 0 or value & ((1 << params.k)-1):
        return None
    value >>= params.k
    if terminal:
        return value if value in (0, 1, 2) else None
    state, pad = value >> params.k, value & ((1 << params.k)-1)
    if state >= params.q:
        return None
    return state, pad.to_bytes(params.k//8, "big")


def pack_keys(keys, params):
    if len(keys) != params.cmax:
        raise ProtocolError("wrong key count")
    for key in keys:
        bounded_int(key, 0, (1 << params.width)-1, "key")
    return b"".join(key.to_bytes(params.key_bytes, "big") for key in keys)


def unpack_keys(bundle, params):
    if len(bundle) != params.bundle_bytes:
        raise ProtocolError("invalid key bundle length")
    keys = tuple(int.from_bytes(bundle[i:i+params.key_bytes], "big")
                 for i in range(0, len(bundle), params.key_bytes))
    if any(key >> params.width for key in keys):
        raise ProtocolError("noncanonical key encoding")
    return keys
