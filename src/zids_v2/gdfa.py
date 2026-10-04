"""ZIDS §5.4 sparse position-based garbling and final-only local evaluation."""
from dataclasses import asdict
import json
import secrets

from .codec import (Params, random_permutation, pack_entries, unpack_entries,
                    transition_entry, terminal_entry, decode_entry, pack_keys, unpack_keys)
from .contracts import Once, ProtocolError, bounded_int
from .crypto import fields, prf, xor
from .dfa import group_characters


def mask_cell(pad, session, position, state, params):
    domain = fields(b"ZIDSv2/GDFA/cell", session,
                    json.dumps(asdict(params), sort_keys=True, separators=(",", ":")).encode(),
                    position.to_bytes(8, "big"), state.to_bytes(8, "big"))
    return prf(pad, domain, params.cell_bytes)


class Garbler:
    """Server-only generator. At most current and next position state is kept."""
    def __init__(self, dfa, n, *, outmax=None, cmax=None, limits=None):
        self.dfa = dfa.padded()
        self.groups = group_characters(self.dfa)
        outmax = self.groups.outmax if outmax is None else outmax
        cmax = self.groups.cmax if cmax is None else cmax
        if outmax < self.groups.outmax or cmax < self.groups.cmax:
            raise ProtocolError("padding bounds smaller than true groups")
        self.params = Params(n, self.dfa.q, outmax, cmax)
        self.params.enforce_limits(**(limits or {}))
        self.session = secrets.token_bytes(16)
        self._permutation = random_permutation(self.dfa.q)
        self._pads = tuple(secrets.token_bytes(16) for _ in range(self.dfa.q))
        self.initial_state = self._permutation[self.dfa.start]
        self.initial_pad = self._pads[self.initial_state]
        self._once = Once()

    def rows(self):
        self._once.consume()
        p = self.params
        permutation, pads = self._permutation, self._pads
        self._permutation, self._pads = (), ()
        for position in range(p.n):
            terminal = position == p.n-1
            next_permutation = random_permutation(p.q) if not terminal else ()
            next_pads = tuple(secrets.token_bytes(16) for _ in range(p.q)) if not terminal else ()
            keys = [secrets.randbits(p.width) for _ in self.groups.catalog]
            cells = [None]*p.q
            for original, edges in enumerate(self.groups.edges):
                current = permutation[original]
                entries = []
                for group, dest in edges:
                    if terminal:
                        entry = terminal_entry(self.dfa.outputs[dest], p)
                    else:
                        next_state = next_permutation[dest]
                        entry = transition_entry(next_state, next_pads[next_state], p)
                    entries.append(entry ^ keys[group])
                entries.extend(secrets.randbits(p.width) for _ in range(p.outmax-len(entries)))
                secrets.SystemRandom().shuffle(entries)
                cells[current] = xor(pack_entries(entries, p),
                                     mask_cell(pads[current], self.session, position, current, p))
            bundles = []
            for groups in self.groups.containing:
                selected = [keys[group] for group in groups]
                selected.extend(secrets.randbits(p.width) for _ in range(p.cmax-len(selected)))
                secrets.SystemRandom().shuffle(selected)
                bundles.append(pack_keys(selected, p))
            yield position, b"".join(cells), tuple(bundles)
            permutation, pads = next_permutation, next_pads


def evaluate(params, session, initial_state, initial_pad, read_cell, selected_bundles):
    """No server-private tables, keys or role objects are accepted by this API."""
    if type(session) is not bytes or len(session) != 16:
        raise ProtocolError("invalid session")
    state = bounded_int(initial_state, 0, params.q-1, "initial state")
    if type(initial_pad) is not bytes or len(initial_pad) != 16:
        raise ProtocolError("invalid initial pad")
    pad = initial_pad
    bundles = iter(selected_bundles)
    result = None
    for position in range(params.n):
        bundle = next(bundles, None)
        if bundle is None:
            raise ProtocolError("missing selected OT bundle")
        keys = unpack_keys(bundle, params)
        cell = read_cell(position, state)
        plain_cell = xor(cell, mask_cell(pad, session, position, state, params))
        entries = unpack_entries(plain_cell, params)
        terminal = position == params.n-1
        candidates = [decoded for entry in entries for key in keys
                      if (decoded := decode_entry(entry ^ key, params, terminal=terminal)) is not None]
        if len(candidates) != 1:
            raise ProtocolError("GDFA decoding failed")
        if terminal:
            result = candidates[0]
        else:
            state, pad = candidates[0]
    if next(bundles, None) is not None:
        raise ProtocolError("extra selected OT bundle")
    return result
