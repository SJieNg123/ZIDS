import itertools
import secrets
import unittest

from src.zids.codec import (Params, pack_entries, unpack_entries, transition_entry,
    terminal_entry, decode_entry, pack_keys, unpack_keys, inverse_permutation)
from src.zids.contracts import ProtocolError
from src.zids.dfa import literal_search, group_characters


class DFAAndCodecTests(unittest.TestCase):
    def test_search_and_global_groups_exhaustive(self):
        dfa = literal_search(b'ab')
        groups = group_characters(dfa)
        self.assertGreater(groups.cmax, 1)
        for size in range(5):
            for word in itertools.product(b'abx', repeat=size):
                self.assertEqual(dfa.evaluate(bytes(word)), int(b'ab' in bytes(word)))
        for q, row in enumerate(dfa.transitions):
            for x in range(256):
                matches = [(g, dest) for g, dest in groups.edges[q] if (groups.catalog[g] >> x) & 1]
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0][1], row[x])
                self.assertIn(matches[0][0], groups.containing[x])

    def test_bit_layout_boundaries_and_zero_tail(self):
        for q in (2, 3, 255, 256, 257, 65537):
            params = Params(2, q, 3, 2)
            pad = secrets.token_bytes(16)
            entry = transition_entry(q-1, pad, params)
            entries = (entry, 0, (1 << params.width)-1)
            self.assertEqual(unpack_entries(pack_entries(entries, params), params), entries)
            self.assertEqual(decode_entry(entry, params), (q-1, pad))
            self.assertIsNone(decode_entry(entry | 1, params))
            for label in range(3):
                self.assertEqual(decode_entry(terminal_entry(label, params), params, terminal=True), label)
            keys = (1, (1 << params.width)-1)
            self.assertEqual(unpack_keys(pack_keys(keys, params), params), keys)
            self.assertEqual(params.matrix_bytes, 2*q*((3*params.width+7)//8))

    def test_invalid_alignment_parameters_and_resources(self):
        p = Params(3, 3, 1, 2)
        with self.assertRaises(ProtocolError):
            unpack_entries(b'\xff'*p.cell_bytes, p)
        with self.assertRaises(ProtocolError):
            unpack_keys(b'\xff'*p.bundle_bytes, p)
        with self.assertRaises(ProtocolError):
            Params(0, 2, 1, 1)
        with self.assertRaises(ProtocolError):
            p.enforce_limits(max_matrix_bytes=1)
        self.assertEqual(inverse_permutation((2,0,1)), (1,2,0))
        with self.assertRaises(ProtocolError):
            inverse_permutation((1,1,2))


if __name__ == '__main__':
    unittest.main()
