import itertools
import random
import unittest

from src.zids_v2.automata import NFA, minimize
from src.zids_v2.dfa import DFA
from src.zids_v2.packed import PackedTransitions


class PackedTests(unittest.TestCase):
    def test_compact_storage_and_total_byte_view(self):
        nfa = NFA()
        start, end = nfa.literal(b'a'*2000)
        nfa.outputs[end] = 2
        dfa, alphabet = nfa.determinize(start)
        table = dfa.transitions
        self.assertIsInstance(table,PackedTransitions)
        self.assertEqual(len(table.data),dfa.q*alphabet)
        self.assertLess(len(table.data)*table.data.itemsize,dfa.q*256*8//20)
        self.assertEqual(len(table[0]),256)
        self.assertEqual(dfa.evaluate(b'a'*2000),1)
        self.assertEqual(dfa.evaluate(b'a'*1999),0)
        self.assertEqual(dfa.evaluate(b'a'*1999+b'\xff'),0)

    def test_refinement_preserves_all_labels_against_dense_dfa(self):
        randomizer = random.Random(42)
        for _ in range(8):
            table = PackedTransitions([byte%3 for byte in range(256)])
            for state in range(12):
                table.append([randomizer.randrange(12) for _ in range(3)])
            outputs = tuple(randomizer.randrange(3) for _ in range(12))
            original = DFA(tuple(tuple(row) for row in table),outputs)
            packed = DFA(table,bytes(outputs))
            self.assertEqual(original,packed)
            reduced = minimize(packed)
            for length in range(5):
                for word in itertools.product((0,1,255),repeat=length):
                    self.assertEqual(original.evaluate(word),reduced.evaluate(word))


if __name__ == '__main__':
    unittest.main()
