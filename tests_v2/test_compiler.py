import itertools
import unittest

from src.zids_v2.automata import CompileLimit
from src.zids_v2.compiler import compile_sources, policy_dict, policy_dfa
from src.zids_v2.context import RequestContext
from src.zids_v2.contracts import OTContext
from src.zids_v2.easylist import parse_sources, plain_match, CoverageError
from src.zids_v2.gdfa import Garbler, evaluate
from src.zids_v2.ot256 import Sender, Receiver
from tests_v2.test_easylist import RULES, oracle


class CompilerTests(unittest.TestCase):
    def test_reference_policy_and_context(self):
        dfa, provenance, _ = compile_sources([('fixture', RULES)])
        rules, _ = parse_sources([('fixture', RULES)])
        contexts = [RequestContext(url, kind, document, ancestors)
                    for url, kind, document, ancestors in itertools.product(
                        ['https://ads.example/a','https://ads.example/allowed.js',
                         'https://specific.example/a','https://notads.example/a',
                         'https://tracker.example/a','https://first.example/a',
                         'https://x.example/banner12.gif','https://exact.example/Path'],
                        ['script','image','document'],
                        ['https://site.example/','https://private.site.example/',
                         'https://generic.example/','https://sub.first.example/'],
                        [(),('https://allow.example/',)])]
        expected = [v['decision'] for v in oracle(rules, contexts)['outputs']]
        self.assertEqual([plain_match(rules, c) for c in contexts], expected)
        self.assertEqual([dfa.evaluate(c.encode()) for c in contexts], expected)
        self.assertLess(provenance['stats']['q'], provenance['stats']['raw_q'])
        self.assertEqual(policy_dfa(policy_dict(dfa, provenance)), dfa)
        # No prefix of a valid request exposes an intermediate rule output.
        data = contexts[0].encode()
        self.assertTrue(all(dfa.evaluate(data[:i]) == 0 for i in range(len(data))))

    def test_domain_override_and_regular_expression_boundaries(self):
        source = r'''/banner[0-9]{2,3}(\.gif|$)/$image,domain=~site.example|ok.site.example
/^https?:\/\/x\.example\/(Ab|c+)[^a-z]?$/
/^https:\/\/x\.example\/\x41$/
/^https:\/\/x\.example\/\D{2}$/
@@||allow.example^$document,domain=parent.example
'''
        dfa, _, _ = compile_sources([('regex', source)])
        rules, _ = parse_sources([('regex', source)])
        contexts = [RequestContext('https://x.example/'+suffix, kind, doc, chain)
                    for suffix, kind, doc, chain in itertools.product(
                        ['banner12','banner12.gif','banner1234.gif','banner1.gif','AB','c','cc9','A','12','ZZ'],
                        ['image','script'], ['https://site.example/','https://ok.site.example/'],
                        [(),('https://allow.example/','https://parent.example/')])]
        expected = [v['decision'] for v in oracle(rules, contexts)['outputs']]
        self.assertEqual([dfa.evaluate(c.encode()) for c in contexts], expected)

    def test_unsupported_and_resource_limits_are_errors(self):
        with self.assertRaises(CoverageError):
            compile_sources([('bad', r'/abc(?=def)/')])
        with self.assertRaises(CompileLimit):
            compile_sources([('bounded','||ads.example^')], max_dfa=2)
        with self.assertRaises(CompileLimit):
            compile_sources([('bounded','||ads.example^')], max_nfa=10)
        with self.assertRaises(CompileLimit):
            compile_sources([('bounded','||ads.example^')], seconds=0)

    def test_reference_dfa_and_real_ot_gdfa_agree(self):
        source = '*ad*\n@@*ok*'
        dfa, _, _ = compile_sources([('secure',source)])
        rules, _ = parse_sources([('secure',source)])
        contexts = [RequestContext('https://a/'+path,'image','https://b/') for path in ('ad','adok','xx')]
        expected = [x['decision'] for x in oracle(rules, contexts)['outputs']]
        self.assertEqual(expected, [1,2,0])
        for context, output in zip(contexts, expected):
            data = context.encode()
            garbler = Garbler(dfa, len(data))
            rows, selected = [], []
            for i, row, tables in garbler.rows():
                ot_context = OTContext(garbler.session, i, 1, garbler.params.bundle_bytes)
                sender = Sender([tables], ot_context)
                receiver = Receiver([data[i]], ot_context)
                selected.extend(receiver.finish(sender.answer(receiver.query(sender.offer())), sender.ciphertexts))
                rows.append(row)
            size = garbler.params.cell_bytes
            result = evaluate(garbler.params, garbler.session, garbler.initial_state, garbler.initial_pad,
                              lambda i,s: rows[i][s*size:(s+1)*size], selected)
            self.assertEqual(dfa.evaluate(data), output)
            self.assertEqual(result, output)


if __name__ == '__main__':
    unittest.main()
