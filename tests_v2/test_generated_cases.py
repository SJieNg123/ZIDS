from pathlib import Path
import unittest

from src.zids_v2.compiler import compile_sources
from src.zids_v2.context import RequestContext
from src.zids_v2.easylist import parse_sources
from tests_v2.test_easylist import oracle
from tools.cases_v2 import rule_cases


class GeneratedCasesTests(unittest.TestCase):
    def test_per_rule_witnesses_and_context_mutations_against_independent_oracle(self):
        source = (Path(__file__).parent/'fixtures/context200.abp').read_text(encoding='utf8')
        rules, _ = parse_sources([('context200',source)])
        records, coverage = rule_cases(rules)
        self.assertGreaterEqual(coverage['witnessed_rules'],190)
        self.assertGreaterEqual(len(records),760)
        contexts = [RequestContext.from_dict(row['context']) for row in records]
        reference = oracle(rules,contexts)
        self.assertEqual(reference['diagnostics'],[])
        expected = [row['decision'] for row in reference['outputs']]
        self.assertEqual(set(expected),{0,1,2})
        dfa, _, _ = compile_sources([('context200',source)])
        self.assertEqual([dfa.evaluate(c.encode()) for c in contexts],expected)

    def test_regex_and_document_exception_coverage_is_explicit(self):
        source = '/banner[0-9]+/\n@@||allow.example^$document\n@@||generic.example^$genericblock'
        rules, _ = parse_sources([('cases',source)])
        records, coverage = rule_cases(rules)
        self.assertEqual(coverage['witnessed_rules'],1)
        self.assertEqual(len(coverage['unwitnessed']),2)
        self.assertTrue(records)


if __name__ == '__main__':
    unittest.main()
