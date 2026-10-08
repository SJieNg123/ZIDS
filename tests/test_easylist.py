from dataclasses import asdict
import json
from pathlib import Path
import subprocess
import unittest

from src.zids.context import RequestContext, third_party
from src.zids.contracts import ProtocolError
from src.zids.easylist import parse_sources, plain_match, CoverageError

RULES = r'''
! fixed offline semantic fixture
||ads.example^
@@||ads.example/allowed.js$script
/banner*ad^$image
|https://exact.example/Path|$match-case
||tracker.example^$third-party,domain=site.example|~private.site.example
||first.example^$~third-party
/collect/$~image
/banner\d{2}\.gif/$image
@@||allow.example^$document
@@||generic.example^$genericblock
||specific.example^$domain=generic.example
example.com##.advert
@@||cosmetic.example^$generichide
'''


def oracle(rules, contexts):
    root = Path(__file__).resolve().parents[1]
    data = json.dumps({'rules': [r.text for r in rules], 'requests': [asdict(c) for c in contexts]})
    proc = subprocess.run(['node', str(root/'tools/reference_matcher.cjs')], input=data,
                          text=True, encoding='utf8', capture_output=True, cwd=root, timeout=30, check=True)
    return json.loads(proc.stdout)


class EasyListTests(unittest.TestCase):
    def test_reference_semantic_cases(self):
        rules, coverage = parse_sources([('fixture', RULES)])
        cases = [
            ('https://ads.example/a','script','https://site.example/',1),
            ('https://sub.ads.example:8080/a','image','https://site.example/',1),
            ('https://notads.example/a','script','https://site.example/',0),
            ('https://ads.example.ar/a','script','https://site.example/',0),
            ('https://ads.example/allowed.js','script','https://site.example/',2),
            ('https://ads.example/allowed.js','image','https://site.example/',1),
            ('https://x.example/banner123ad?x','image','https://site.example/',1),
            ('https://exact.example/Path','image','https://site.example/',1),
            ('https://exact.example/path','image','https://site.example/',0),
            ('https://tracker.example/x','script','https://site.example/',1),
            ('https://tracker.example/x','script','https://private.site.example/',0),
            ('https://first.example/x','script','https://sub.first.example/',1),
            ('https://first.example/x','script','https://site.example/',0),
            ('https://x.example/banner12.gif','image','https://site.example/',1),
            ('https://x.example/banner1.gif','image','https://site.example/',0),
            ('https://ads.example/a','script','https://allow.example/',2),
            ('https://ads.example/a','script','https://generic.example/',0),
            ('https://specific.example/a','script','https://generic.example/',1),
        ]
        contexts = [RequestContext(*case[:3]) for case in cases]
        result = oracle(rules, contexts)
        self.assertEqual(result['diagnostics'], [])
        expected = [c[3] for c in cases]
        self.assertEqual([plain_match(rules,c) for c in contexts], expected)
        self.assertEqual([x['decision'] for x in result['outputs']], expected)
        self.assertEqual(coverage['counts']['out_of_scope'], 2)

    def test_domains_party_and_ancestors(self):
        rules, _ = parse_sources([('r', 'advert$domain=~site.example|ok.site.example\n@@||allow.example^$document')])
        contexts = [RequestContext('https://a.co.uk/advert','script','https://b.co.uk/'),
                    RequestContext('https://a.github.io/advert','script','https://b.github.io/'),
                    RequestContext('https://x.example/advert','script','https://ok.site.example/'),
                    RequestContext('https://x.example/advert','script','https://site.example/'),
                    RequestContext('https://x.example/advert','script','https://child.example/',('https://allow.example/',))]
        result = oracle(rules, contexts)
        self.assertEqual([plain_match(rules,c) for c in contexts], [x['decision'] for x in result['outputs']])
        self.assertEqual([third_party(c.url,c.document_url) for c in contexts], [x['third_party'] for x in result['outputs']])

    def test_encoding_and_coverage(self):
        context = RequestContext('https://EXAMPLE.com:443/Case?q=%00','script','https://site.example/')
        self.assertIn(b'https://example.com/Case?q=%00', context.encode())
        self.assertNotEqual(context.encode(), RequestContext(context.url,'image',context.document_url).encode())
        for value in ['https://a.example/\x00secret','relative/url','https://user:password@a.example/']:
            with self.assertRaises(ProtocolError):
                RequestContext(value,'script','https://site.example/')
        with self.assertRaises(ProtocolError):
            RequestContext.from_dict({'url':'https://example.com/'})
        with self.assertRaises(CoverageError):
            parse_sources([('r','advert$unknown-option')])
        rules, _ = parse_sources([('a','||ads.example^'),('b','||ads.example^')])
        self.assertNotEqual(rules[0].rule_id,rules[1].rule_id)


if __name__ == '__main__':
    unittest.main()
