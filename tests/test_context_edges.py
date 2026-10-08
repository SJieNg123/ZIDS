import unittest

from src.zids.compiler import compile_sources
from src.zids.context import RequestContext, third_party
from src.zids.contracts import ProtocolError
from src.zids.easylist import parse_sources, plain_match
from tests.test_easylist import oracle


class ContextEdgeTests(unittest.TestCase):
    def test_ip_domains_are_exact_and_do_not_inherit_numeric_suffixes(self):
        source = '''advert$domain=0.1
exact$domain=127.0.0.1
@@adsafe$domain=127.0.0.1
tracker$third-party
ipv6$domain=[::1]
except$domain=~0.1
override$domain=0.1|127.0.0.1
exclude$domain=0.1|~127.0.0.1
'''
        rules, _ = parse_sources([('ip',source)])
        contexts = [RequestContext('https://x/'+path,'script',document)
                    for path in ('advert','exact','adsafe','ipv6','except','override','exclude')
                    for document in ('https://127.0.0.1/','https://126.0.0.1/',
                                     'https://foo.0.1/','https://[::1]/')]
        contexts += [RequestContext('https://127.000.0.1/tracker','script','https://126.000.0.1/'),
                     RequestContext('https://[2001:db8::1]/tracker','script','https://[2001:db8::2]/'),
                     RequestContext('https://B\u00dcCHER.example/tracker','script','https://xn--bcher-kva.example/'),
                     RequestContext('https://a.co.uk./tracker','script','https://b.co.uk/'),
                     RequestContext('https://a.github.io/tracker','script','https://b.github.io/')]
        reference = oracle(rules,contexts)
        self.assertEqual(reference['diagnostics'],[])
        expected = [x['decision'] for x in reference['outputs']]
        self.assertEqual([plain_match(rules,c) for c in contexts],expected)
        self.assertEqual([third_party(c.url,c.document_url) for c in contexts],
                         [x['third_party'] for x in reference['outputs']])
        dfa, _, _ = compile_sources([('ip',source)])
        self.assertEqual([dfa.evaluate(c.encode()) for c in contexts],expected)

    def test_scoped_ipv6_requires_caller_normalization(self):
        with self.assertRaises(ProtocolError):
            RequestContext('https://[fe80::1%25eth0]/','script','https://site.example/')
        for kind in ([],{},True,None):
            with self.assertRaises(ProtocolError):
                RequestContext('https://x/',kind,'https://site.example/')

    def test_domain_option_history_and_trailing_dots(self):
        source = '''trail$domain=site.example.
excluded$domain=~site.example.
cancel$domain=site.example|~site.example
restore$domain=~site.example|site.example
shadow$domain=site.example|~site.example|deep.site.example
'''
        rules, _ = parse_sources([('domains',source)])
        contexts = [RequestContext('https://x/'+path,'image','https://'+domain+'/')
                    for path in ('trail','excluded','cancel','restore','shadow')
                    for domain in ('site.example','other.example','deep.site.example','site.example.')]
        reference = oracle(rules,contexts)
        expected = [x['decision'] for x in reference['outputs']]
        self.assertEqual(reference['diagnostics'],[])
        self.assertEqual([plain_match(rules,c) for c in contexts],expected)
        dfa, _, _ = compile_sources([('domains',source)])
        self.assertEqual([dfa.evaluate(c.encode()) for c in contexts],expected)


if __name__ == '__main__':
    unittest.main()
