from array import array
import json
from pathlib import Path
import tempfile
import unittest

from src.zids_v2.compiler import compile_sources, policy_dict
from src.zids_v2.contracts import ProtocolError
from src.zids_v2.dfa import DFA
from src.zids_v2.packed import PackedTransitions
from src.zids_v2.policy_io import open_policy, save_policy
from tools.verify_benchmark_policies import canonical_digest


class PolicyIOTests(unittest.TestCase):
    def test_binary_and_legacy_roundtrip_and_digest_rejection(self):
        dfa, provenance, _ = compile_sources([('policy','*ad*\n@@*ok*')])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root/'policy.bin'
            save_policy(path,dfa,provenance)
            with self.assertRaises(FileExistsError):
                save_policy(path,dfa,provenance)
            legacy = root/'policy.json'
            legacy.write_text(json.dumps(policy_dict(dfa,provenance)),encoding='utf8')
            for source in (path,legacy):
                with open_policy(source) as (loaded,metadata):
                    self.assertEqual(canonical_digest(loaded),canonical_digest(dfa))
                    self.assertEqual(metadata,provenance)
            with path.open('r+b') as file:
                file.seek(-40,2)
                file.write(b'corrupt!')
            with self.assertRaisesRegex(ProtocolError,'digest'):
                with open_policy(path):
                    self.fail('corrupt policy accepted')

    def test_binary_policy_exceeds_previous_128_mib_limit(self):
        count = 65537
        table = PackedTransitions(bytes(range(256)),array('Q',[0])*(count*256))
        dfa = DFA(table,bytes(count))
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'large.bin'
            save_policy(path,dfa,{'test':'former size boundary'})
            self.assertGreater(path.stat().st_size,128*1024*1024)
            with open_policy(path) as (loaded,_):
                self.assertEqual(loaded.q,count)
                self.assertEqual(loaded.evaluate(b'abc'),0)
                self.assertTrue(loaded.transitions.data.readonly)


if __name__ == '__main__':
    unittest.main()
