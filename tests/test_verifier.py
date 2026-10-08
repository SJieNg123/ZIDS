import copy
import json
from pathlib import Path
import unittest

from src.zids.contracts import ProtocolError
from tools.verify_benchmark_policies import PROTOCOL_FILES, protocol_source_checks


ROOT = Path(__file__).resolve().parents[1]


class VerifierTests(unittest.TestCase):
    def setUp(self):
        path = ROOT/'legacy/benchmarks/2026-10-05/readiness-report.json'
        self.measured = json.loads(path.read_text(encoding='utf8'))

    def test_archived_and_relocated_paths_check_the_same_module_bytes(self):
        old = protocol_source_checks(self.measured)
        moved = {'implementation_sha256': {
            'src/zids/'+Path(path).name: digest
            for path,digest in self.measured['implementation_sha256'].items()}}
        self.assertEqual(old, {name: True for name in PROTOCOL_FILES})
        self.assertEqual(protocol_source_checks(moved), old)

    def test_content_changes_are_still_reported_after_relocation(self):
        modified = copy.deepcopy(self.measured)
        hashes = modified['implementation_sha256']
        key = next(path for path in hashes if path.endswith('/crypto.py'))
        hashes[key] = '0'*64
        checks = protocol_source_checks(modified)
        self.assertFalse(checks.pop('crypto'))
        self.assertTrue(all(checks.values()))

    def test_missing_or_ambiguous_source_identity_is_rejected(self):
        for ambiguous in (False, True):
            with self.subTest(ambiguous=ambiguous):
                modified = copy.deepcopy(self.measured)
                hashes = modified['implementation_sha256']
                key = next(path for path in hashes if path.endswith('/crypto.py'))
                if ambiguous:
                    hashes['other/crypto.py'] = hashes[key]
                else:
                    del hashes[key]
                with self.assertRaisesRegex(ProtocolError, 'missing or ambiguous'):
                    protocol_source_checks(modified)


if __name__ == '__main__':
    unittest.main()
