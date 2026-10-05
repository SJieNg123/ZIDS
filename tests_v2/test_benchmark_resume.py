import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.zids_v2.contracts import ProtocolError
from tools.benchmark_v2 import run


class BenchmarkResumeTests(unittest.TestCase):
    def test_controller_interruption_after_policy_write_retains_incomplete_attempt(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temporary)/'benchmark'
            options = {'scales':['synthetic'],'secure_scales':[]}
            with patch('tools.benchmark_v2.check_compiled',side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    run(root,**options)
            self.assertTrue((root/'synthetic/policy.bin').exists())
            attempt = root/'synthetic/attempt-0001.json'
            incomplete = attempt.read_bytes()
            self.assertEqual(json.loads(incomplete)['status'],'running')
            resumed = run(root,resume=True,**options)
            self.assertEqual(resumed['scales'][0]['status'],'ok')
            self.assertEqual(attempt.read_bytes(),incomplete)
            self.assertEqual(resumed['scales'][0]['attempt'],2)
            self.assertNotIn('active_scale',resumed)

    def test_failed_compile_resumes_preserves_attempts_and_skips_success(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temporary)/'benchmark'
            options = {'scales':['synthetic'],'secure_scales':[]}
            failed = run(root,max_dfa=2,**options)
            self.assertEqual(failed['scales'][0]['status'],'compile_limit')
            old_attempt = (root/'synthetic/attempt-0001.json').read_bytes()
            old_progress = (root/'synthetic/compile-progress.jsonl').read_bytes()
            resumed = run(root,resume=True,**options)
            self.assertEqual(resumed['scales'][0]['status'],'ok')
            self.assertEqual(resumed['scales'][0]['dfa_mismatches'],0)
            self.assertEqual((root/'synthetic/attempt-0001.json').read_bytes(),old_attempt)
            self.assertTrue((root/'synthetic/compile-progress.jsonl').read_bytes().startswith(old_progress))
            self.assertTrue((root/'synthetic/attempt-0002.json').exists())
            self.assertIsNone(resumed['scales'][0]['compile_bounds']['max_dfa'])
            stamp = (root/'synthetic/policy.bin').stat().st_mtime_ns
            with patch('tools.benchmark_v2.isolated',side_effect=AssertionError('must skip completed scale')):
                self.assertEqual(run(root,resume=True,**options)['scales'],resumed['scales'])
            self.assertEqual((root/'synthetic/policy.bin').stat().st_mtime_ns,stamp)
            self.assertEqual(len(list((root/'synthetic').glob('attempt-*.json'))),2)
            with self.assertRaisesRegex(ProtocolError,'compilation only'):
                run(root,resume=True,scales=['synthetic'])
            report = json.loads((root/'report.json').read_text())
            report['inputs_sha256']['synthetic'] = 'changed'
            (root/'report.json').write_text(json.dumps(report),encoding='utf8')
            with self.assertRaisesRegex(ProtocolError,'inputs_sha256'):
                run(root,resume=True,**options)


if __name__ == '__main__':
    unittest.main()
