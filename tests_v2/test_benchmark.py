import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from tools.benchmark_v2 import isolated, worker


def abrupt_worker(*args):
    os._exit(7)


def sleeping_worker(*args):
    time.sleep(60)


def memory_failure_worker(*args):
    with patch('tools.benchmark_v2.compile_sources',side_effect=MemoryError('injected allocation failure')):
        worker(*args)


class BenchmarkTests(unittest.TestCase):
    def payload(self, root):
        source = root/'rules.abp'
        source.write_text('*ad*\n@@*ok*',encoding='utf8')
        return {'rules':str(source),'output':str(root)}

    def test_compile_without_deadline_records_progress_and_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = isolated('compile',self.payload(root))
            self.assertEqual(result['status'],'ok',result)
            self.assertTrue((root/'policy.bin').exists())
            events = [json.loads(line) for line in (root/'compile-progress.jsonl').read_text().splitlines()]
            self.assertEqual(events[0]['stage'],'regex_validation')
            self.assertEqual(events[-1]['stage'],'policy_write')
            self.assertTrue(all(event['worker_pid'] != os.getpid() for event in events))

    def test_hard_worker_exit_does_not_wait_forever_without_deadline(self):
        with patch('tools.benchmark_v2.worker',abrupt_worker):
            result = isolated('compile',{})
        self.assertEqual(result['error_type'],'WorkerExit')
        self.assertEqual(result['exit_code'],7)

    def test_memory_error_is_reported_without_claiming_compile_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch('tools.benchmark_v2.worker',memory_failure_worker):
                result = isolated('compile',self.payload(root))
            self.assertEqual(result['error_type'],'MemoryError')
            self.assertFalse((root/'policy.bin').exists())

    def test_explicit_worker_deadline_still_ends_the_child(self):
        with patch('tools.benchmark_v2.worker',sleeping_worker):
            result = isolated('compile',{},timeout=0.1)
        self.assertEqual(result['error_type'],'WorkerTimeout')


if __name__ == '__main__':
    unittest.main()
