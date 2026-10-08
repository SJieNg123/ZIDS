import multiprocessing as mp
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from src.zids.automata import NFA
from src.zids.compiler import compile_sources
from src.zids.contracts import ProtocolError
from src.zids.local_state import exclusive_lock
from tools.verify_benchmark_policies import canonical_digest

SOURCE = '||ads.example/'+('a'*150)+'^\n@@*allowed*'


def interrupted_compile(path):
    original = NFA.check
    def crash(self, **counts):
        original(self,**counts)
        if counts.get('processed_states',0) >= 60:
            os._exit(73)
    with patch.object(NFA,'check',crash):
        compile_sources([('fixture',SOURCE)],checkpoint=path,checkpoint_rows=20)


class CheckpointTests(unittest.TestCase):
    def test_abrupt_process_exit_resumes_committed_work_and_preserves_language(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'compiler.sqlite'
            child = mp.get_context('spawn').Process(target=interrupted_compile,args=(str(path),))
            child.start()
            child.join(30)
            if child.is_alive():
                child.terminate()
                child.join()
                self.fail('checkpoint fixture did not finish')
            self.assertEqual(child.exitcode,73)
            with closing(sqlite3.connect(path)) as db:
                cursor = int(db.execute("SELECT value FROM meta WHERE key='processed'").fetchone()[0])
            self.assertEqual(cursor,60)
            events = []
            resumed, _, _ = compile_sources([('fixture',SOURCE)],checkpoint=path,progress=events.append)
            phase = next(e for e in events if e['stage']=='determinization')
            self.assertEqual(phase['processed_states'],cursor)
            reference, _, _ = compile_sources([('fixture',SOURCE)])
            self.assertEqual(canonical_digest(resumed),canonical_digest(reference))
            again, _, _ = compile_sources([('moved-input-name',SOURCE)],checkpoint=path)
            self.assertEqual(canonical_digest(again),canonical_digest(reference))

    def test_mismatch_and_concurrent_writers_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'compiler.sqlite'
            compile_sources([('fixture','*ad*')],checkpoint=path)
            with self.assertRaises(ProtocolError):
                compile_sources([('fixture','*different*')],checkpoint=path)
            with exclusive_lock(str(path)+'.lock'):
                with self.assertRaises(BlockingIOError):
                    compile_sources([('fixture','*ad*')],checkpoint=path)


if __name__ == '__main__':
    unittest.main()
