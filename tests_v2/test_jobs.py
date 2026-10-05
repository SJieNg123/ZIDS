import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from src.zids_v2.local_state import atomic_json, exclusive_lock
from tools.jobs_v2 import status, TERMINAL

ROOT = Path(__file__).resolve().parents[1]


class JobTests(unittest.TestCase):
    def test_jobs_outlive_launcher_and_retain_results(self):
        with tempfile.TemporaryDirectory() as temp:
            for code in (0,7):
                root = Path(temp)/str(code)
                command = [sys.executable,'-B','-m','tools.jobs_v2','start','--directory',str(root),'--',
                           sys.executable,'-c',
                           'import time,sys\ntime.sleep(1.5)\nprint("retained output")\nprint("retained error",file=sys.stderr)\nsys.exit('+str(code)+')']
                launched = subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=20)
                self.assertEqual(launched.returncode,0,launched.stderr)
                deadline = time.monotonic()+20
                while time.monotonic() < deadline:
                    value = status(root)
                    if value['state'] in TERMINAL:
                        break
                    time.sleep(0.1)
                self.assertEqual(value['state'],'SUCCEEDED' if code == 0 else 'FAILED',value)
                self.assertEqual(value['exit_code'],code)
                self.assertIn('retained output',(root/'stdout.log').read_text())
                self.assertIn('retained error',(root/'stderr.log').read_text())

    def test_lost_supervisor_does_not_invent_worker_exit_or_overwrite_live_job(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            atomic_json(root/'job.json',{'state':'RUNNING','worker_pid':123,'exit_code':None})
            with exclusive_lock(root/'supervisor.lock'):
                self.assertEqual(status(root)['state'],'RUNNING')
            value = status(root)
            self.assertEqual(value['state'],'SUPERVISOR_LOST')
            self.assertIsNone(value['exit_code'])
            self.assertEqual(json.loads((root/'job.json').read_text()),value)


if __name__ == '__main__':
    unittest.main()
