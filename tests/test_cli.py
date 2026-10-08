import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from src.zids.lifecycle import state

ROOT = Path(__file__).resolve().parents[1]
COMMAND = [sys.executable,'-B','-X','utf8','-m','src.zids']


class CLITests(unittest.TestCase):
    def invoke(self, *arguments, success=True):
        result = subprocess.run(COMMAND+list(map(str,arguments)),cwd=ROOT,text=True,encoding='utf8',
                                capture_output=True,timeout=120)
        self.assertEqual(result.returncode,0 if success else 2,result.stderr)
        return json.loads(result.stdout if success else result.stderr)

    def test_two_independent_cli_processes_and_no_session_reuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rules, request = root/'rules.txt', root/'request.json'
            rules.write_text('*ad*\n@@*ok*',encoding='utf8')
            request.write_text(json.dumps({'url':'https://a/adok','resource_type':'image',
                                           'document_url':'https://b/'}),encoding='utf8')
            compiled = root/'compiled'
            self.invoke('compile','--rules',rules,'--output',compiled)
            length = self.invoke('length','--request',request)['n']
            session = root/'server'
            self.invoke('prepare','--policy',compiled/'policy.bin','--length',length,'--output',session)
            server = subprocess.Popen(COMMAND+['serve','--session',str(session),'--port','0'],
                                      cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf8')
            try:
                ready = json.loads(server.stdout.readline())
                output = self.invoke('evaluate','--request',request,'--output',root/'client',
                                     '--port',ready['listening'])
                stdout, stderr = server.communicate(timeout=120)
                self.assertEqual(server.returncode,0,stderr)
                sender = json.loads(stdout)
                self.assertEqual(output['label'],'ALLOW')
                self.assertEqual(output['metrics']['base_transfers'],8*length)
                self.assertEqual(sender['metrics']['base_transfers'],8*length)
                self.assertEqual(sender['metrics']['sent_bytes'],output['metrics']['received_bytes'])
                self.assertEqual(sender['metrics']['received_bytes'],output['metrics']['sent_bytes'])
                self.assertNotIn('decision',sender)
                self.assertEqual(state(session)['state'],'CONSUMED')
                self.assertEqual(sorted(p.name for p in (root/'client').iterdir()),
                                 ['bootstrap.json','manifest.json','matrix.bin','result.json'])
                public = json.loads((root/'client/manifest.json').read_text())
                self.assertNotIn('provenance',public)
                self.invoke('serve','--session',session,'--port','0',success=False)
            finally:
                if server.poll() is None:
                    server.kill()
                    server.communicate()

    def test_coverage_error_retains_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root/'bad.txt'
            source.write_text('/abc(?=def)/\nadvert$bad-option',encoding='utf8')
            self.invoke('compile','--rules',source,'--output',root/'failed',success=False)
            coverage = json.loads((root/'failed/coverage.json').read_text())
            self.assertEqual(coverage['counts']['unsupported'],2)
            self.assertFalse((root/'failed/policy.bin').exists())


if __name__ == '__main__':
    unittest.main()
