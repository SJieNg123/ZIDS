import multiprocessing as mp
import os
from pathlib import Path
import socket
import ssl
import subprocess
import shutil
import tempfile
import threading
import unittest

from src.zids_v2.artifacts import prepare
from src.zids_v2.contracts import ProtocolError
from src.zids_v2.dfa import literal_search
from src.zids_v2.lifecycle import Reservation, state, recover
from src.zids_v2.protocol import serve_connection, transport_context


def claim(root, gate, results):
    gate.wait()
    try:
        Reservation(root)
        results.put('reserved')
    except ProtocolError:
        results.put('rejected')


def crash(root):
    Reservation(root)
    os._exit(7)


class LifecycleTests(unittest.TestCase):
    def test_atomic_reservation_and_crash_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)/'session'
            prepare(literal_search(b'a'),1,root)
            ctx = mp.get_context('spawn')
            gate, results = ctx.Event(), ctx.Queue()
            processes = [ctx.Process(target=claim,args=(root,gate,results)) for _ in range(2)]
            for proc in processes:
                proc.start()
            gate.set()
            self.assertEqual(sorted(results.get(timeout=10) for _ in processes), ['rejected','reserved'])
            for proc in processes:
                proc.join(10)
                self.assertEqual(proc.exitcode,0)
            results.close()
            self.assertEqual(state(root)['state'],'RESERVED')
            self.assertEqual(recover(root)['state'],'BURNED')
            with self.assertRaises(ProtocolError):
                Reservation(root)
            fresh = Path(temporary)/'fresh'
            prepare(literal_search(b'a'),1,fresh)
            proc = ctx.Process(target=crash,args=(fresh,))
            proc.start()
            proc.join(10)
            self.assertEqual(proc.exitcode,7)
            with self.assertRaises(ProtocolError):
                Reservation(fresh)
            self.assertEqual(recover(fresh)['state'],'BURNED')

    def test_completion_error_disconnect_and_manifest_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            for scenario in ('success','error','disconnect','tamper'):
                root = Path(temporary)/scenario
                prepare(literal_search(b'a'),1,root)
                if scenario == 'success':
                    with Reservation(root):
                        pass
                    self.assertEqual(state(root)['state'],'CONSUMED')
                elif scenario == 'error':
                    with self.assertRaises(RuntimeError):
                        with Reservation(root):
                            raise RuntimeError('test')
                elif scenario == 'disconnect':
                    sender, receiver = socket.socketpair()
                    receiver.close()
                    with self.assertRaises(ProtocolError):
                        serve_connection(sender,root)
                else:
                    path = root/'public/manifest.json'
                    path.write_bytes(path.read_bytes()+b' ')
                    with self.assertRaises(ProtocolError):
                        Reservation(root)
                if scenario != 'success':
                    self.assertEqual(state(root)['state'],'BURNED')
                with self.assertRaises(ProtocolError):
                    Reservation(root)

    def test_remote_transport_requires_mutual_authentication(self):
        self.assertIsNone(transport_context('127.0.0.1'))
        self.assertIsNone(transport_context('::1'))
        for host in ('localhost','192.0.2.1','0.0.0.0','example.com'):
            with self.assertRaises(ProtocolError):
                transport_context(host)
        with self.assertRaises(ProtocolError):
            transport_context('127.0.0.1',cert='missing-cert')

    def test_mutual_tls_handshake_and_reject_missing_client_certificate(self):
        openssl = shutil.which('openssl')
        if not openssl and Path('C:/Program Files/Git/usr/bin/openssl.exe').exists():
            openssl = 'C:/Program Files/Git/usr/bin/openssl.exe'
        if not openssl:
            self.skipTest('OpenSSL CLI is required to generate an ephemeral TLS test certificate')
        with tempfile.TemporaryDirectory() as temporary:
            cert, key = Path(temporary)/'cert.pem', Path(temporary)/'key.pem'
            subprocess.run([openssl,'req','-x509','-newkey','ed25519','-nodes','-keyout',str(key),
                            '-out',str(cert),'-days','1','-subj','/CN=localhost',
                            '-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],
                           check=True,capture_output=True,timeout=30)
            server = transport_context('127.0.0.1',server=True,cert=cert,key=key,ca=cert)
            authenticated = transport_context('127.0.0.1',cert=cert,key=key,ca=cert)
            anonymous = ssl.create_default_context(cafile=cert)
            for client, valid in ((authenticated,True),(anonymous,False)):
                left, right = socket.socketpair()
                left.settimeout(5)
                right.settimeout(5)
                outcomes = []
                def accept():
                    try:
                        with server.wrap_socket(left,server_side=True) as connection:
                            connection.sendall(b'authenticated')
                        outcomes.append(True)
                    except ssl.SSLError:
                        outcomes.append(False)
                    finally:
                        left.close()
                thread = threading.Thread(target=accept)
                thread.start()
                try:
                    with client.wrap_socket(right,server_hostname='localhost') as connection:
                        payload = connection.recv(32)
                        self.assertTrue(valid)
                        self.assertEqual(payload,b'authenticated')
                        self.assertEqual(connection.version(),'TLSv1.3')
                except ssl.SSLError:
                    self.assertFalse(valid)
                finally:
                    right.close()
                    thread.join(10)
                self.assertEqual(outcomes,[valid])


if __name__ == '__main__':
    unittest.main()
