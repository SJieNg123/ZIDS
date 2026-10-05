import hashlib
import io
import secrets
import socket
import threading
import tracemalloc
import unittest

from src.zids_v2.batch_ot import BaseOTBackend, send_options, receive_options, FRAGMENT
from src.zids_v2.codec import Params
from src.zids_v2.contracts import OTContext, ProtocolError
from src.zids_v2.crypto import prf, prf_slice
from src.zids_v2.dfa import DFA
from src.zids_v2.gdfa import Garbler
from src.zids_v2.wire import Channel, Kind, MAX_FRAME


class StreamingTests(unittest.TestCase):
    def test_prf_slices_preserve_length_binding_and_unaligned_boundaries(self):
        key, domain = bytes(range(32)),b'test-domain'
        full = prf(key,domain,211)
        for size in (1,7,31,32,33,79):
            self.assertEqual(b''.join(prf_slice(key,domain,211,offset,min(size,211-offset))
                                     for offset in range(0,211,size)),full)
        self.assertNotEqual(prf(key,domain,210),full[:210])

    def test_real_base_ot_across_small_frames_and_selected_sink(self):
        context = OTContext(secrets.token_bytes(16),7,3,97)
        tables = [[bytes([option])*97 for option in range(256)] for _ in range(3)]
        left,right = socket.socketpair()
        errors = []
        def send():
            try:
                with Channel(left,max_frame=1024,timeout=10) as wire:
                    BaseOTBackend(batch_size=1).send(wire,tables,context)
                    self.assertEqual(wire.metrics.base_transfers,24)
            except BaseException as exc:
                errors.append(exc)
        thread = threading.Thread(target=send)
        thread.start()
        try:
            with Channel(right,max_frame=1024,timeout=10) as wire:
                selected = io.BytesIO()
                result = BaseOTBackend(batch_size=1).receive(wire,[0,127,255],context,sink=selected.write)
                self.assertEqual(result,[])
                self.assertEqual(selected.getvalue(),bytes(97)+bytes([127])*97+bytes([255])*97)
                self.assertEqual(wire.metrics.base_transfers,24)
        finally:
            thread.join(15)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors,[])

    def test_options_cross_old_64_mib_frame_bound_with_small_buffers(self):
        context = OTContext(secrets.token_bytes(16),0,1,MAX_FRAME//256+1)
        total = 32+256*context.message_bytes
        block = bytes(65536)
        expected = hashlib.sha256()
        for offset in range(0,total,len(block)):
            expected.update(block[:min(len(block),total-offset)])
        left,right = socket.socketpair()
        errors = []
        def send():
            try:
                with Channel(left,timeout=20) as wire:
                    chunks = (block[:min(len(block),total-offset)] for offset in range(0,total,len(block)))
                    send_options(wire,context,chunks,0)
            except BaseException as exc:
                errors.append(exc)
        tracemalloc.start()
        thread = threading.Thread(target=send)
        thread.start()
        try:
            digest, received = hashlib.sha256(),0
            with Channel(right,timeout=20) as wire:
                for data in receive_options(wire,context,0):
                    digest.update(data)
                    received += len(data)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            thread.join(25)
            tracemalloc.stop()
        self.assertEqual(errors,[])
        self.assertFalse(thread.is_alive())
        self.assertEqual(received,total)
        self.assertEqual(digest.digest(),expected.digest())
        self.assertLess(peak,24*1024*1024)

    def test_wrong_fragment_offset_batch_replay_and_truncation(self):
        context = OTContext(bytes(16),3,1,4)
        total = 32+256*4
        for failure in ('offset','batch','replay','truncated'):
            left,right = socket.socketpair()
            with Channel(left,max_frame=1024) as sender, Channel(right,max_frame=1024,timeout=2) as receiver:
                first = FRAGMENT.pack(context.batch+(failure=='batch'),int(failure=='offset'))+bytes(1008)
                sender.send(Kind.OPTIONS_FRAGMENT,OTContext(context.session,0,1,4),first)
                if failure == 'replay':
                    # Use a fresh wrapper to deliberately bypass sender replay rejection.
                    duplicate = Channel(left,max_frame=1024)
                    duplicate.send(Kind.OPTIONS_FRAGMENT,OTContext(context.session,0,1,4),
                                   FRAGMENT.pack(context.batch,1008)+bytes(total-1008))
                if failure == 'truncated':
                    left.shutdown(socket.SHUT_WR)
                with self.assertRaises(ProtocolError):
                    list(receive_options(receiver,context,0))

    def test_gdfa_row_exceeds_old_bound_without_materializing_the_row(self):
        q = 8000
        dfa = DFA((tuple([0]*256),)*q,(0,)*q)
        garbler = Garbler(dfa,1,outmax=256)
        self.assertGreater(garbler.params.q*garbler.params.cell_bytes,64*1024*1024)
        matrix_bytes, bundle_count = 0,0
        for _,kind,data in garbler.blocks(chunk_bytes=1024*1024):
            if kind == 'matrix':
                self.assertLessEqual(len(data),1024*1024)
                matrix_bytes += len(data)
            else:
                bundle_count += 1
        self.assertEqual(matrix_bytes,garbler.params.matrix_bytes)
        self.assertEqual(bundle_count,256)
        Params(65536,4096,256,256).enforce_limits()


if __name__ == '__main__':
    unittest.main()
