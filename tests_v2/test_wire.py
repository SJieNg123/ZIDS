import multiprocessing as mp
import socket
import unittest

from src.zids_v2.contracts import OTContext, Once, ProtocolError
from src.zids_v2.wire import Channel, HEADER, MAGIC, Kind

CTX = OTContext(b"a" * 16, 0, 1, 32)


def sender_process(port_queue, result_queue):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port_queue.put(listener.getsockname()[1])
        conn, _ = listener.accept()
        with Channel(conn) as wire:
            wire.send(Kind.SETUP, CTX, b"public setup")
            got = wire.receive(Kind.QUERY, CTX, size=32)
            wire.send(Kind.RESPONSE, CTX, got[::-1])
            result_queue.put(wire.metrics.sent_frames)


def receiver_process(port_queue, result_queue):
    with Channel(socket.create_connection(("127.0.0.1", port_queue.get(timeout=10)))) as wire:
        if wire.receive(Kind.SETUP, CTX) != b"public setup":
            raise RuntimeError("bad setup")
        query = bytes(range(32))
        wire.send(Kind.QUERY, CTX, query)
        result_queue.put(wire.receive(Kind.RESPONSE, CTX, size=32) == query[::-1])


class WireTests(unittest.TestCase):
    def test_separate_processes(self):
        ctx = mp.get_context("spawn")
        ports, results = ctx.Queue(), ctx.Queue()
        processes = [ctx.Process(target=f, args=(ports, results))
                     for f in (sender_process, receiver_process)]
        for process in processes:
            process.start()
        try:
            for process in processes:
                process.join(15)
                self.assertEqual(process.exitcode, 0)
            self.assertEqual(sorted([results.get(timeout=2), results.get(timeout=2)]), [True, 2])
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join()
            ports.close()
            results.close()

    def bad_frame(self, data):
        a, b = socket.socketpair()
        with a, Channel(b) as wire:
            a.sendall(data)
            a.shutdown(socket.SHUT_WR)
            with self.assertRaises(ProtocolError):
                wire.receive(Kind.SETUP, CTX, size=32)

    def test_truncation_and_wrong_headers(self):
        self.bad_frame(b"short")
        for field, value in [(0, b"badmagic"), (1, 255), (2, b"b"*16), (3, 1), (4, 2**40)]:
            fields = [MAGIC, Kind.SETUP, CTX.session, 0, 32]
            fields[field] = value
            self.bad_frame(HEADER.pack(*fields))
        self.bad_frame(HEADER.pack(MAGIC, Kind.SETUP, CTX.session, 0, 32) + b"short")

    def test_duplicate_and_consumed_material(self):
        a, b = socket.socketpair()
        with Channel(a) as left, Channel(b) as right:
            left.send(Kind.SETUP, CTX, b"hello")
            self.assertEqual(right.receive(Kind.SETUP, CTX), b"hello")
            with self.assertRaises(ProtocolError):
                left.send(Kind.SETUP, CTX, b"hello")
            with self.assertRaises(ProtocolError):
                right.receive(Kind.SETUP, CTX)
        token = Once()
        token.consume()
        with self.assertRaises(ProtocolError):
            token.consume()

    def test_reject_extensions_and_invalid_context(self):
        for change in ({"suite": "iknp"}, {"count": 0}, {"batch": -1},
                       {"message_bytes": True}, {"session": bytes(15)}):
            params = dict(session=CTX.session, batch=0, count=1, message_bytes=32)
            params.update(change)
            with self.assertRaises(ProtocolError):
                OTContext(**params)


if __name__ == "__main__":
    unittest.main()
