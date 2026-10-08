import multiprocessing as mp
import secrets
import socket
import unittest

from src.zids.base_ot import Sender, Receiver, send_bits, receive_bits
from src.zids.contracts import OTContext, ProtocolError
from src.zids.crypto import ORDER, multiply, ro_pad
from src.zids.wire import Channel


def sender_worker(ports, results, context, messages):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        ports.put(listener.getsockname()[1])
        conn, _ = listener.accept()
        with Channel(conn) as channel:
            send_bits(channel, messages, context)
            results.put(("sent", channel.metrics.base_transfers))


def receiver_worker(ports, results, context, choices):
    with Channel(socket.create_connection(("127.0.0.1", ports.get(timeout=10)))) as channel:
        results.put(("received", receive_bits(channel, choices, context)))


class BaseOTTests(unittest.TestCase):
    def test_two_processes(self):
        context = OTContext(secrets.token_bytes(16), 3, 24, 37)
        messages = [(secrets.token_bytes(37), secrets.token_bytes(37)) for _ in range(24)]
        choices = [i % 2 for i in range(24)]
        ctx = mp.get_context("spawn")
        ports, results = ctx.Queue(), ctx.Queue()
        processes = [ctx.Process(target=sender_worker, args=(ports, results, context, messages)),
                     ctx.Process(target=receiver_worker, args=(ports, results, context, choices))]
        for p in processes:
            p.start()
        try:
            got = dict(results.get(timeout=15) for _ in processes)
            for p in processes:
                p.join(15)
                self.assertEqual(p.exitcode, 0)
            self.assertEqual(got['sent'], 24)
            self.assertEqual(got['received'], [m[c] for m, c in zip(messages, choices)])
        finally:
            for p in processes:
                if p.is_alive():
                    p.terminate()
                    p.join()
            ports.close()
            results.close()

    def test_invalid_sender_points(self):
        context = OTContext(b"x"*16, 0, 1, 32)
        offer = Sender([(b"a"*32, b"b"*32)], context).offer()
        bad = [bytes(32), b"\x01"+bytes(31), b"\xff"*32,
               (2**255-20).to_bytes(32, "little")]
        for point in bad:
            for offset in (32, 64):
                for choice in (0, 1):
                    receiver = Receiver([choice], context)
                    with self.assertRaises(ProtocolError):
                        receiver.query(offer[:offset]+point+offer[offset+32:])

    def test_receiver_points_replay_and_binding(self):
        context = OTContext(b"x"*16, 0, 1, 32)
        for kind in ('identity', 'C', 'truncated'):
            sender = Sender([(b"a"*32, b"b"*32)], context)
            bad = {'identity': b'\x01'+bytes(31), 'C': sender.C, 'truncated': b'bad'}[kind]
            with self.assertRaises(ProtocolError):
                sender.answer(bad)
            with self.assertRaises(ProtocolError):
                sender.answer(bad)
        sender = Sender([(b"a"*32, b"b"*32)], context)
        with self.assertRaises(ProtocolError):
            Receiver([0], OTContext(b"y"*16, 0, 1, 32)).query(sender.offer())
        receiver = Receiver([1], context)
        query = receiver.query(sender.offer())
        response = sender.answer(query)
        self.assertEqual(receiver.finish(response), [b"b"*32])
        with self.assertRaises(ProtocolError):
            receiver.finish(response)
        with self.assertRaises(ProtocolError):
            sender.answer(query)

    def test_equal_public_keys_keep_distinct_hash_domains(self):
        context = OTContext(b"x"*16, 1, 1, 32)
        sender = Sender([(bytes(32), bytes(32))], context)
        half = pow(2, -1, ORDER).to_bytes(32, "little")
        response = sender.answer(multiply(half, sender.C))
        self.assertNotEqual(response[32:64], response[64:96])
        self.assertNotEqual(ro_pad(b"x", b"t", 0, 0, 32), ro_pad(b"x", b"t", 0, 1, 32))


if __name__ == "__main__":
    unittest.main()
