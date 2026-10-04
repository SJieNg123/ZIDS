from dataclasses import asdict
import multiprocessing as mp
import secrets
import socket
import unittest

from src.zids_v2.batch_ot import BaseOTBackend, contexts
from src.zids_v2.contracts import OTContext, ProtocolError
from src.zids_v2.wire import Channel


def party_sender(ports, results, context, tables, batch_size):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        ports.put(listener.getsockname()[1])
        conn, _ = listener.accept()
        with Channel(conn) as channel:
            BaseOTBackend(batch_size=batch_size).send(channel, iter(tables), context)
            results.put(("sender", asdict(channel.metrics)))


def party_receiver(ports, results, context, choices, batch_size):
    with Channel(socket.create_connection(("127.0.0.1", ports.get(timeout=10)))) as channel:
        selected = BaseOTBackend(batch_size=batch_size).receive(channel, choices, context)
        results.put(("receiver", (selected, asdict(channel.metrics))))


class BatchOTTests(unittest.TestCase):
    def test_whole_and_split_batches(self):
        choices = [0, 1, 127, 128, 255, 15, 240, 99, 42]
        tables = [[secrets.token_bytes(9) for _ in range(256)] for _ in choices]
        expected = [t[c] for t, c in zip(tables, choices)]
        for batch_size in (4, 9):
            ctx = mp.get_context("spawn")
            context = OTContext(secrets.token_bytes(16), 0, len(choices), 9)
            ports, results = ctx.Queue(), ctx.Queue()
            processes = [ctx.Process(target=party_sender, args=(ports, results, context, tables, batch_size)),
                         ctx.Process(target=party_receiver, args=(ports, results, context, choices, batch_size))]
            for p in processes:
                p.start()
            try:
                got = dict(results.get(timeout=20) for _ in processes)
                for p in processes:
                    p.join(10)
                    self.assertEqual(p.exitcode, 0)
                selected, receiver_metrics = got['receiver']
                self.assertEqual(selected, expected)
                self.assertEqual(got['sender']['base_transfers'], 8*len(choices))
                self.assertEqual(receiver_metrics['base_transfers'], 8*len(choices))
                self.assertEqual(got['sender']['sent_bytes'], receiver_metrics['received_bytes'])
                self.assertEqual(got['sender']['received_bytes'], receiver_metrics['sent_bytes'])
            finally:
                for p in processes:
                    if p.is_alive():
                        p.terminate()
                        p.join()
                ports.close()
                results.close()

    def test_limits_and_explicit_no_extension(self):
        for name in ('iknp', 'kos', 'direct', 'fake', ''):
            with self.assertRaises(ProtocolError):
                BaseOTBackend(name)
        with self.assertRaises(ProtocolError):
            list(contexts(OTContext(bytes(16), 0, 1, 8*1024*1024)))
        chunks = list(contexts(OTContext(bytes(16), 6, 17, 32), 8))
        self.assertEqual([(i, c.batch, c.count) for i, c in chunks], [(0,6,8), (8,7,8), (16,8,1)])


if __name__ == '__main__':
    unittest.main()
