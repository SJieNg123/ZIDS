from dataclasses import asdict
import itertools
import json
import multiprocessing as mp
import socket
import unittest
from unittest.mock import patch

from src.zids_v2.batch_ot import BaseOTBackend
from src.zids_v2.codec import Params
from src.zids_v2.contracts import OTContext, ProtocolError
from src.zids_v2.dfa import literal_search
from src.zids_v2.gdfa import Garbler, evaluate
from src.zids_v2.wire import Channel, Kind


def server(ports, results, n):
    garbler = Garbler(literal_search(b'ab'), n)
    rows = list(garbler.rows())
    p = garbler.params
    context = OTContext(garbler.session, 0, p.n, p.bundle_bytes)
    # Only explicitly public data goes to the other process.
    public = (asdict(p), garbler.session, garbler.initial_state, garbler.initial_pad)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        ports.put((listener.getsockname()[1], public))
        conn, _ = listener.accept()
        with Channel(conn) as wire:
            wire.send(Kind.MATRIX, context, b''.join(row for _, row, _ in rows))
            BaseOTBackend(batch_size=2).send(wire, (bundles for _, _, bundles in rows), context)
            results.put(('base_transfers', wire.metrics.base_transfers))


def client(ports, results, data):
    port, (parameters, session, state, pad) = ports.get(timeout=10)
    p = Params(**parameters)
    context = OTContext(session, 0, p.n, p.bundle_bytes)
    with Channel(socket.create_connection(('127.0.0.1', port))) as wire:
        matrix = wire.receive(Kind.MATRIX, context, size=p.matrix_bytes)
        selected = BaseOTBackend(batch_size=2).receive(wire, data, context)
    def read_cell(position, state):
        offset = (position*p.q+state)*p.cell_bytes
        return matrix[offset:offset+p.cell_bytes]
    results.put(('output', evaluate(p, session, state, pad, read_cell, selected)))


class GDFATests(unittest.TestCase):
    def run_ideal(self, data, *, corruption=False):
        g = Garbler(literal_search(b'ab'), len(data), outmax=4, cmax=4)
        rows = list(g.rows())
        selected = [bundles[x] for (_, _, bundles), x in zip(rows, data)]
        if corruption:
            selected[0] = bytes(g.params.bundle_bytes)
        def cell(i, state):
            offset = state*g.params.cell_bytes
            return rows[i][1][offset:offset+g.params.cell_bytes]
        return evaluate(g.params, g.session, g.initial_state, g.initial_pad, cell, selected)

    def test_exhaustive_small_dfa_with_padding(self):
        # The ideal selection exists only here in the trusted correctness test.
        for length in range(1, 4):
            for data in itertools.product(b'abx', repeat=length):
                self.assertEqual(self.run_ideal(bytes(data)), int(b'ab' in bytes(data)))

    def test_nonidentity_permutations_corruption_and_freshness(self):
        with patch('src.zids_v2.gdfa.random_permutation', return_value=(2,0,1)):
            self.assertEqual(self.run_ideal(b'abx'), 1)
            self.assertEqual(self.run_ideal(b'aax'), 0)
        with self.assertRaises(ProtocolError):
            self.run_ideal(b'ab', corruption=True)
        first, second = [Garbler(literal_search(b'ab'), 2) for _ in range(2)]
        self.assertNotEqual(first.session, second.session)
        self.assertNotEqual(first.initial_pad, second.initial_pad)
        self.assertNotEqual(list(first.rows()), list(second.rows()))
        with self.assertRaises(ProtocolError):
            list(first.rows())

    def test_real_ot_two_processes(self):
        for data, expected in [(b'a',0), (b'xabx',1), (b'axbx',0)]:
            ctx = mp.get_context('spawn')
            ports, results = ctx.Queue(), ctx.Queue()
            processes = [ctx.Process(target=server, args=(ports, results, len(data))),
                         ctx.Process(target=client, args=(ports, results, data))]
            for p in processes:
                p.start()
            try:
                got = dict(results.get(timeout=30) for _ in processes)
                for p in processes:
                    p.join(10)
                    self.assertEqual(p.exitcode, 0)
                self.assertEqual(got, {'base_transfers': 8*len(data), 'output': expected})
            finally:
                for p in processes:
                    if p.is_alive():
                        p.terminate()
                        p.join()
                ports.close()
                results.close()


if __name__ == '__main__':
    unittest.main()
