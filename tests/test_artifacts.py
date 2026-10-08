import json
from pathlib import Path
import tempfile
import tracemalloc
import unittest

from src.zids.artifacts import prepare, private_tables, MatrixReader, PUBLIC_FIELDS
from src.zids.contracts import ProtocolError
from src.zids.dfa import literal_search
from src.zids.gdfa import evaluate


class ArtifactTests(unittest.TestCase):
    def test_disk_roundtrip_and_private_boundary(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'session'
            m = prepare(literal_search(b'ab'), 4, root, provenance={'rules_sha256':'server-only'})
            self.assertEqual(set(m), PUBLIC_FIELDS)
            public_text = (root/'public'/'manifest.json').read_text()
            self.assertNotIn('server-only', public_text)
            tables = list(private_tables(root/'private'))
            selected = [table[x] for table, x in zip(tables, b'xabx')]
            with MatrixReader(root/'public') as reader:
                self.assertEqual(evaluate(reader.params, bytes.fromhex(m['session']), m['initial_state'],
                                         bytes.fromhex(m['initial_pad']), reader.cell, selected), 1)
            with self.assertRaises(FileExistsError):
                prepare(literal_search(b'ab'), 4, root)
            matrix = root/'public'/'matrix.bin'
            with matrix.open('r+b') as file:
                file.write(b'corrupted')
            with self.assertRaises(ProtocolError):
                MatrixReader(root/'public')

    def test_manifest_injection_and_truncated_private_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'session'
            m = prepare(literal_search(b'a'), 1, root)
            (root/'private'/'ot_messages.bin').write_bytes(b'bad')
            with self.assertRaises(ProtocolError):
                list(private_tables(root/'private'))
            m['row_alphabet'] = []
            (root/'public'/'manifest.json').write_text(json.dumps(m))
            with self.assertRaises(ProtocolError):
                MatrixReader(root/'public')

    def test_preparation_peak_memory_is_bounded_across_positions(self):
        peaks = []
        with tempfile.TemporaryDirectory() as temp:
            for n in (2, 40):
                tracemalloc.start()
                prepare(literal_search(b'ab'), n, Path(temp)/str(n))
                peaks.append(tracemalloc.get_traced_memory()[1])
                tracemalloc.stop()
        # Forty positions must not retain twenty times the material of two.
        self.assertLess(peaks[1], 3*peaks[0]+100000)


if __name__ == '__main__':
    unittest.main()
