"""Transactional, server-private determinization state. No pickle or OT material."""
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import sys
from time import monotonic

from .contracts import ProtocolError
from .local_state import exclusive_lock


def identity(nfa, start, partitions, binding):
    digest = hashlib.sha256()
    for name in ('automata.py','compiler.py','checkpoint.py','dfa.py','context.py','easylist.py'):
        digest.update(Path(__file__).with_name(name).read_text(encoding='utf8').encode('utf8'))
    digest.update(json.dumps([1,sys.version_info[:3],start,partitions,binding],sort_keys=True).encode())
    for index in range(len(nfa.edges)):
        digest.update(json.dumps([nfa.edges[index],nfa.eps[index],nfa.begin[index],nfa.end[index],
                                  nfa.outputs[index]],separators=(',',':')).encode())
    for marker, redundant in sorted(nfa.dominance.items()):
        for value in (marker,redundant):
            encoded = encode_key(value,False)
            digest.update(len(encoded).to_bytes(8,'big'))
            digest.update(encoded)
    return digest.hexdigest()


def encode_key(subset, beginning):
    return bytes([int(beginning)])+subset.to_bytes((subset.bit_length()+7)//8,'little')


class MemoryStates:
    def __init__(self):
        self.states, self.indices, self.rows, self.outputs = [], {}, [], []

    @property
    def count(self):
        return len(self.states)

    @property
    def processed(self):
        return len(self.rows)

    def intern(self, subset, beginning):
        key = (subset,beginning)
        if key not in self.indices:
            self.indices[key] = len(self.states)
            self.states.append(key)
        return self.indices[key]

    def state(self, index):
        return self.states[index]

    def append(self, row, output):
        self.rows.append(tuple(row))
        self.outputs.append(output)

    def result(self):
        return tuple(self.rows),tuple(self.outputs)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


class DiskStates:
    def __init__(self, path, fingerprint, *, commit_rows=1000):
        if type(commit_rows) is not int or commit_rows < 1:
            raise ValueError('checkpoint interval must be positive')
        self.path, self.fingerprint = Path(path), fingerprint
        self.commit_rows = commit_rows

    def __enter__(self):
        self.path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.lock = exclusive_lock(str(self.path)+'.lock')
        self.lock.__enter__()
        self.db = None
        try:
            self.db = sqlite3.connect(self.path,timeout=0)
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA cache_size=-8192')
            self.db.execute('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS states (id INTEGER PRIMARY KEY, subset BLOB UNIQUE NOT NULL, row BLOB, output INTEGER)')
            meta = dict(self.db.execute('SELECT key,value FROM meta'))
            if meta and meta.get('identity') != self.fingerprint:
                raise ProtocolError('checkpoint source, compiler or NFA identity mismatch')
            if not meta:
                self.db.executemany('INSERT INTO meta VALUES (?,?)',
                                    [('identity',self.fingerprint),('count','0'),('processed','0')])
                self.db.commit()
            self.count = int(meta.get('count',0))
            self.processed = int(meta.get('processed',0))
            if not 0 <= self.processed <= self.count:
                raise ProtocolError('invalid checkpoint cursor')
            self.committed = self.processed
            self.last_commit = monotonic()
            self._lookup = lru_cache(maxsize=8192)(self._intern)
            return self
        except BaseException:
            if self.db is not None:
                self.db.close()
            self.lock.__exit__(None,None,None)
            raise

    def _intern(self, key):
        found = self.db.execute('SELECT id FROM states WHERE subset=?',(key,)).fetchone()
        if found is not None:
            return found[0]
        index = self.count
        self.db.execute('INSERT INTO states(id,subset) VALUES (?,?)',(index,key))
        self.count += 1
        return index

    def intern(self, subset, beginning):
        return self._lookup(encode_key(subset,beginning))

    def state(self, index):
        value = self.db.execute('SELECT subset FROM states WHERE id=?',(index,)).fetchone()[0]
        return int.from_bytes(value[1:],'little'),bool(value[0])

    def append(self, row, output):
        self.db.execute('UPDATE states SET row=?,output=? WHERE id=?',
                        (struct.pack('<'+str(len(row))+'Q',*row),output,self.processed))
        self.processed += 1
        if self.processed-self.committed >= self.commit_rows or monotonic()-self.last_commit >= 30:
            self.commit()

    def commit(self):
        self.db.executemany('UPDATE meta SET value=? WHERE key=?',
                            [(str(self.count),'count'),(str(self.processed),'processed')])
        self.db.commit()
        self.committed, self.last_commit = self.processed,monotonic()

    def result(self):
        self.commit()
        rows, outputs = [], []
        for row, output in self.db.execute('SELECT row,output FROM states ORDER BY id'):
            if row is None:
                raise ProtocolError('checkpoint is incomplete')
            rows.append(struct.unpack('<'+str(len(row)//8)+'Q',row))
            outputs.append(output)
        return tuple(rows),tuple(outputs)

    def __exit__(self, kind, value, traceback):
        try:
            if kind is None:
                self.commit()
            else:
                self.db.rollback()
        finally:
            self._lookup.cache_clear()
            self.db.close()
            self.lock.__exit__(kind,value,traceback)
