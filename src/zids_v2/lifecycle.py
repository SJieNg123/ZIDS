"""Durable fail-closed ownership of each fresh GDFA and its position bundles."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3

from .contracts import ProtocolError


def bindings(root):
    root = Path(root)
    return tuple(hashlib.sha256((root/role/'manifest.json').read_bytes()).hexdigest()
                 for role in ('public','private'))


@contextmanager
def database(root):
    path = (Path(root)/'private/lifecycle.sqlite').resolve()
    try:
        db = sqlite3.connect(path.as_uri()+'?mode=rw', uri=True, timeout=10)
        db.execute('PRAGMA synchronous=FULL')
    except sqlite3.Error as exc:
        raise ProtocolError('session lifecycle is missing or inaccessible') from exc
    try:
        yield db
    finally:
        db.close()


def initialize(root, session):
    path = Path(root)/'private/lifecycle.sqlite'
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    public, private = bindings(root)
    with database(root) as db, db:
        db.execute('CREATE TABLE session (id TEXT PRIMARY KEY, state TEXT NOT NULL, token TEXT, public_hash TEXT, private_hash TEXT)')
        db.execute('INSERT INTO session VALUES (?, ?, NULL, ?, ?)', (session,'PREPARED',public,private))


def state(root):
    with database(root) as db:
        record = db.execute('SELECT id, state FROM session').fetchone()
    if record is None:
        raise ProtocolError('incomplete session lifecycle')
    return {'session':record[0], 'state':record[1]}


class Reservation:
    def __init__(self, root):
        self.root, self.token = Path(root), secrets.token_hex(32)
        self.closed = False
        with database(root) as db, db:
            db.execute('BEGIN IMMEDIATE')
            record = db.execute('SELECT id, state, public_hash, private_hash FROM session').fetchone()
            if record is None or record[1] != 'PREPARED':
                raise ProtocolError('session is not available for a fresh evaluation')
            self.session = record[0]
            if bindings(root) != record[2:]:
                db.execute("UPDATE session SET state='BURNED'")
                db.commit()
                raise ProtocolError('session artifact binding changed')
            db.execute("UPDATE session SET state='RESERVED', token=?", (self.token,))

    def finish(self, success):
        if self.closed:
            raise ProtocolError('reservation already finalized')
        self.closed = True
        with database(self.root) as db, db:
            result = db.execute('UPDATE session SET state=?, token=NULL WHERE state=? AND token=?',
                                ('CONSUMED' if success else 'BURNED','RESERVED',self.token))
            if result.rowcount != 1:
                raise ProtocolError('reservation ownership changed')

    def __enter__(self):
        return self

    def __exit__(self, error_type, *_):
        self.finish(error_type is None)


def recover(root):
    """After stopping an abandoned server, burn its reservation. Never rearm."""
    with database(root) as db, db:
        db.execute("UPDATE session SET state='BURNED', token=NULL WHERE state='RESERVED'")
    return state(root)
