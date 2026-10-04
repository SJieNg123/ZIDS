"""Streaming preparation with strictly separate public and server-private files."""
from dataclasses import asdict
import hashlib
import json
import mmap
import os
from pathlib import Path

from . import OT_SUITE, VERSION
from .codec import Params
from .contracts import ProtocolError, bounded_int
from .gdfa import Garbler

PUBLIC_FIELDS = {'version', 'suite', 'session', 'params', 'initial_state', 'initial_pad',
                 'matrix_bytes', 'matrix_sha256'}
PARAM_FIELDS = {'n', 'q', 'outmax', 'cmax', 'k'}


def write_json(path, value, *, exclusive=True):
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as file:
        json.dump(value, file, sort_keys=True, indent=2)
        file.write('\n')
        file.flush()
        os.fsync(file.fileno())


def read_json(path, limit=16384):
    with open(path, 'rb') as file:
        data = file.read() if limit is None else file.read(limit+1)
    if limit is not None and len(data) > limit:
        raise ProtocolError('manifest too large')
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ProtocolError('duplicate JSON field')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeError) as exc:
        raise ProtocolError('invalid manifest JSON') from exc


def digest_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as file:
        for block in iter(lambda: file.read(1024*1024), b''):
            digest.update(block)
    return digest.hexdigest()


def validate_public(manifest):
    if type(manifest) is not dict or set(manifest) != PUBLIC_FIELDS:
        raise ProtocolError('unexpected public manifest fields')
    if type(manifest['version']) is not int or manifest['version'] != VERSION or manifest['suite'] != OT_SUITE:
        raise ProtocolError('unsupported public format')
    if type(manifest['params']) is not dict or set(manifest['params']) != PARAM_FIELDS:
        raise ProtocolError('invalid parameter fields')
    params = Params(**manifest['params'])
    for name, length in [('session',16), ('initial_pad',16), ('matrix_sha256',32)]:
        value = manifest[name]
        if type(value) is not str or len(value) != 2*length:
            raise ProtocolError(f'invalid {name}')
        try:
            if bytes.fromhex(value).hex() != value:
                raise ValueError()
        except ValueError as exc:
            raise ProtocolError(f'invalid {name}') from exc
    bounded_int(manifest['initial_state'], 0, params.q-1, 'initial state')
    if type(manifest['matrix_bytes']) is not int or manifest['matrix_bytes'] != params.matrix_bytes:
        raise ProtocolError('incorrect matrix size')
    return params


def prepare(dfa, n, destination, *, provenance=None, limits=None):
    garbler = Garbler(dfa, n, limits=limits)
    p = garbler.params
    if 256*p.bundle_bytes > 64*1024*1024-32:
        raise ProtocolError('single OT table exceeds transfer bound')
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    public, private = root/'public', root/'private'
    public.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    matrix_hash, ot_hash = hashlib.sha256(), hashlib.sha256()
    with open(public/'matrix.bin', 'xb') as matrix, open(private/'ot_messages.bin', 'xb') as ot:
        for _, row, bundles in garbler.rows():
            matrix.write(row)
            matrix_hash.update(row)
            for bundle in bundles:
                ot.write(bundle)
                ot_hash.update(bundle)
        for file in (matrix, ot):
            file.flush()
            os.fsync(file.fileno())
    manifest = {'version':VERSION, 'suite':OT_SUITE, 'session':garbler.session.hex(),
                'params':asdict(p), 'initial_state':garbler.initial_state,
                'initial_pad':garbler.initial_pad.hex(), 'matrix_bytes':p.matrix_bytes,
                'matrix_sha256':matrix_hash.hexdigest()}
    validate_public(manifest)
    write_json(public/'manifest.json', manifest)
    write_json(private/'manifest.json', {'public':manifest, 'provenance':provenance or {},
               'ot_bytes':p.n*256*p.bundle_bytes, 'ot_sha256':ot_hash.hexdigest()})
    from .lifecycle import initialize
    initialize(root, manifest['session'])
    return manifest


def private_tables(directory, *, verify=True):
    private = Path(directory)
    manifest = read_json(private/'manifest.json', limit=1024*1024)
    if type(manifest) is not dict or set(manifest) != {'public', 'provenance', 'ot_bytes', 'ot_sha256'}:
        raise ProtocolError('invalid private manifest')
    p = validate_public(manifest['public'])
    path = private/'ot_messages.bin'
    expected = p.n*256*p.bundle_bytes
    if type(manifest['ot_bytes']) is not int or manifest['ot_bytes'] != expected or path.stat().st_size != expected:
        raise ProtocolError('private OT file length mismatch')
    if verify and digest_file(path) != manifest['ot_sha256']:
        raise ProtocolError('private OT file digest mismatch')
    with open(path, 'rb') as file:
        for _ in range(p.n):
            data = file.read(256*p.bundle_bytes)
            if len(data) != 256*p.bundle_bytes:
                raise ProtocolError('truncated private OT file')
            yield tuple(data[i:i+p.bundle_bytes] for i in range(0, len(data), p.bundle_bytes))


class MatrixReader:
    def __init__(self, public_directory, *, limits=None):
        directory = Path(public_directory)
        self.manifest = read_json(directory/'manifest.json')
        self.params = validate_public(self.manifest)
        self.params.enforce_limits(**(limits or {}))
        path = directory/'matrix.bin'
        if path.stat().st_size != self.params.matrix_bytes:
            raise ProtocolError('matrix size mismatch')
        if digest_file(path) != self.manifest['matrix_sha256']:
            raise ProtocolError('matrix digest mismatch')
        self._file = open(path, 'rb')
        try:
            self._map = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        except BaseException:
            self._file.close()
            raise

    def cell(self, position, state):
        p = self.params
        bounded_int(position, 0, p.n-1, 'position')
        bounded_int(state, 0, p.q-1, 'state')
        offset = (position*p.q+state)*p.cell_bytes
        return self._map[offset:offset+p.cell_bytes]

    def close(self):
        self._map.close()
        self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
