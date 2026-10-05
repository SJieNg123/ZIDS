"""Versioned private binary policy with compact mmap transitions and a digest."""
from array import array
from contextlib import contextmanager
import hashlib
import json
import mmap
import os
from pathlib import Path
import struct
import sys
import tempfile

from .artifacts import read_json
from .compiler import COMPILER_VERSION, policy_dfa
from .contracts import ProtocolError
from .dfa import DFA
from .easylist import PROFILE
from .packed import PackedTransitions

MAGIC = b'ZPOLv1\0\0'
HEADER = struct.Struct('<8sQQHQ')


def save_policy(path, dfa, provenance, *, exclusive=True):
    path = Path(path)
    table = dfa.transitions
    packed = isinstance(table,PackedTransitions)
    mapping = table.mapping if packed else bytes(range(256))
    columns = max(mapping)+1
    metadata = json.dumps({'version':COMPILER_VERSION,'profile':PROFILE,'provenance':provenance},
                          sort_keys=True,separators=(',',':')).encode('utf8')
    fd, temporary = tempfile.mkstemp(prefix=path.name+'.',suffix='.tmp',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as file:
            digest = hashlib.sha256()
            def write(data):
                file.write(data)
                digest.update(data)
            write(HEADER.pack(MAGIC,dfa.q,dfa.start,columns,len(metadata)))
            write(mapping)
            write(metadata)
            for offset in range(0,dfa.q,1024*1024):
                write(bytes(dfa.outputs[offset:offset+1024*1024]))
            if packed:
                for offset in range(0,len(table.data),131072):
                    block = array('Q',table.data[offset:offset+131072])
                    if sys.byteorder != 'little':
                        block.byteswap()
                    write(block.tobytes())
            else:
                for row in table:
                    write(struct.pack('<256Q',*row))
            file.write(digest.digest())
            file.flush()
            os.fsync(file.fileno())
        if exclusive:
            os.link(temporary,path)
        else:
            os.replace(temporary,path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def unique(pairs):
    result = {}
    for key,value in pairs:
        if key in result:
            raise ProtocolError('duplicate policy metadata field')
        result[key] = value
    return result


@contextmanager
def open_policy(path):
    path = Path(path)
    with path.open('rb') as file:
        magic = file.read(8)
        if magic != MAGIC:
            # Read legacy JSON explicitly, without the former 128 MiB cap.
            if magic.lstrip()[:1] != b'{':
                raise ProtocolError('unknown private policy format')
            value = read_json(path,limit=None)
            yield policy_dfa(value),value['provenance']
            return
        file.seek(0)
        raw = file.read(HEADER.size)
        if len(raw) != HEADER.size:
            raise ProtocolError('truncated policy header')
        _, q, start, columns, metadata_bytes = HEADER.unpack(raw)
        if q < 1 or start >= q or not 1 <= columns <= 256:
            raise ProtocolError('invalid binary policy dimensions')
        data_offset = HEADER.size+256+metadata_bytes+q
        total = data_offset+q*columns*8+32
        if file.seek(0,os.SEEK_END) != total:
            raise ProtocolError('binary policy size mismatch')
        file.seek(0)
        digest = hashlib.sha256()
        remaining = total-32
        while remaining:
            chunk = file.read(min(1024*1024,remaining))
            if not chunk:
                raise ProtocolError('truncated binary policy')
            digest.update(chunk)
            remaining -= len(chunk)
        if digest.digest() != file.read(32):
            raise ProtocolError('binary policy digest mismatch')
        file.seek(HEADER.size)
        mapping = file.read(256)
        try:
            metadata = json.loads(file.read(metadata_bytes),object_pairs_hook=unique)
        except (ValueError,UnicodeError) as exc:
            raise ProtocolError('invalid policy metadata') from exc
        if (type(metadata) is not dict or set(metadata) != {'version','profile','provenance'}
                or metadata['version'] != COMPILER_VERSION or metadata['profile'] != PROFILE):
            raise ProtocolError('unsupported private policy metadata')
        outputs = file.read(q)
        if max(mapping)+1 != columns:
            raise ProtocolError('policy alphabet width mismatch')
        mapped = mmap.mmap(file.fileno(),0,access=mmap.ACCESS_READ)
        view = memoryview(mapped)[data_offset:total-32]
        values = view.cast('Q')
        view.release()
        try:
            if sys.byteorder != 'little':
                copied = array('Q',values)
                copied.byteswap()
                table = PackedTransitions(mapping,copied)
            else:
                table = PackedTransitions(mapping,values)
            yield DFA(table,outputs,start),metadata['provenance']
        finally:
            values.release()
            mapped.close()
