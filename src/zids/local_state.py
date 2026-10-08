"""Atomic local metadata and OS locks, released even after process death."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile


def atomic_json(path, value):
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix=path.name+'.',suffix='.tmp',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf8',newline='\n') as file:
            json.dump(value,file,sort_keys=True,indent=2)
            file.write('\n')
            file.flush()
            os.fsync(file.fileno())
        os.replace(name,path)
        if os.name != 'nt':
            directory = os.open(path.parent,os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@contextmanager
def exclusive_lock(path):
    with open(path,'a+b') as file:
        file.seek(0,os.SEEK_END)
        if file.tell() == 0:
            file.write(b'0')
            file.flush()
        file.seek(0)
        if os.name == 'nt':
            import msvcrt
            try:
                msvcrt.locking(file.fileno(),msvcrt.LK_NBLCK,1)
            except OSError as exc:
                raise BlockingIOError('local state is in use') from exc
        else:
            import fcntl
            fcntl.flock(file,fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            file.seek(0)
            if os.name == 'nt':
                msvcrt.locking(file.fileno(),msvcrt.LK_UNLCK,1)
            else:
                fcntl.flock(file,fcntl.LOCK_UN)
