"""Detached local jobs with persistent logs and honest interruption status."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

from src.zids.local_state import atomic_json, exclusive_lock

ROOT = Path(__file__).resolve().parents[1]
TERMINAL = {'SUCCEEDED','FAILED','LAUNCH_FAILED','INTERRUPTED','SUPERVISOR_LOST'}


def now():
    return datetime.now(timezone.utc).isoformat()


def status(directory, *, reconcile=True):
    root = Path(directory)
    value = json.loads((root/'job.json').read_text(encoding='utf8'))
    if reconcile and value['state'] == 'RUNNING':
        try:
            with exclusive_lock(root/'supervisor.lock'):
                value = json.loads((root/'job.json').read_text(encoding='utf8'))
                if value['state'] == 'RUNNING':
                    value.update(state='SUPERVISOR_LOST',observed_utc=now(),exit_code=None,
                                 error='supervisor absent, worker outcome unknown')
                    atomic_json(root/'job.json',value)
        except BlockingIOError:
            pass
    return value


def supervise(directory):
    root = Path(directory).resolve()
    with exclusive_lock(root/'supervisor.lock'):
        record = status(root,reconcile=False)
        if record['state'] != 'QUEUED':
            raise ValueError('job has already been launched')
        record.update(state='RUNNING',supervisor_pid=os.getpid(),started_utc=now(),heartbeat_utc=now())
        atomic_json(root/'job.json',record)
        child = None
        with (root/'stdout.log').open('ab',buffering=0) as stdout, (root/'stderr.log').open('ab',buffering=0) as stderr:
            try:
                flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                child = subprocess.Popen(record['command'],cwd=record['cwd'],stdin=subprocess.DEVNULL,
                                         stdout=stdout,stderr=stderr,creationflags=flags)
                record['worker_pid'] = child.pid
                while child.poll() is None:
                    record['heartbeat_utc'] = now()
                    atomic_json(root/'job.json',record)
                    time.sleep(1)
                record.update(state='SUCCEEDED' if child.returncode == 0 else 'FAILED',exit_code=child.returncode)
            except BaseException as exc:
                stderr.write(traceback.format_exc().encode('utf8'))
                record.update(state='INTERRUPTED' if isinstance(exc,KeyboardInterrupt) else 'FAILED',
                              error_type=type(exc).__name__,error=str(exc),exit_code=None)
                if child is not None and child.poll() is None:
                    child.terminate()
                    child.wait()
                    record['exit_code'] = child.returncode
            finally:
                record.update(finished_utc=now(),heartbeat_utc=now())
                atomic_json(root/'job.json',record)
    return 0 if record['state'] == 'SUCCEEDED' else 2


def start(directory, command, *, cwd=None):
    root = Path(directory).resolve()
    if not command:
        raise ValueError('a command argument list is required')
    root.mkdir(parents=True,exist_ok=False,mode=0o700)
    record = dict(version=1,state='QUEUED',created_utc=now(),command=list(command),
                  cwd=str(Path(cwd or Path.cwd()).resolve()),exit_code=None)
    atomic_json(root/'job.json',record)
    arguments = [sys.executable,'-B','-X','utf8','-m','tools.jobs','supervise','--directory',str(root)]
    options = {'start_new_session':True} if os.name != 'nt' else {
        'creationflags':subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP}
    try:
        with (root/'supervisor.log').open('ab',buffering=0) as log:
            process = subprocess.Popen(arguments,cwd=ROOT,stdin=subprocess.DEVNULL,
                                       stdout=log,stderr=log,close_fds=True,**options)
        # This is only a launch acknowledgement, never a workload deadline.
        deadline = time.monotonic()+15
        while time.monotonic() < deadline:
            value = status(root,reconcile=False)
            if value['state'] != 'QUEUED':
                return value
            if process.poll() is not None:
                raise RuntimeError('supervisor failed before acknowledging launch')
            time.sleep(0.05)
        return dict(record,launch_acknowledgement='pending',supervisor_pid=process.pid)
    except Exception as exc:
        record.update(state='LAUNCH_FAILED',error=str(exc),finished_utc=now())
        atomic_json(root/'job.json',record)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action',required=True)
    for name in ('start','status','supervise'):
        item = commands.add_parser(name)
        item.add_argument('--directory',required=True)
        if name == 'start':
            item.add_argument('--cwd')
            item.add_argument('command',nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.action == 'supervise':
        return supervise(args.directory)
    if args.action == 'start':
        command = args.command[1:] if args.command[:1] == ['--'] else args.command
        value = start(args.directory,command,cwd=args.cwd)
    else:
        value = status(args.directory)
    print(json.dumps(value,sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
