"""One connection transfers public data and real base OT, never a verdict."""
from dataclasses import asdict
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
from time import perf_counter

from .artifacts import MatrixReader, read_json, write_json, private_tables, validate_public
from .batch_ot import BaseOTBackend
from .contracts import OTContext, ProtocolError, bounded_int
from .gdfa import evaluate
from .lifecycle import Reservation, state
from .wire import Channel, Kind

CHUNK_BYTES = 1024*1024
BOOTSTRAP = OTContext(bytes(16), 0, 1, 1)
TRANSPORT = 'base-ot-fragments-v1'


def transport_context(host, *, server=False, cert=None, key=None, ca=None):
    if not any((cert,key,ca)):
        try:
            local = ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = False
        if not local:
            raise ProtocolError('remote transport requires mutual TLS with cert, key and ca')
        return None
    if not all((cert,key,ca)):
        raise ProtocolError('mutual TLS requires cert, key and ca together')
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) if server else ssl.create_default_context(cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    if server:
        ctx.load_verify_locations(cafile=ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def serve_connection(connection, root, *, batch_size=16):
    root = Path(root)
    backend = BaseOTBackend(batch_size=batch_size)
    started = perf_counter()
    with connection, Reservation(root), Channel(connection) as wire:
        # Verify the complete public file locally before exposing a manifest.
        with MatrixReader(root/'public') as reader:
            manifest, p = reader.manifest, reader.params
        private = read_json(root/'private/manifest.json', limit=1024*1024)
        if private['public'] != manifest:
            raise ProtocolError('private and public session manifests differ')
        sid = bytes.fromhex(manifest['session'])
        context = OTContext(sid, 0, p.n, p.bundle_bytes)
        envelope = {'manifest':manifest, 'batch_size':batch_size, 'transport':TRANSPORT}
        wire.send(Kind.MANIFEST, BOOTSTRAP, json.dumps(envelope, sort_keys=True).encode('ascii'))
        with open(root/'public/matrix.bin', 'rb') as matrix:
            for chunk, offset in enumerate(range(0, p.matrix_bytes, CHUNK_BYTES)):
                part = matrix.read(min(CHUNK_BYTES, p.matrix_bytes-offset))
                wire.send(Kind.MATRIX, OTContext(sid,chunk,p.n,p.bundle_bytes), part)
        prepared = perf_counter()
        backend.send(wire, private_tables(root/'private',lazy=True), context)
        finished = perf_counter()
        metrics = asdict(wire.metrics)
    return {'session':sid.hex(), 'metrics':metrics, 'prefetch_seconds':prepared-started,
            'ot_seconds':finished-prepared, 'online_seconds':finished-started}


def serve(root, host='127.0.0.1', port=8787, *, batch_size=16, cert=None, key=None, ca=None,
          ready=None, accept_timeout=120):
    tls = transport_context(host, server=True, cert=cert, key=key, ca=ca)
    if state(root)['state'] != 'PREPARED':
        raise ProtocolError('session is not available for a fresh evaluation')
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    with socket.socket(family) as listener:
        listener.bind((host, port))
        listener.listen(1)
        listener.settimeout(accept_timeout)
        if ready:
            ready(listener.getsockname()[1])
        connection, _ = listener.accept()
        connection.settimeout(120)
        if tls:
            try:
                connection = tls.wrap_socket(connection, server_side=True)
            except BaseException:
                connection.close()
                raise
        return serve_connection(connection, root, batch_size=batch_size)


def receive_connection(connection, request, destination):
    data = request.encode()
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    started = perf_counter()
    with connection, Channel(connection) as wire:
        raw = wire.receive(Kind.MANIFEST, BOOTSTRAP, max_size=16384)
        # Reuse the strict duplicate-field JSON parser and preserve the received data.
        (root/'bootstrap.json').write_bytes(raw)
        envelope = read_json(root/'bootstrap.json')
        if (type(envelope) is not dict or set(envelope) != {'manifest','batch_size','transport'}
                or envelope['transport'] != TRANSPORT):
            raise ProtocolError('invalid bootstrap fields')
        manifest = envelope['manifest']
        p = validate_public(manifest)
        p.enforce_limits()
        batch_size = bounded_int(envelope['batch_size'], 1, 8192, 'batch size')
        if p.n != len(data):
            raise ProtocolError('encoded input length differs from public session length')
        sid = bytes.fromhex(manifest['session'])
        write_json(root/'manifest.json', manifest)
        with open(root/'matrix.bin','xb') as matrix:
            for chunk, offset in enumerate(range(0, p.matrix_bytes, CHUNK_BYTES)):
                size = min(CHUNK_BYTES, p.matrix_bytes-offset)
                matrix.write(wire.receive(Kind.MATRIX, OTContext(sid,chunk,p.n,p.bundle_bytes), size=size))
            matrix.flush()
            os.fsync(matrix.fileno())
        with MatrixReader(root) as reader, tempfile.SpooledTemporaryFile(max_size=1024*1024,mode='w+b') as selected:
            prefetched = perf_counter()
            BaseOTBackend(batch_size=batch_size).receive(wire,data,OTContext(sid,0,p.n,p.bundle_bytes),sink=selected.write)
            ot_finished = perf_counter()
            metrics = asdict(wire.metrics)
            # Close independently of the decision, before any path-dependent decoding.
            wire.close()
            selected.seek(0)
            bundles = iter(lambda:selected.read(p.bundle_bytes),b'')
            result = evaluate(p,sid,manifest['initial_state'],bytes.fromhex(manifest['initial_pad']),reader.cell,bundles)
    return {'decision':result, 'session':sid.hex(), 'n':p.n, 'metrics':metrics,
            'prefetch_seconds':prefetched-started, 'ot_seconds':ot_finished-prefetched,
            'decode_seconds':perf_counter()-ot_finished, 'online_seconds':perf_counter()-started}


def receive(request, destination, host='127.0.0.1', port=8787, *, cert=None, key=None, ca=None, server_name=None):
    tls = transport_context(host, cert=cert, key=key, ca=ca)
    connection = socket.create_connection((host,port), timeout=120)
    try:
        if tls:
            connection = tls.wrap_socket(connection, server_hostname=server_name or host)
        return receive_connection(connection, request, destination)
    finally:
        connection.close()
