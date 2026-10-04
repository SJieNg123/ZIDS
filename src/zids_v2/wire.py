"""Bounded binary framing over an authenticated socket or local test transport."""
import socket
import struct
from dataclasses import dataclass
from enum import IntEnum

from .contracts import OTContext, ProtocolError

MAGIC = b"ZIDSv2\x00\x00"
HEADER = struct.Struct("!8sB16sQQ")
MAX_FRAME = 64 * 1024 * 1024


class Kind(IntEnum):
    SETUP = 1
    QUERY = 2
    RESPONSE = 3
    OPTIONS = 4
    MANIFEST = 5
    MATRIX = 6
    INITIAL = 7


@dataclass
class Metrics:
    sent_bytes: int = 0
    received_bytes: int = 0
    sent_frames: int = 0
    received_frames: int = 0
    base_transfers: int = 0
    scalar_multiplications: int = 0


class Channel:
    def __init__(self, connection: socket.socket, *, max_frame=MAX_FRAME, timeout=120):
        if type(max_frame) is not int or not 1 <= max_frame <= MAX_FRAME:
            raise ProtocolError("invalid frame limit")
        self.socket = connection
        connection.settimeout(timeout)
        self.max_frame = max_frame
        self.metrics = Metrics()
        self._sent = set()
        self._received = set()

    def _read(self, size):
        chunks = bytearray()
        while len(chunks) < size:
            try:
                chunk = self.socket.recv(min(size - len(chunks), 1024 * 1024))
            except (OSError, TimeoutError) as exc:
                raise ProtocolError("transport read failed") from exc
            if not chunk:
                raise ProtocolError("truncated frame")
            self.metrics.received_bytes += len(chunk)
            chunks.extend(chunk)
        return bytes(chunks)

    def send(self, kind: Kind, context: OTContext, payload: bytes):
        if not isinstance(kind, Kind) or type(payload) is not bytes:
            raise ProtocolError("invalid frame type")
        key = (context.session, context.batch, kind)
        if key in self._sent:
            raise ProtocolError("duplicate outgoing frame")
        if len(payload) > self.max_frame:
            raise ProtocolError("frame too large")
        self._sent.add(key)
        data = HEADER.pack(MAGIC, kind, context.session, context.batch, len(payload)) + payload
        try:
            self.socket.sendall(data)
        except OSError as exc:
            raise ProtocolError("transport write failed") from exc
        self.metrics.sent_bytes += len(data)
        self.metrics.sent_frames += 1

    def receive(self, kind: Kind, context: OTContext, *, size=None, max_size=None):
        key = (context.session, context.batch, kind)
        if key in self._received:
            raise ProtocolError("duplicate incoming frame")
        self._received.add(key)
        magic, got_kind, session, batch, length = HEADER.unpack(self._read(HEADER.size))
        if (magic, got_kind, session, batch) != (MAGIC, kind, context.session, context.batch):
            raise ProtocolError("wrong version, role, session or batch")
        if length > self.max_frame or (size is not None and length != size) or (max_size is not None and length > max_size):
            raise ProtocolError("invalid frame length")
        payload = self._read(length)
        self.metrics.received_frames += 1
        return payload

    def close(self):
        self.socket.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
