"""Public protocol contracts. Private messages and choices have separate APIs."""
from dataclasses import dataclass
from typing import Protocol, Sequence

from . import OT_SUITE


class ProtocolError(ValueError):
    """A local protocol rejection, never serialize its detail to the peer."""


def bounded_int(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise ProtocolError(f"invalid {name}")
    return value


@dataclass(frozen=True)
class OTContext:
    session: bytes
    batch: int
    count: int
    message_bytes: int
    suite: str = OT_SUITE

    def __post_init__(self):
        if type(self.session) is not bytes or len(self.session) != 16:
            raise ProtocolError("session must be 16 opaque bytes")
        if self.suite != OT_SUITE:
            raise ProtocolError("unsupported suite, OT extension is not supported")
        bounded_int(self.batch, 0, 2**64 - 1, "batch")
        bounded_int(self.count, 1, 65536, "count")
        bounded_int(self.message_bytes, 1, 8 * 1024 * 1024, "message length")

    def encode(self):
        return (self.suite.encode("ascii") + b"\x00" + self.session
                + self.batch.to_bytes(8, "big") + self.count.to_bytes(4, "big")
                + self.message_bytes.to_bytes(4, "big"))


class BitSender(Protocol):
    def send(self, channel, messages: Sequence[tuple[bytes, bytes]], context: OTContext) -> None:
        ...


class BitReceiver(Protocol):
    def receive(self, channel, choices: Sequence[int], context: OTContext) -> list[bytes]:
        ...


class Once:
    """Consume before processing untrusted input. Never reset after failure."""
    def __init__(self):
        self._used = False

    def consume(self):
        if self._used:
            raise ProtocolError("one-time material already consumed")
        self._used = True
