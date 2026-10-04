"""Bounded-memory batching of real base OTs, with no OT extension."""
from itertools import islice

from . import OT_SUITE
from .contracts import OTContext, ProtocolError, bounded_int
from .ot256 import Sender, Receiver
from .wire import Kind, MAX_FRAME


def contexts(context, batch_size=16):
    bounded_int(batch_size, 1, 8192, "batch size")
    capacity = min(batch_size, (MAX_FRAME - 32) // (256 * context.message_bytes))
    if capacity < 1:
        raise ProtocolError("one OT table exceeds frame limit")
    for batch, offset in enumerate(range(0, context.count, capacity), start=context.batch):
        yield offset, OTContext(context.session, batch, min(capacity, context.count-offset),
                                context.message_bytes, context.suite)


class BaseOTBackend:
    """The sender takes only tables, the receiver takes only byte choices."""
    def __init__(self, suite=OT_SUITE, *, batch_size=16):
        if suite != OT_SUITE:
            raise ProtocolError("unsupported backend, OT extension is excluded")
        bounded_int(batch_size, 1, 8192, "batch size")
        self.suite = suite
        self.batch_size = batch_size

    def send(self, channel, message_tables, context):
        if context.suite != self.suite:
            raise ProtocolError("suite mismatch")
        iterator = iter(message_tables)
        for _, chunk in contexts(context, self.batch_size):
            tables = list(islice(iterator, chunk.count))
            sender = Sender(tables, chunk)
            channel.send(Kind.SETUP, chunk, sender.offer())
            query = channel.receive(Kind.QUERY, chunk, size=32*8*chunk.count)
            channel.send(Kind.RESPONSE, chunk, sender.answer(query))
            channel.send(Kind.OPTIONS, chunk, sender.ciphertexts)
            channel.metrics.base_transfers += 8*chunk.count
            channel.metrics.scalar_multiplications += 8*chunk.count+3
        if next(iterator, None) is not None:
            raise ProtocolError("too many position tables")

    def receive(self, channel, choices, context):
        if context.suite != self.suite or len(choices) != context.count:
            raise ProtocolError("suite or choice count mismatch")
        result = []
        for offset, chunk in contexts(context, self.batch_size):
            receiver = Receiver(choices[offset:offset+chunk.count], chunk)
            offer = channel.receive(Kind.SETUP, chunk, size=96)
            channel.send(Kind.QUERY, chunk, receiver.query(offer))
            response = channel.receive(Kind.RESPONSE, chunk, size=32+2*8*chunk.count*32)
            ciphertexts = channel.receive(Kind.OPTIONS, chunk,
                                          size=32+chunk.count*256*chunk.message_bytes)
            result.extend(receiver.finish(response, ciphertexts))
            channel.metrics.base_transfers += 8*chunk.count
            channel.metrics.scalar_multiplications += 16*chunk.count
        return result
