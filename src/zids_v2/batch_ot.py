"""Bounded-memory batching of real base OTs, with no OT extension."""
from itertools import islice
import struct

from . import OT_SUITE
from .contracts import OTContext, ProtocolError, bounded_int
from .ot256 import Sender, Receiver
from .wire import Kind, MAX_FRAME

FRAGMENT = struct.Struct('!QQ')
OPTION_CHUNK_BYTES = 1024*1024


def option_frames(context, max_frame=MAX_FRAME):
    total = 32+context.count*256*context.message_bytes
    size = min(OPTION_CHUNK_BYTES,max_frame-FRAGMENT.size)
    if size < 1:
        raise ProtocolError('frame capacity too small for option fragments')
    for offset in range(0,total,size):
        yield offset,min(size,total-offset)


def send_options(channel, context, chunks, sequence):
    iterator, pending = iter(chunks),bytearray()
    for offset, size in option_frames(context,channel.max_frame):
        while len(pending) < size:
            part = next(iterator,None)
            if part is None:
                raise ProtocolError('truncated outgoing OT options')
            pending.extend(part)
        payload = FRAGMENT.pack(context.batch,offset)+bytes(pending[:size])
        del pending[:size]
        frame = OTContext(context.session,sequence,context.count,context.message_bytes,context.suite)
        channel.send(Kind.OPTIONS_FRAGMENT,frame,payload)
        sequence += 1
    if pending or next(iterator,None) is not None:
        raise ProtocolError('extra outgoing OT options')
    return sequence


def receive_options(channel, context, sequence):
    for offset, size in option_frames(context,channel.max_frame):
        frame = OTContext(context.session,sequence,context.count,context.message_bytes,context.suite)
        payload = channel.receive(Kind.OPTIONS_FRAGMENT,frame,size=FRAGMENT.size+size)
        if FRAGMENT.unpack(payload[:FRAGMENT.size]) != (context.batch,offset):
            raise ProtocolError('wrong OT fragment batch or offset')
        yield payload[FRAGMENT.size:]
        sequence += 1


def contexts(context, batch_size=16):
    bounded_int(batch_size, 1, 8192, "batch size")
    capacity = max(1,min(batch_size,(MAX_FRAME-32)//(256*context.message_bytes)))
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
        sequence = 0
        for _, chunk in contexts(context, self.batch_size):
            tables = list(islice(iterator, chunk.count))
            sender = Sender(tables, chunk)
            channel.send(Kind.SETUP, chunk, sender.offer())
            query = channel.receive(Kind.QUERY, chunk, size=32*8*chunk.count)
            channel.send(Kind.RESPONSE, chunk, sender.answer(query))
            sequence = send_options(channel,chunk,sender.ciphertext_chunks(),sequence)
            channel.metrics.base_transfers += 8*chunk.count
            channel.metrics.scalar_multiplications += 8*chunk.count+3
        if next(iterator, None) is not None:
            raise ProtocolError("too many position tables")

    def receive(self, channel, choices, context, *, sink=None):
        if context.suite != self.suite or len(choices) != context.count:
            raise ProtocolError("suite or choice count mismatch")
        result = []
        sequence = 0
        for offset, chunk in contexts(context, self.batch_size):
            receiver = Receiver(choices[offset:offset+chunk.count], chunk)
            offer = channel.receive(Kind.SETUP, chunk, size=96)
            channel.send(Kind.QUERY, chunk, receiver.query(offer))
            response = channel.receive(Kind.RESPONSE, chunk, size=32+2*8*chunk.count*32)
            result.extend(receiver.finish_stream(response,receive_options(channel,chunk,sequence),sink=sink))
            sequence += sum(1 for _ in option_frames(chunk,channel.max_frame))
            channel.metrics.base_transfers += 8*chunk.count
            channel.metrics.scalar_multiplications += 16*chunk.count
        return result
