"""Naor-Pinkas Protocol 3.1, N=2, amortized within one fresh batch.

See docs/ot_suite.md. This is public-key base OT, never OT extension.
"""
import hashlib
import hmac

from .contracts import OTContext, Once, ProtocolError, bounded_int
from .crypto import base, multiply, random_scalar, require_point, ro_pad, subtract, valid_point, xor
from .wire import Kind, MAX_FRAME


def context_tag(context):
    return hashlib.sha256(context.encode()).digest()


class Sender:
    def __init__(self, messages, context: OTContext):
        self.context = context
        if 32 + context.count * 2 * context.message_bytes > MAX_FRAME:
            raise ProtocolError("base OT batch exceeds frame limit")
        if len(messages) != context.count:
            raise ProtocolError("message count mismatch")
        for pair in messages:
            if len(pair) != 2 or any(type(x) is not bytes or len(x) != context.message_bytes for x in pair):
                raise ProtocolError("base OT messages must be equal-length byte pairs")
        self._messages = tuple(tuple(pair) for pair in messages)
        self._r = random_scalar()
        self.C = base(random_scalar())
        self.A = base(self._r)
        self._rC = multiply(self._r, self.C)
        self._offer = context_tag(context) + self.C + self.A
        self._once = Once()

    def offer(self):
        return self._offer

    def answer(self, query):
        self._once.consume()
        try:
            if type(query) is not bytes or len(query) != 32 * self.context.count:
                raise ProtocolError("invalid base OT query length")
            points = [query[i:i+32] for i in range(0, len(query), 32)]
            for point in points:
                require_point(point)
                require_point(subtract(self.C, point))
            transcript = hashlib.sha256(self._offer + query).digest()
            result = bytearray(transcript)
            for i, (point, messages) in enumerate(zip(points, self._messages)):
                shared0 = multiply(self._r, point)
                shared1 = subtract(self._rC, shared0)
                for branch, shared in enumerate((shared0, shared1)):
                    result.extend(xor(messages[branch], ro_pad(shared, transcript, i, branch,
                                                             self.context.message_bytes)))
            return bytes(result)
        finally:
            self._r = None
            self._rC = None
            self._messages = ()


class Receiver:
    def __init__(self, choices, context: OTContext):
        if len(choices) != context.count:
            raise ProtocolError("choice count mismatch")
        self._choices = tuple(bounded_int(x, 0, 1, "bit choice") for x in choices)
        self.context = context
        self._query_once = Once()
        self._finish_once = Once()
        self._secrets = ()
        self._transcript = None

    def query(self, offer):
        self._query_once.consume()
        if (type(offer) is not bytes or len(offer) != 96
                or not hmac.compare_digest(offer[:32], context_tag(self.context))):
            raise ProtocolError("invalid base OT setup")
        C, A = require_point(offer[32:64]), require_point(offer[64:96])
        query = bytearray()
        secrets_for_batch = []
        for choice in self._choices:
            while True:
                scalar = random_scalar()
                point = base(scalar)
                other = subtract(C, point)
                if valid_point(other):
                    break
            query.extend((point, other)[choice])
            secrets_for_batch.append(scalar)
        self._secrets = tuple(secrets_for_batch)
        self._A = A
        query = bytes(query)
        self._transcript = hashlib.sha256(offer + query).digest()
        return query

    def finish(self, response):
        self._finish_once.consume()
        try:
            length = self.context.message_bytes
            if (self._transcript is None or type(response) is not bytes
                    or len(response) != 32 + 2 * self.context.count * length
                    or not hmac.compare_digest(response[:32], self._transcript)):
                raise ProtocolError("invalid base OT response")
            result = []
            for i, (choice, scalar) in enumerate(zip(self._choices, self._secrets)):
                shared = multiply(scalar, self._A)
                offset = 32 + (2*i + choice) * length
                result.append(xor(response[offset:offset+length],
                                  ro_pad(shared, self._transcript, i, choice, length)))
            return result
        finally:
            self._secrets = ()


def send_bits(channel, messages, context):
    sender = Sender(messages, context)
    channel.send(Kind.SETUP, context, sender.offer())
    query = channel.receive(Kind.QUERY, context, size=32*context.count)
    channel.send(Kind.RESPONSE, context, sender.answer(query))
    channel.metrics.base_transfers += context.count
    channel.metrics.scalar_multiplications += context.count + 3


def receive_bits(channel, choices, context):
    receiver = Receiver(choices, context)
    query = receiver.query(channel.receive(Kind.SETUP, context, size=96))
    channel.send(Kind.QUERY, context, query)
    result = receiver.finish(channel.receive(Kind.RESPONSE, context,
                                            size=32+2*context.count*context.message_bytes))
    channel.metrics.base_transfers += context.count
    channel.metrics.scalar_multiplications += 2*context.count
    return result
