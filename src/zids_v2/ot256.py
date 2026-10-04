"""Naor-Pinkas Protocol 2.1: byte OT from eight chosen-seed base OTs.

Every PRF includes the complete option index. Omitting it leaks XOR relations.
"""
import hashlib
import hmac
import secrets

from . import base_ot
from .contracts import OTContext, Once, ProtocolError, bounded_int
from .crypto import fields, prf, xor
from .wire import MAX_FRAME


def bit_context(context):
    return OTContext(context.session, context.batch, 8 * context.count, 32, context.suite)


def option_domain(context, position, bit, option):
    return fields(b"NP/Protocol-2.1", context.encode(), position.to_bytes(4, "big"),
                  bytes([bit, option]))


def mask(context, position, option, selected_seeds):
    if len(selected_seeds) != 8 or any(len(s) != 32 for s in selected_seeds):
        raise ProtocolError("invalid reduction seeds")
    pad = bytes(context.message_bytes)
    for j, seed in enumerate(selected_seeds):
        pad = xor(pad, prf(seed, option_domain(context, position, j, option), context.message_bytes))
    return pad


class Sender:
    def __init__(self, message_tables, context: OTContext):
        self.context = context
        if len(message_tables) != context.count or 32 + context.count*256*context.message_bytes > MAX_FRAME:
            raise ProtocolError("invalid byte OT batch dimensions")
        for table in message_tables:
            if len(table) != 256 or any(type(m) is not bytes or len(m) != context.message_bytes for m in table):
                raise ProtocolError("OT requires 256 equal-length messages per position")
        self._pairs = [(secrets.token_bytes(32), secrets.token_bytes(32))
                       for _ in range(8 * context.count)]
        encrypted = bytearray(hashlib.sha256(context.encode()).digest())
        for position, table in enumerate(message_tables):
            pairs = self._pairs[8*position:8*position+8]
            for option, message in enumerate(table):
                seeds = [pair[(option >> j) & 1] for j, pair in enumerate(pairs)]
                encrypted.extend(xor(message, mask(context, position, option, seeds)))
        self.ciphertexts = bytes(encrypted)
        self._bit_sender = base_ot.Sender(self._pairs, bit_context(context))
        self._pairs = ()

    def offer(self):
        return self._bit_sender.offer()

    def answer(self, query):
        return self._bit_sender.answer(query)


class Receiver:
    def __init__(self, choices, context: OTContext):
        if len(choices) != context.count:
            raise ProtocolError("byte choice count mismatch")
        self._choices = tuple(bounded_int(x, 0, 255, "byte choice") for x in choices)
        self.context = context
        bits = [(x >> j) & 1 for x in self._choices for j in range(8)]
        self._bit_receiver = base_ot.Receiver(bits, bit_context(context))
        self._once = Once()

    def query(self, offer):
        return self._bit_receiver.query(offer)

    def finish(self, response, ciphertexts):
        self._once.consume()
        context = self.context
        if (type(ciphertexts) is not bytes or len(ciphertexts) != 32+context.count*256*context.message_bytes
                or not hmac.compare_digest(ciphertexts[:32], hashlib.sha256(context.encode()).digest())):
            raise ProtocolError("invalid byte OT ciphertext table")
        seeds = self._bit_receiver.finish(response)
        result = []
        length = context.message_bytes
        for position, choice in enumerate(self._choices):
            offset = 32 + (position*256+choice)*length
            pad = mask(context, position, choice, seeds[8*position:8*position+8])
            result.append(xor(ciphertexts[offset:offset+length], pad))
        return result
