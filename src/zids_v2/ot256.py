"""Naor-Pinkas Protocol 2.1: byte OT from eight chosen-seed base OTs.

Every PRF includes the complete option index. Omitting it leaks XOR relations.
"""
import hashlib
import hmac
import secrets
import tempfile

from . import base_ot
from .contracts import OTContext, Once, ProtocolError, bounded_int
from .crypto import fields, prf_slice, xor


def bit_context(context):
    return OTContext(context.session, context.batch, 8 * context.count, 32, context.suite)


def option_domain(context, position, bit, option):
    return fields(b"NP/Protocol-2.1", context.encode(), position.to_bytes(4, "big"),
                  bytes([bit, option]))


def mask(context, position, option, selected_seeds):
    return mask_slice(context,position,option,selected_seeds,0,context.message_bytes)


def mask_slice(context, position, option, selected_seeds, offset, size):
    if len(selected_seeds) != 8 or any(len(s) != 32 for s in selected_seeds):
        raise ProtocolError("invalid reduction seeds")
    pad = bytes(size)
    for j, seed in enumerate(selected_seeds):
        pad = xor(pad,prf_slice(seed,option_domain(context,position,j,option),context.message_bytes,offset,size))
    return pad


class Sender:
    def __init__(self, message_tables, context: OTContext):
        self.context = context
        if len(message_tables) != context.count:
            raise ProtocolError("invalid byte OT batch dimensions")
        for table in message_tables:
            if len(table) != 256:
                raise ProtocolError("OT requires 256 equal-length messages per position")
            if hasattr(table,'chunk'):
                if table.message_size != context.message_bytes:
                    raise ProtocolError('private OT message length mismatch')
            elif any(type(m) is not bytes or len(m) != context.message_bytes for m in table):
                raise ProtocolError('OT requires 256 equal-length messages per position')
        self._pairs = [(secrets.token_bytes(32), secrets.token_bytes(32))
                       for _ in range(8 * context.count)]
        self._tables = message_tables
        self._cipher_once, self._ciphertexts = Once(),None
        self._bit_sender = base_ot.Sender(self._pairs, bit_context(context))

    @property
    def ciphertexts(self):
        if self._ciphertexts is None:
            self._ciphertexts = b''.join(self.ciphertext_chunks())
        return self._ciphertexts

    def ciphertext_chunks(self, chunk_bytes=65536):
        if chunk_bytes < 1:
            raise ValueError('chunk size must be positive')
        self._cipher_once.consume()
        context = self.context
        try:
            yield hashlib.sha256(context.encode()).digest()
            for position, table in enumerate(self._tables):
                pairs = self._pairs[8*position:8*position+8]
                for option in range(256):
                    seeds = [pair[(option >> j) & 1] for j,pair in enumerate(pairs)]
                    for offset in range(0,context.message_bytes,chunk_bytes):
                        size = min(chunk_bytes,context.message_bytes-offset)
                        message = (table.chunk(option,offset,size) if hasattr(table,'chunk')
                                   else table[option][offset:offset+size])
                        if type(message) is not bytes or len(message) != size:
                            raise ProtocolError('invalid streamed OT message')
                        yield xor(message,mask_slice(context,position,option,seeds,offset,size))
        finally:
            self._pairs, self._tables = (),()

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
        if type(ciphertexts) is not bytes:
            self._once.consume()
            raise ProtocolError('invalid byte OT ciphertext table')
        return self.finish_stream(response,[ciphertexts])

    def finish_stream(self, response, chunks, *, sink=None):
        self._once.consume()
        context = self.context
        expected = 32+context.count*256*context.message_bytes
        # Read the entire public schedule before looking up any private choice.
        with tempfile.SpooledTemporaryFile(max_size=1024*1024,mode='w+b') as ciphertexts:
            received = 0
            for block in chunks:
                if type(block) is not bytes or received+len(block) > expected:
                    raise ProtocolError('invalid byte OT ciphertext length')
                ciphertexts.write(block)
                received += len(block)
            ciphertexts.seek(0)
            if received != expected or not hmac.compare_digest(ciphertexts.read(32),hashlib.sha256(context.encode()).digest()):
                raise ProtocolError('invalid byte OT ciphertext table')
            seeds = self._bit_receiver.finish(response)
            result = []
            length = context.message_bytes
            for position, choice in enumerate(self._choices):
                ciphertexts.seek(32+(position*256+choice)*length)
                selected = bytearray() if sink is None else None
                for offset in range(0,length,65536):
                    size = min(65536,length-offset)
                    block = xor(ciphertexts.read(size),mask_slice(context,position,choice,
                                seeds[8*position:8*position+8],offset,size))
                    if sink is None:
                        selected.extend(block)
                    else:
                        sink(block)
                if sink is None:
                    result.append(bytes(selected))
            return result
