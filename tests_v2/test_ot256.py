import secrets
import unittest

from src.zids_v2.contracts import OTContext, ProtocolError
from src.zids_v2.crypto import xor
from src.zids_v2.ot256 import Sender, Receiver


class ByteOTTests(unittest.TestCase):
    def test_all_choices_with_real_base_ot(self):
        for choice in range(256):
            context = OTContext(secrets.token_bytes(16), choice, 1, 17)
            messages = [bytes([i])+secrets.token_bytes(16) for i in range(256)]
            sender = Sender([messages], context)
            receiver = Receiver([choice], context)
            response = sender.answer(receiver.query(sender.offer()))
            self.assertEqual(receiver.finish(response, sender.ciphertexts), [messages[choice]])

    def test_four_ciphertext_xor_no_longer_discloses_plaintext_relation(self):
        context = OTContext(secrets.token_bytes(16), 0, 1, 32)
        messages = [bytes([i])*32 for i in range(256)]
        messages[3] = b"\x04"*32
        sender = Sender([messages], context)
        plaintext_xor = ciphertext_xor = bytes(32)
        for i in range(4):
            plaintext_xor = xor(plaintext_xor, messages[i])
            ciphertext_xor = xor(ciphertext_xor, sender.ciphertexts[32+32*i:64+32*i])
        self.assertEqual(plaintext_xor, b"\x07"*32)
        self.assertNotEqual(ciphertext_xor, plaintext_xor)

    def test_invalid_tables_replay_and_cross_session(self):
        context = OTContext(secrets.token_bytes(16), 0, 1, 1)
        messages = [bytes([i]) for i in range(256)]
        with self.assertRaises(ProtocolError):
            Sender([messages[:-1]], context)
        for choice in (-1, 256, True):
            with self.assertRaises(ProtocolError):
                Receiver([choice], context)
        sender = Sender([messages], context)
        receiver = Receiver([123], context)
        response = sender.answer(receiver.query(sender.offer()))
        other = Sender([messages], OTContext(secrets.token_bytes(16), 0, 1, 1))
        with self.assertRaises(ProtocolError):
            receiver.finish(response, other.ciphertexts)
        with self.assertRaises(ProtocolError):
            receiver.finish(response, sender.ciphertexts)


if __name__ == '__main__':
    unittest.main()
