# common/crypto/prg.py
from __future__ import annotations
import hmac
import hashlib
from typing import Optional

from src.common.utils.encode import i2osp

_HASH = hashlib.sha256
_BLOCKLEN = _HASH().digest_size  # 32 bytes for SHA-256

def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, _HASH).digest()

def _prg_ctr(seed: bytes, out_len: int, *, label: bytes) -> bytes:
    """
    HMAC-SHA256-CTR: deterministically expand `seed` into `out_len` bytes.
    data = b"PRG|" + label + b"|ctr=" + I2OSP(i,4) + b"|len=" + I2OSP(out_len,4)
    block_i = HMAC(seed, data), i = 1,2,...
    output = block_1 || block_2 || ... (truncate to out_len)
    """
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes")
    if len(seed) == 0:
        raise ValueError("seed must be non-empty")
    if not isinstance(label, (bytes, bytearray)):
        raise TypeError("label must be bytes")
    if out_len < 0:
        raise ValueError("out_len must be non-negative")

    out = bytearray()
    i = 1
    while len(out) < out_len:
        data = b"PRG|" + bytes(label) + b"|ctr=" + i2osp(i, 4) + b"|len=" + i2osp(out_len, 4)
        out.extend(_hmac(bytes(seed), data))
        i += 1
    return bytes(out[:out_len])

def G_bytes(seed: bytes, out_len: int, *, label: bytes = b"ZIDS|PRG") -> bytes:
    """Expand to an exact number of BYTES."""
    return _prg_ctr(seed, out_len, label=label)

def G_bits(seed: bytes, out_bits: int, *, label: bytes = b"ZIDS|PRG") -> bytes:
    """Expand to an exact number of BITS (MSB-first truncation on the last byte)."""
    if out_bits < 0:
        raise ValueError("out_bits must be non-negative")
    out_len = (out_bits + 7) // 8
    if out_len == 0:
        return b""
    buf = _prg_ctr(seed, out_len, label=label)
    r = out_bits & 7
    if r == 0:
        return buf
    mask = (0xFF << (8 - r)) & 0xFF
    return buf[:-1] + bytes([buf[-1] & mask])

# ---- Thin wrapper to match engine.py's expected signature ----
def prg(seed: bytes, label: bytes, out_len: int) -> bytes:
    """
    Compatibility wrapper used by engine.py:
        prg(seed, label, out_len)  -> bytes
    Internally calls G_bytes(seed, out_len, label=label).
    """
    return G_bytes(seed, out_len, label=label)

__all__ = ["prg", "G_bytes", "G_bits"]