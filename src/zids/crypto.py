"""Native prime-subgroup arithmetic and explicitly framed hash domains."""
import hashlib
import hmac
import secrets

from nacl import bindings as sodium

from .contracts import ProtocolError

ORDER = 2**252 + 27742317777372353535851937790883648493


def fields(*parts):
    return b"".join(len(p).to_bytes(8, "big") + p for p in parts)


def random_scalar():
    return (secrets.randbelow(ORDER - 1) + 1).to_bytes(32, "little")


def valid_point(point):
    return (type(point) is bytes and len(point) == 32
            and sodium.crypto_core_ed25519_is_valid_point(point))


def require_point(point):
    if not valid_point(point):
        raise ProtocolError("invalid prime-subgroup point")
    return point


def base(scalar):
    return sodium.crypto_scalarmult_ed25519_base_noclamp(scalar)


def multiply(scalar, point):
    return sodium.crypto_scalarmult_ed25519_noclamp(scalar, require_point(point))


def subtract(a, b):
    return sodium.crypto_core_ed25519_sub(a, b)


def xor(a, b):
    if len(a) != len(b):
        raise ProtocolError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def ro_pad(shared, transcript, index, branch, length):
    domain = fields(b"ZIDSv2/base-OT", shared, transcript, index.to_bytes(8, "big"),
                    bytes([branch]), length.to_bytes(8, "big"))
    return hashlib.shake_256(domain).digest(length)


def prf(key, domain, length):
    return prf_slice(key,domain,length,0,length)


def prf_slice(key, domain, length, offset, size):
    if not 0 <= offset <= offset+size <= length:
        raise ProtocolError('invalid PRF slice')
    prefix = fields(b"ZIDSv2/PRF-HMAC-SHA256", domain, length.to_bytes(8, "big"))
    blocks = (hmac.digest(key, prefix + i.to_bytes(8, "big"), "sha256")
              for i in range(offset//32,(offset+size+31)//32))
    return b"".join(blocks)[offset%32:offset%32+size]
