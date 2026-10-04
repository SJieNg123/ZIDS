"""Check the native primitives used by the base-OT suite, without secret output."""
import json
import platform
import secrets

import nacl
from nacl import bindings as b


def main():
    order = 2**252 + 27742317777372353535851937790883648493
    a = (secrets.randbelow(order - 1) + 1).to_bytes(32, "little")
    c = (secrets.randbelow(order - 1) + 1).to_bytes(32, "little")
    ap = b.crypto_scalarmult_ed25519_base_noclamp(a)
    cp = b.crypto_scalarmult_ed25519_base_noclamp(c)
    assert b.crypto_core_ed25519_is_valid_point(ap)
    assert b.crypto_scalarmult_ed25519_noclamp(a, cp) == b.crypto_scalarmult_ed25519_noclamp(c, ap)
    assert b.crypto_core_ed25519_sub(b.crypto_core_ed25519_add(ap, cp), cp) == ap
    assert not b.crypto_core_ed25519_is_valid_point(bytes(32))
    assert not b.crypto_core_ed25519_is_valid_point(b"\x01" + bytes(31))
    print(json.dumps({"platform": platform.platform(), "python": platform.python_version(),
                      "pynacl": nacl.__version__, "native_group_check": "passed"}))


if __name__ == "__main__":
    main()
