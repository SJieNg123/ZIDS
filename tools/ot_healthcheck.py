# tools/ot_healthcheck.py
from __future__ import annotations
import argparse, os, random, hmac, hashlib
import requests

# 與 server 一致（只在開發期使用）
HMAC_DOMAIN = b"ZIDS|DEV-OT|PAYLOAD"

def derive_payload_local(secret: bytes, session: str, row: int, choice: int, index: int, k_bytes: int) -> bytes:
    msg = HMAC_DOMAIN + (f"|sid={session}|row={row}|idx={index}|ch={choice}".encode("utf-8"))
    full = hmac.new(secret, msg, hashlib.sha256).digest()
    if k_bytes <= len(full):
        return full[:k_bytes]
    out = bytearray(); ctr = 0
    while len(out) < k_bytes:
        out.extend(hmac.new(secret, full + bytes([ctr]), hashlib.sha256).digest())
        ctr += 1
    return bytes(out[:k_bytes])

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def main() -> None:
    ap = argparse.ArgumentParser(description="Dev OT healthcheck (no real OT, just payload hashes)")
    ap.add_argument("--base-url", default="http://127.0.0.1:8443", help="dev OT server base URL")
    ap.add_argument("--session", default="cli")
    ap.add_argument("--k-bytes", type=int, default=32)
    ap.add_argument("--row", type=int, default=0)
    ap.add_argument("--length", type=int, default=200, help="number of choices (simulate input length)")
    ap.add_argument("--secret", default=os.environ.get("DEV_OT_SERVER_SECRET", "dev-secret"),
                    help="dev shared secret for hash cross-check (dev only)")
    args = ap.parse_args()

    s = requests.Session()
    # 1) start
    r = s.post(f"{args.base_url}/ot/start", json={"session": args.session, "k_bytes": args.k_bytes, "kappa": 128})
    r.raise_for_status()
    j = r.json()
    sid = j["session"]; k_bytes = j["k_bytes"]
    print(f"[start] ok session={sid} k_bytes={k_bytes}")

    # 2) random choices
    choices = [random.randint(0, 255) for _ in range(args.length)]
    r = s.post(f"{args.base_url}/ot/choose",
               json={"session": sid, "row": args.row, "choices": choices, "nonce": "dev"})
    r.raise_for_status()
    resp = r.json()
    items = resp["items"]
    assert len(items) == len(choices)

    # 3) cross-check hashes（純開發）
    secret = args.secret.encode("utf-8")
    ok = 0
    for i, ch in enumerate(choices):
        p_local = derive_payload_local(secret, sid, args.row, int(ch), i, k_bytes)
        h_local = sha256(p_local)
        h_srv   = items[i]["payload_hash_hex"]
        if h_local == h_srv:
            ok += 1
        else:
            print(f"[mismatch] idx={i} ch={ch} h_local={h_local} h_srv={h_srv}")
            break

    if ok == len(choices):
        print(f"[ok] hashes match for {ok}/{len(choices)} items ✔")
    else:
        print(f"[fail] mismatch at index {ok}")

if __name__ == "__main__":
    main()