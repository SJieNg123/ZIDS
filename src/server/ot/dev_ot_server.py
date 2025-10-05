# dev_ot_server.py  (drop-in)
from __future__ import annotations
import json, hmac, hashlib, os
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

MASTER_HEX = os.environ.get("MASTER_HEX")  # 可用參數覆寫
ROW_ENDIAN = "little"

def i2osp(x: int, l: int, endian="big") -> bytes:
    return int(x).to_bytes(l, endian, signed=False)

def derive_gk(master_hex: str, row: int, k_bytes: int) -> bytes:
    mk = bytes.fromhex(master_hex)
    base = hmac.new(mk, b"ZIDS|GK|row" + i2osp(row, 4, "little"), hashlib.sha256).digest()
    if k_bytes <= len(base):
        return base[:k_bytes]
    out = bytearray(base)
    ctr = 0
    while len(out) < k_bytes:
        out.extend(hmac.new(mk, b"ZIDS|GK|row" + i2osp(row, 4, "little") + bytes([ctr]), hashlib.sha256).digest())
        ctr += 1
    return bytes(out[:k_bytes])

class Handler(BaseHTTPRequestHandler):
    server_version = "DevOT/1.0"

    def _read_json(self):
        try:
            ln = int(self.headers.get("Content-Length", "0"))
        except:
            return {}
        raw = self.rfile.read(ln)
        try:
            return json.loads(raw.decode("utf-8"))
        except:
            return {}

    def do_POST(self):
        if self.path == "/ot/start":
            body = self._read_json()  # ignore
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"ok": true}')
            return

        if self.path == "/ot/choose":
            body = self._read_json()
            row = int(body.get("row", 0))
            col = int(body.get("col", 0))  # 目前忽略
            k_bytes = int(body.get("k_bytes", 32))
            master_hex = body.get("master_hex") or MASTER_HEX
            if not master_hex:
                self.send_response(400); self.end_headers(); self.wfile.write(b'{"error":"no master_hex"}'); return
            gk = derive_gk(master_hex, row, k_bytes)
            resp = {"gk_hex": gk.hex()}
            out = json.dumps(resp).encode("utf-8")
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.end_headers(); self.wfile.write(out)
            return

        self.send_response(404); self.end_headers()

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--master-hex", default=None, help="override MASTER_HEX")
    args = ap.parse_args()
    if args.master_hex:
        global MASTER_HEX
        MASTER_HEX = args.master_hex
    if not MASTER_HEX:
        raise SystemExit("Set MASTER_HEX env or --master-hex")
    print(f"[dev-ot] listen on http://{args.host}:{args.port}  k_bytes: dynamic  master={MASTER_HEX[:8]}...")
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.serve_forever()

if __name__ == "__main__":
    main()