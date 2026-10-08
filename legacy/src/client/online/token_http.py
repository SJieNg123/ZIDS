# src/client/online/token_http.py
from __future__ import annotations
import requests, json, time

class _OTRowChooser:
    """
    Minimal OT chooser over HTTP with metrics:
      POST /ot/start   <- {"sid": "..."}             -> {"ok": true}
      POST /ot/choose  <- {"row","col","k_bytes"...} -> {"gk_hex": "..."}
    """
    def __init__(self, url_base: str, master_hex: str, session_id: str = "cli", timeout: float = 2.0):
        if url_base.endswith("/"):
            url_base = url_base[:-1]
        self.base = url_base
        self.master_hex = master_hex
        self.session_id = session_id
        self.timeout = timeout

        # metrics
        self._bytes_up = 0
        self._bytes_down = 0
        self._num_start = 0
        self._num_choose = 0
        self._latencies = []   # seconds

        # engine 會把 k_bytes 注入/覆寫
        self.k_bytes = 32

        # health check (/ot/start)
        payload = {"sid": self.session_id}
        body = json.dumps(payload).encode("utf-8")
        t0 = time.perf_counter()
        r = requests.post(self.base + "/ot/start", json=payload, timeout=self.timeout)
        dt = time.perf_counter() - t0
        self._num_start += 1
        self._bytes_up += len(body)
        self._bytes_down += len(r.content)
        # 不把 /ot/start 記進 latency 分佈（避免汙染）
        r.raise_for_status()
        obj = r.json()
        if not obj or not obj.get("ok", False):
            raise RuntimeError(f"/ot/start not ok: {obj}")

    def ensure_row_payload_cached(self, row: int) -> None:
        return

    def choose_one(self, row: int, col: int) -> bytes:
        payload = {
            "row": int(row),
            "col": int(col),
            "k_bytes": int(self.k_bytes),
            "master_hex": self.master_hex,
            "sid": self.session_id,
        }
        body = json.dumps(payload).encode("utf-8")
        t0 = time.perf_counter()
        r = requests.post(self.base + "/ot/choose", json=payload, timeout=self.timeout)
        dt = time.perf_counter() - t0
        self._num_choose += 1
        self._latencies.append(dt)
        self._bytes_up += len(body)
        self._bytes_down += len(r.content)

        r.raise_for_status()
        obj = r.json()
        gk_hex = obj.get("gk_hex")
        if not gk_hex:
            raise RuntimeError(f"bad /ot/choose response: {obj}")
        return bytes.fromhex(gk_hex)

    # ---- metrics API for engine/bench ----
    def get_stats(self) -> dict:
        n = len(self._latencies)
        if n:
            import statistics as st
            avg = sum(self._latencies)/n
            p50 = st.median(self._latencies)
            p95 = st.quantiles(self._latencies, n=20)[18] if n >= 20 else max(self._latencies)
        else:
            avg = p50 = p95 = 0.0
        return {
            "bytes_up": self._bytes_up,
            "bytes_down": self._bytes_down,
            "num_start": self._num_start,
            "num_choose": self._num_choose,
            "lat_avg_s": avg,
            "lat_p50_s": p50,
            "lat_p95_s": p95,
        }

    def reset_stats(self) -> None:
        self._bytes_up = 0
        self._bytes_down = 0
        self._num_start = 0
        self._num_choose = 0
        self._latencies.clear()