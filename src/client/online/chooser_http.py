# src/client/online/chooser_http.py
from __future__ import annotations

import base64
from typing import Optional, Dict, Any
import requests

class HttpChooser:
    """
    符合 OTChooser 介面的 HTTP 客戶端。
    會嘗試呼叫以下端點之一取得 GK（按序嘗試，取第一個 2xx 且包含 gk 的回應）：
      1) POST {base_url}/ot          body: {"row": <int>, "col": <int>}
      2) POST {base_url}/choose_one  body: {"row": <int>, "col": <int>}

    支援回應欄位：
      - {"gk_b64": "<base64>"}（首選）
      - {"gk": "<base64 或 hex>"}（自動判別）
      - {"gk_hex": "<hex>"}

    備註：
      - ensure_row_payload_cached(row) 是可選優化；若後端沒有 /ot/preload，這裡靜默忽略。
      - acquire_gk(...) 為舊介面相容，直接轉呼叫 choose_one(row, col)。
    """

    def __init__(self, base_url: str, timeout: float = 10.0, extra_headers: Optional[Dict[str, str]] = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.s = requests.Session()
        if extra_headers:
            self.s.headers.update(extra_headers)

    # 新式接口（推薦）
    def ensure_row_payload_cached(self, row: int) -> None:
        # 後端若有預載端點就用；沒有就忽略錯誤
        try:
            url = f"{self.base_url}/ot/preload"
            self.s.post(url, json={"row": row}, timeout=self.timeout)
        except Exception:
            pass

    def choose_one(self, row: int, col: int) -> bytes:
        last_err: Optional[Exception] = None
        candidates = [
            (f"{self.base_url}/ot", {"row": row, "col": col}),
            (f"{self.base_url}/choose_one", {"row": row, "col": col}),
        ]
        for url, body in candidates:
            try:
                resp = self.s.post(url, json=body, timeout=self.timeout)
                if 200 <= resp.status_code < 300:
                    data: Dict[str, Any] = resp.json()
                    if "gk_b64" in data:
                        return base64.b64decode(data["gk_b64"])
                    if "gk_hex" in data:
                        return bytes.fromhex(data["gk_hex"])
                    if "gk" in data:
                        # 先試 base64，失敗再當 hex
                        try:
                            return base64.b64decode(data["gk"])
                        except Exception:
                            return bytes.fromhex(data["gk"])
            except Exception as e:
                last_err = e
                continue
        raise RuntimeError(f"HttpChooser failed to fetch GK for row={row} col={col}; last_err={last_err}")

    # 舊式接口（相容）
    def acquire_gk(self, *, row_id: int, m: int, col: int, aad: bytes) -> bytes:
        return self.choose_one(row_id, col)