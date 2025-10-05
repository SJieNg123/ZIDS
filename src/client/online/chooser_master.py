# src/client/online/chooser_master.py
from __future__ import annotations
import hmac
import hashlib
from typing import List, Optional

class MasterChooser:
    """
    混合 chooser（最小改動版）：
      - 若提供 gk_table：直接用離線產生的 GK 表（與 builder 完全一致）→ 最穩
      - 否則若提供 master_hex：本地 HMAC 派生 GK（需與離線規則完全匹配）
      - 兩種都給時，**優先用 gk_table**
    """

    def __init__(self,
                 master_hex: Optional[str] = None,
                 gk_table: Optional[str] = None,
                 gk_bytes: int = 32,
                 row_endian: str = "little"):
        self._gk_bytes = int(gk_bytes)
        self._row_endian = "little" if str(row_endian).lower().startswith("l") else "big"

        # 優先載表（與離線 builder 一致）
        self._rows: Optional[List[bytes]] = None
        if gk_table:
            with open(gk_table, "rb") as f:
                data = f.read()
            if len(data) % self._gk_bytes != 0:
                raise ValueError(f"gk_table size {len(data)} not multiple of gk_bytes={self._gk_bytes}")
            n = len(data) // self._gk_bytes
            self._rows = [data[i*self._gk_bytes:(i+1)*self._gk_bytes] for i in range(n)]
            self._master = None
            return  # 表模式就緒

        # 後備：master→GK（只有在確定離線也用同規則時才可靠）
        if master_hex:
            self._master = bytes.fromhex(master_hex)
        else:
            raise ValueError("MasterChooser needs either 'gk_table' or 'master_hex'")

    # 新式 API
    def ensure_row_payload_cached(self, row: int) -> None:
        return None

    def choose_one(self, row: int, col: int) -> bytes:  # noqa: ARG002 (col unused)
        # 表模式
        if self._rows is not None:
            if not (0 <= row < len(self._rows)):
                raise IndexError(f"row {row} out of range (n={len(self._rows)})")
            return self._rows[row]

        # master 後備模式
        rb = int(row).to_bytes(4, self._row_endian, signed=False)
        base = hmac.new(self._master, b"ZIDS|GK|row" + rb, hashlib.sha256).digest()
        if self._gk_bytes <= len(base):
            return base[:self._gk_bytes]
        out = bytearray(); ctr = 0
        while len(out) < self._gk_bytes:
            out.extend(hmac.new(self._master, b"ZIDS|GK|row" + rb + bytes([ctr]), hashlib.sha256).digest())
            ctr += 1
        return bytes(out[:self._gk_bytes])

    # 舊式 API 兼容
    def acquire_gk(self, *, row_id: int, m: int, col: int, aad: bytes) -> bytes:  # noqa: ARG002
        return self.choose_one(row_id, col)