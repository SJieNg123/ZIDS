# src/client/online/ot_client.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, List, Protocol

# ---- 最小 server 端 handler 介面（本地呼叫） ----
class ServerHandler(Protocol):
    def ot_row_payload(self, session_id: str, row_id: int) -> tuple[bytes, List[bytes]]:
        """
        回傳 (aad, payload_list)，其中 payload_list[c] = GK[row][c]（bytes）。
        來源：src/server/online/handlers.ZIDSServerApp.ot_row_payload
        """
        ...

# ---- 可供 engine.py 使用的 OTChooser 介面（保持一致） ----
class OTChooser(Protocol):
    def acquire_gk(self, *, row_id: int, m: int, col: int, aad: bytes) -> bytes:
        """
        針對指定 (row_id, col)，執行 1-of-m OT 取得 GK[row][col]（bytes）。
        - m: 該列群數（供 sanity check）
        - aad: 引擎計算的 AAD，需與 server 端對應列的 AAD 完全一致
        """
        ...

# =========================================================
# 1) 本地直取版（不做密碼學，只為「先跑起來驗證架構」）
# =========================================================

@dataclass
class LocalTrivialOTChooser:
    """
    極簡本地版 OT 選擇器：
      - 直接向 server handler 取得 (aad, payload)，回傳 payload[col]
      - 僅作 AAD 與長度一致性檢查；不提供任何密碼學隱匿/安全性
    使用時機：
      - 你正在搭架構、要先讓 pipeline 從 input → output 走通
      - 之後再換成真正的 OT（見下方 Pluggable 版本）
    """
    server: ServerHandler
    session_id: str

    def acquire_gk(self, *, row_id: int, m: int, col: int, aad: bytes) -> bytes:
        aad_srv, payload = self.server.ot_row_payload(self.session_id, row_id)
        if aad_srv != aad:
            raise ValueError("AAD mismatch between client and server for the requested row")
        if len(payload) != m:
            raise ValueError(f"server payload length {len(payload)} != m={m}")
        if not (0 <= col < m):
            raise ValueError("col out of range for this row")
        return payload[col]


# =========================================================
# 2) 可插拔版（把你的 1-of-m OT 實作接進來）
# =========================================================

@dataclass
class LocalPluggableOTChooser:
    """
    可插拔本地 OT 選擇器：
      - 仍由本地 server handler 提供 (aad, payload)
      - 透過你注入的 `run_ot_1ofm(payload, aad, choice_col)` 完成真正的 1-of-m OT
      - `run_ot_1ofm` 必須回傳選到的 GK（bytes）
    用法：
      chooser = LocalPluggableOTChooser(server, session_id, run_ot_1ofm=my_impl)
      # 其中 my_impl 可以包你現有的 DDH-OT1ofm 實作
    """
    server: ServerHandler
    session_id: str
    run_ot_1ofm: Callable[[List[bytes], bytes, int], bytes]

    def acquire_gk(self, *, row_id: int, m: int, col: int, aad: bytes) -> bytes:
        aad_srv, payload = self.server.ot_row_payload(self.session_id, row_id)
        if aad_srv != aad:
            raise ValueError("AAD mismatch between client and server for the requested row")
        if len(payload) != m:
            raise ValueError(f"server payload length {len(payload)} != m={m}")
        if not (0 <= col < m):
            raise ValueError("col out of range for this row")
        # 交給你注入的 OT 實作（BYTES 模式 + 綁定 AAD）
        gk = self.run_ot_1ofm(payload, aad, col)
        if not isinstance(gk, (bytes, bytearray)):
            raise TypeError("run_ot_1ofm must return bytes")
        return bytes(gk)
