# src/server/online/session_manager.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import os
import secrets
import time

from src.server.online.ot_response_builder import RowAlphMeta, GKStore, OTResponseBuilder
from src.server.offline.key_generator import (
    sample_gk_table,
    derive_seed_from_gk,
    derive_deterministic_gk_table,  # 新增在 key_generator（見下）
)
from src.common.odfa.seed_rules import i2osp

# ---- Session 定義 ----

@dataclass
class SessionConfig:
    k_bytes: int = 32
    aad_prefix: bytes = b"ZIDS|GK"
    ttl_seconds: int = 900              # 會話有效期（可改）
    master_key: Optional[bytes] = None  # 若提供，則 GK 決定性；否則隨機

@dataclass
class SessionState:
    session_id: str
    created_at: float
    meta: RowAlphMeta
    gk_store: GKStore
    aad_prefix: bytes
    k_bytes: int

    def aad_for_row(self, row_id: int) -> bytes:
        # 建議把 session_id 與 row 加入 AAD，避免跨會話/跨列重放
        return (self.aad_prefix
                + b"|sid=" + self.session_id.encode("ascii")
                + b"|row=" + i2osp(row_id, 4))

class SessionManager:
    """
    In-memory GK session manager.
    - 以 RowAlphMeta 驗證每列 m（群數）與 GK 表一致。
    - 建立/回收會話，提供 per-row OT payload。
    - 不處理網路/序列化；與你的 OT1ofmSender 解耦。
    """

    def __init__(self, meta: RowAlphMeta, cfg: Optional[SessionConfig] = None):
        self.meta = meta
        self.cfg = cfg or SessionConfig()
        self._sessions: Dict[str, SessionState] = {}

    def _new_session_id(self) -> str:
        return secrets.token_urlsafe(16)

    def _make_gk_store(self) -> GKStore:
        k = self.cfg.k_bytes
        if self.cfg.master_key:
            # 決定性 GK：由 master key + (row,col) 產生
            table = derive_deterministic_gk_table(self.cfg.master_key,
                                                  cols_per_row=self.meta.cols_per_row,
                                                  k_bytes=k)
            return GKStore(table)
        # 隨機 GK（每列的長度依 cols_per_row）
        table = [[os.urandom(k) for _ in range(m)] for m in self.meta.cols_per_row]
        return GKStore(table)

    def create_session(self) -> SessionState:
        sid = self._new_session_id()
        st = SessionState(
            session_id=sid,
            created_at=time.time(),
            meta=self.meta,
            gk_store=self._make_gk_store(),
            aad_prefix=self.cfg.aad_prefix,
            k_bytes=self.cfg.k_bytes,
        )
        # 一致性檢查交給 OTResponseBuilder（含 key 長度/列寬）
        _ = OTResponseBuilder(self.meta, st.gk_store)
        self._sessions[sid] = st
        return st

    def get(self, session_id: str) -> SessionState:
        st = self._sessions.get(session_id)
        if st is None:
            raise KeyError("session not found")
        if (time.time() - st.created_at) > self.cfg.ttl_seconds:
            # 簡單處理：過期即刪除
            del self._sessions[session_id]
            raise KeyError("session expired")
        return st

    # ---- 對上層提供的關鍵 API ----

    def payload_for_row(self, session_id: str, row_id: int) -> Tuple[bytes, List[bytes]]:
        """
        回傳 (aad, payload_list)，其中 payload_list 的長度 = m（該列群數），元素為 GK bytes。
        讓上層把 (aad, payload) 丟給 OT1ofmSender（BYTES mode）。
        """
        st = self.get(session_id)
        builder = OTResponseBuilder(self.meta, st.gk_store)
        aad = st.aad_for_row(row_id)
        payload = builder.payload_for_row(row_id)
        return aad, payload

    # ----（選）驗證/除錯用：以 server 端複算 seed ----

    def derive_seed(self, session_id: str, row_id: int, col: int, out_len: int) -> bytes:
        st = self.get(session_id)
        gk = st.gk_store.table[row_id][col]
        return derive_seed_from_gk(gk, row_id, col, out_len)

    # ---- 清理 ----

    def drop(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def gc(self) -> int:
        """回收過期會話；回傳刪除數"""
        now = time.time()
        to_del = [sid for sid, st in self._sessions.items()
                  if (now - st.created_at) > self.cfg.ttl_seconds]
        for sid in to_del:
            del self._sessions[sid]
        return len(to_del)
