# src/server/online/handlers.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Tuple, List

from src.server.online.session_manager import SessionManager, SessionConfig
from src.server.online.ot_response_builder import RowAlphMeta
from src.server.online.gk_loader import load_gk_store_from_master, load_gk_store_from_files
from src.server.online.ot_response_builder import GKStore, OTResponseBuilder

@dataclass
class ServerConfig:
    # 二選一：用 master key 決定性導出 GK，或讀離線輸出的 gk_table.*
    master_key: Optional[bytes] = None
    gk_files_dir: Optional[str] = None
    k_bytes: int = 32
    session_ttl_sec: int = 900
    aad_prefix: bytes = b"ZIDS|GK"

class ZIDSServerApp:
    """
    極簡 server 應用層：管理 sessions，並把 per-row 的 GK 負載交給 OT 協議層。
    不含任何網路／序列化；呼叫端可用它作為 in-process handler。
    """
    def __init__(self, row_alph_meta: RowAlphMeta, cfg: ServerConfig):
        self.meta = row_alph_meta
        self.cfg = cfg

        # 決定 GK 來源策略（會話生命週期內固定）
        if (cfg.master_key is None) and (cfg.gk_files_dir is None):
            # 預設：用 master key 決定性比較容易重現；你也可在外層傳 random。
            raise ValueError("ServerConfig must set either master_key or gk_files_dir")

        # SessionManager 以 master key 生成 GK（決定性、每 session 一組）
        sess_cfg = SessionConfig(
            k_bytes=cfg.k_bytes,
            aad_prefix=cfg.aad_prefix,
            ttl_seconds=cfg.session_ttl_sec,
            master_key=cfg.master_key,
        )
        self.sessions = SessionManager(self.meta, sess_cfg)

        # 若要「共用同一份離線產生的 GK 表」，可在外層用 gk_loader 讀檔，並自行擴 SessionManager 支援注入固定 GK。
        # 目前的設計已足夠對齊論文：離線/線上用相同 master 即可一致。

    # --- 對外 API ---

    def init_session(self) -> dict:
        st = self.sessions.create_session()
        # 回傳最小必要資訊；wire 層可直接對這個 dict 做序列化
        return {
            "session_id": st.session_id,
            "start_row": st.meta.cols_per_row and 0 or 0,  # 占位；真正 start_row 應來自 GDFA header
            "aid_bits": None,  # 占位；請由 GDFA header 提供（client 端已從 GDFA 取）
        }

    def ot_row_payload(self, session_id: str, row_id: int) -> Tuple[bytes, List[bytes]]:
        """
        回傳 (aad, payload_list)，讓 OT Sender 用於該行的 1-of-m。
        """
        aad, payload = self.sessions.payload_for_row(session_id, row_id)
        return aad, payload