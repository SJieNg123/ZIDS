# -*- coding: utf-8 -*-
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Tuple, List
import json, os

from src.server.online.session_manager import SessionManager, SessionConfig
from src.server.online.ot_response_builder import RowAlphMeta, GKStore, OTResponseBuilder
from src.server.online.gk_loader import load_gk_store_from_master, load_gk_store_from_files

@dataclass
class ServerConfig:
    # 单一真源：服务端自己读 manifest（不要让外层传魔法数）
    manifest_path: str
    # GK 来源二选一：1) 读离线文件；2) master_key 决定性导出（不要两者都给）
    gk_files_dir: Optional[str] = None
    master_key: Optional[bytes] = None
    # 仅 master 模式需要：GK 的字节长度（必须与 manifest["gk_bytes"] 一致）
    gk_bytes: int = 32

class ZIDSServerApp:
    def __init__(self, row_meta: RowAlphMeta, cfg: ServerConfig):
        self.meta = row_meta
        self.cfg  = cfg

        with open(cfg.manifest_path, "rb") as f:
            self.manifest = json.loads(f.read().decode("utf-8"))

        # 种子 k（bits）→ bytes；这是 pad/PRG 的种子长度，不是 GK 长度
        self.seed_k_bytes = int(self.manifest["crypto_params"]["k"]) // 8

        # 初始 SessionManager（默认随机 GK；后面按模式覆写）
        self.sessions = SessionManager(
            row_meta,
            SessionConfig(k_bytes=(cfg.gk_bytes or 32), master_key=None)
        )

        # 离线 GK 文件模式
        self._gk_from_files: Optional[GKStore] = None
        if cfg.gk_files_dir:
            self._gk_from_files = load_gk_store_from_files(cfg.gk_files_dir)
            # 做一次一致性检查：列数要和 row_meta 对齐
            OTResponseBuilder(self.meta, self._gk_from_files)

        # master 模式
        if cfg.master_key:
            gk_bytes_manifest = int(self.manifest.get("gk_bytes", cfg.gk_bytes))
            if cfg.gk_bytes != gk_bytes_manifest:
                raise ValueError(f"gk_bytes mismatch: cfg={cfg.gk_bytes} manifest={gk_bytes_manifest}")
            self.sessions.cfg.master_key = cfg.master_key
            self.sessions.cfg.k_bytes    = cfg.gk_bytes

        # 双源保护
        if cfg.gk_files_dir and cfg.master_key:
            raise ValueError("Do not set both gk_files_dir and master_key")

    def init_session(self) -> dict:
        st = self.sessions.create_session()
        if self._gk_from_files is not None:
            st.gk_store = self._gk_from_files
            OTResponseBuilder(self.meta, st.gk_store)  # 再次校验
        # 只回 session_id；其他参数由工件/manifest 提供，避免未来破坏相容
        return {"session_id": st.session_id}

    def ot_row_payload(self, session_id: str, row_id: int) -> Tuple[bytes, List[bytes]]:
        """
        返回 (aad, payload_list)，payload_list[c] = GK[row_id][c]（bytes）。
        上层拿去做 1-of-m OT。
        """
        aad, payload = self.sessions.payload_for_row(session_id, row_id)
        return aad, payload