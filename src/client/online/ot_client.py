# src/client/online/ot_client.py
from __future__ import annotations
from typing import Dict, Tuple, List

from src.common.odfa.seed_rules import seed_from_gk

class LocalTrivialOTChooser:
    """
    本地评测用的“假 OT”：
      - 一次取整行载荷 (aad, payload)，缓存
      - 第一次使用某 (row, logical_col) 时，通过对比“客户端种子 vs 服务器种子”
        解析出 payload 的物理槽位，建立映射 (row, logical_col) -> slot
      - 以后直接用该 slot 取 GK
    这样适配了“服务器可对 payload 做置换/填充”的情况，避免列错位。
    """
    def __init__(self, server, session_id: str, seed_k_bytes: int):
        self.server = server
        self.session_id = session_id
        self.seed_k_bytes = seed_k_bytes
        self._row_payload_cache: Dict[int, Tuple[bytes, List[bytes]]] = {}
        self._slot_map: Dict[Tuple[int, int], int] = {}  # (row, logical_col) -> physical_slot

    def ensure_row_payload_cached(self, row: int) -> None:
        if row not in self._row_payload_cache:
            self._row_payload_cache[row] = self.server.ot_row_payload(self.session_id, row)

    def get_row_payload(self, row: int) -> Tuple[bytes, List[bytes]]:
        self.ensure_row_payload_cached(row)
        return self._row_payload_cache[row]

    def _resolve_slot_for_col(self, row: int, logical_col: int) -> int:
        key = (row, logical_col)
        if key in self._slot_map:
            return self._slot_map[key]

        aad, payload = self.get_row_payload(row)
        # 服务器（真源）给出该逻辑列对应的“正确种子”
        seed_srv = self.server.sessions.derive_seed(self.session_id, row, logical_col, self.seed_k_bytes)

        # 扫描这一行 payload 的每个物理槽位，寻找与 seed_srv 一致的 GK
        for slot, gk in enumerate(payload):
            seed_cli = seed_from_gk(gk, row, logical_col, self.seed_k_bytes)
            if seed_cli == seed_srv:
                self._slot_map[key] = slot
                return slot

        raise ValueError(f"cannot resolve payload slot for row={row} logical_col={logical_col} (payload mismatch)")

    def choose_one(self, row: int, logical_col: int) -> bytes:
        self.ensure_row_payload_cached(row)
        slot = self._resolve_slot_for_col(row, logical_col)
        _, payload = self._row_payload_cache[row]
        return payload[slot]