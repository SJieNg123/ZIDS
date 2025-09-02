# src/server/key_generator.py
from __future__ import annotations
import os
from typing import List

from src.common.odfa.seed_rules import seed_from_master, seed_from_gk, seed_info, PRG_LABEL_CELL
from src.common.crypto.prf import prf_msg
from src.common.odfa.seed_rules import i2osp

def sample_gk_table(num_rows: int, outmax: int, k_bytes: int) -> List[List[bytes]]:
    if num_rows <= 0 or outmax <= 0:
        raise ValueError("num_rows and outmax must be positive")
    if k_bytes <= 0:
        raise ValueError("k_bytes must be positive")
    return [[os.urandom(k_bytes) for _ in range(outmax)] for _ in range(num_rows)]

def make_offline_pad_seed_fn(master_key: bytes):
    def pad_seed_fn(new_row: int, col: int, k_bytes: int) -> bytes:
        return seed_from_master(master_key, new_row, col, k_bytes)
    return pad_seed_fn

def derive_seed_from_gk(gk_cell: bytes, row: int, col: int, k_bytes: int) -> bytes:
    return seed_from_gk(gk_cell, row, col, k_bytes)

# ---- 新增：用 master key 決定性地產生 GK 表（與 offline 對齊） ----

def derive_deterministic_gk_table(master_key: bytes,
                                  cols_per_row: List[int],
                                  k_bytes: int) -> List[List[bytes]]:
    """
    GK[row][col] = PRF(master_key, b"ZIDS|GK|" + row||col)
    - row 用 4 bytes、大端；col 用 2 bytes。
    - 與 offline/online 的 seed 導出搭配：
        seed = PRF(GK[row][col], seed_info(row, col))
    """
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) == 0:
        raise ValueError("master_key must be non-empty bytes")
    if k_bytes <= 0:
        raise ValueError("k_bytes must be positive")
    table: List[List[bytes]] = []
    for r, m in enumerate(cols_per_row):
        if m <= 0:
            raise ValueError(f"cols_per_row[{r}] must be >= 1")
        row_list: List[bytes] = []
        for c in range(m):
            label = b"ZIDS|GK|" + i2osp(r, 4) + b"|" + i2osp(c, 2)
            row_list.append(prf_msg(master_key, label, k_bytes))
        table.append(row_list)
    return table
