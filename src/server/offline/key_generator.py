# src/server/offline/key_generator.py
from __future__ import annotations
from typing import List, Optional, Callable
import os

from src.common.crypto.prf import prf_msg
from src.common.odfa.seed_rules import seed_from_gk, i2osp

# ------------------ GK 生成 ------------------

def derive_deterministic_gk_table(master_key: bytes, cols_per_row: List[int], k_bytes: int) -> List[List[bytes]]:
    """
    從 master_key 決定性導出每列的 GK[row][col]（長度 = k_bytes；這裡的 k_bytes = --gk-bytes，例如 32）。
    """
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) == 0:
        raise ValueError("master_key must be non-empty bytes")
    if k_bytes <= 0:
        raise ValueError("k_bytes must be positive")

    mk = bytes(master_key)
    table: List[List[bytes]] = []
    for row, m in enumerate(cols_per_row):
        row_list: List[bytes] = []
        for col in range(m):
            label = b"ZIDS|GK|row=" + i2osp(row, 4) + b"|col=" + i2osp(col, 2)
            gk = prf_msg(mk, label, k_bytes)   # 這裡的 k_bytes = GK 長度（--gk-bytes）
            row_list.append(gk)
        table.append(row_list)
    return table


def sample_gk_table(cols_per_row: List[int], k_bytes: int, *, master_key: Optional[bytes] = None) -> List[List[bytes]]:
    """
    舊接口相容：若提供 master_key -> 決定性；否則隨機（僅測試用）。
    k_bytes 仍指 GK 長度（= --gk-bytes）。
    """
    if k_bytes <= 0:
        raise ValueError("k_bytes must be positive")
    if master_key is not None:
        return derive_deterministic_gk_table(master_key, cols_per_row, k_bytes)
    return [[os.urandom(k_bytes) for _ in range(m)] for m in cols_per_row]

# ------------------ SEED 導出（線上/離線一致） ------------------

def derive_seed_from_gk(gk: bytes, row: int, col: int, k_bytes: int) -> bytes:
    """
    從 GK 導出 PRG 的 seed（長度 = k_bytes；此處的 k_bytes = --k/8，預設 16）。
    """
    return seed_from_gk(gk, row, col, k_bytes)

# ------------------ builder 專用：pad_seed 函式工廠 ------------------

def make_offline_pad_seed_fn(
    *,
    gk_table: Optional[List[List[bytes]]] = None,
    master_gk: Optional[bytes] = None,
    gk_bytes: Optional[int] = None,   # ★ 新增：指定「GK 的長度」= --gk-bytes
) -> Callable[[int, int, int], bytes]:
    """
    回傳 pad_seed_fn(row, col, k_bytes)->seed，供 build_gdfa_stream 使用。

    規則：
      - 若提供 gk_table：col<m 用表中 GK；col>=m（補位）用 master_gk 導出 dummy GK（長度= gk_bytes）再導 seed
      - 若僅 master_gk：即時導出 GK(row,col)（長度= gk_bytes）再導 seed
    注意：
      - 此處的參數 k_bytes 指「seed 長度」（= --k/8），不是 GK 長度
      - gk_bytes 必須等於你的離線參數 --gk-bytes（例如 32）
    """
    if gk_table is None and master_gk is None:
        raise ValueError("make_offline_pad_seed_fn: need master_gk and/or gk_table")

    if gk_table is None:
        if not isinstance(master_gk, (bytes, bytearray)) or len(master_gk) == 0:
            raise ValueError("master_gk must be non-empty bytes")
        if not isinstance(gk_bytes, int) or gk_bytes <= 0:
            raise ValueError("gk_bytes must be a positive int (== --gk-bytes)")
        mk = bytes(master_gk)

        def pad_seed_from_master(row: int, col: int, k_bytes: int) -> bytes:
            # 先導出 GK(row,col)（長度 = gk_bytes），再導 seed（長度 = k_bytes）
            label = b"ZIDS|GK|row=" + i2osp(row, 4) + b"|col=" + i2osp(col, 2)
            gk = prf_msg(mk, label, gk_bytes)
            return derive_seed_from_gk(gk, row, col, k_bytes)

        return pad_seed_from_master

    # 有 gk_table 的情形
    if not isinstance(gk_table, list) or len(gk_table) == 0:
        raise ValueError("gk_table must be non-empty list")
    mk = bytes(master_gk) if master_gk is not None else None
    if mk is not None:
        if not isinstance(gk_bytes, int) or gk_bytes <= 0:
            raise ValueError("gk_bytes must be a positive int (== --gk-bytes)")

    def pad_seed_from_gk_table(row: int, col: int, k_bytes: int) -> bytes:
        if row < 0 or row >= len(gk_table):
            raise IndexError("row out of range for gk_table")
        m = len(gk_table[row])
        if col < m:
            return derive_seed_from_gk(gk_table[row][col], row, col, k_bytes)
        # 補位欄位：用 master_gk 決定性導出 dummy GK（長度 = gk_bytes）
        if mk is None:
            raise IndexError("col exceeds row's GK count and no master_gk provided for dummy slots")
        dummy_label = b"ZIDS|GK|unused|" + i2osp(row, 4) + b"|" + i2osp(col, 2)
        dummy_gk = prf_msg(mk, dummy_label, gk_bytes)
        return derive_seed_from_gk(dummy_gk, row, col, k_bytes)

    return pad_seed_from_gk_table


__all__ = [
    "derive_deterministic_gk_table",
    "sample_gk_table",
    "derive_seed_from_gk",
    "make_offline_pad_seed_fn",
]