# src/common/odfa/seed_rules.py
from __future__ import annotations
from typing import Final
from src.common.utils.encode import i2osp
from src.common.crypto.prf import prf_msg  # HMAC-SHA256 PRF(key, msg, out_len)

# 唯一標籤（PRG domain separation）
PRG_LABEL_CELL: Final[bytes] = b"ZIDS|CELL"

def seed_info(row: int, col: int) -> bytes:
    # 嚴禁改動；改了要重建離線工件
    return b"ZIDS|SEED|row=" + i2osp(row, 4) + b"|col=" + i2osp(col, 2)

def seed_from_gk(gk: bytes, row: int, col: int, k_bytes: int) -> bytes:
    if not gk or k_bytes <= 0:
        raise ValueError("seed_from_gk: bad gk/k_bytes")
    return prf_msg(gk, seed_info(row, col), k_bytes)
