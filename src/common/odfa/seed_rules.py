# src/common/odfa/seed_rules.py
from __future__ import annotations
from typing import Optional
from src.common.crypto.prf import prf_msg

def i2osp(x: int, L: int) -> bytes:
    if x < 0 or x >= (1 << (8*L)): raise ValueError("i2osp out of range")
    return x.to_bytes(L, "big")

SEED_INFO_PREFIX = b"ZIDS|SEED|"
PRG_LABEL_CELL   = b"PRG|GDFA|cell"  # 你在 PRG 擴展時用到的 label，集中在這

def seed_info(row_id: int, col: int) -> bytes:
    return SEED_INFO_PREFIX + b"row=" + i2osp(row_id, 4) + b"|col=" + i2osp(col, 2)

def seed_from_gk(gk: bytes, row_id: int, col: int, k_bytes: int) -> bytes:
    return prf_msg(gk, seed_info(row_id, col), k_bytes)

def seed_from_master(master_key: bytes, row_id: int, col: int, k_bytes: int) -> bytes:
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) == 0:
        raise ValueError("master_key must be non-empty bytes")
    return prf_msg(master_key, seed_info(row_id, col), k_bytes)