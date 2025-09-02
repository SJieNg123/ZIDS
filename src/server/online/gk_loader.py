# src/server/online/gk_loader.py
from __future__ import annotations
import json, os
from typing import List
from src.server.online.ot_response_builder import GKStore
from src.server.offline.key_generator import derive_deterministic_gk_table

def load_gk_store_from_files(dirpath: str) -> GKStore:
    meta_path = os.path.join(dirpath, "gk_meta.json")
    bin_path  = os.path.join(dirpath, "gk_table.bin")
    with open(meta_path, "rb") as f:
        meta = json.loads(f.read().decode("utf-8"))
    num_rows: int = int(meta["num_rows"])
    cols_per_row: List[int] = list(map(int, meta["cols_per_row"]))
    k_bytes: int = int(meta["k_bytes"])
    with open(bin_path, "rb") as f:
        blob = f.read()
    table: List[List[bytes]] = []
    p = 0
    for m in cols_per_row:
        row = []
        for _ in range(m):
            row.append(blob[p:p+k_bytes]); p += k_bytes
        table.append(row)
    if p != len(blob):
        raise ValueError("gk_table.bin size mismatch with meta")
    return GKStore(table)

def load_gk_store_from_master(master_key: bytes, cols_per_row: List[int], k_bytes: int) -> GKStore:
    table = derive_deterministic_gk_table(master_key, cols_per_row=cols_per_row, k_bytes=k_bytes)
    return GKStore(table)
