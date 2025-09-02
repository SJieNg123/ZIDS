# src/client/io/row_alph_loader.py
from __future__ import annotations
import json
import os
from dataclasses import dataclass

@dataclass(frozen=True)
class RowAlphabetMeta:
    num_rows: int
    cols_per_row: list[int]
    format: str

class RowAlphabetMap:
    """
    row_alph.bin/json as produced by build_gdfa_from_rules.py:
      - bin:  num_rows × 256 bytes (row-major)
      - json: {num_rows, cols_per_row, format}
    """
    def __init__(self, meta: RowAlphabetMeta, table_bytes: bytes):
        if len(table_bytes) != meta.num_rows * 256:
            raise ValueError("row_alph.bin size mismatch")
        self.meta = meta
        self._tbl = table_bytes

    @staticmethod
    def load(dirpath: str) -> "RowAlphabetMap":
        meta_path = os.path.join(dirpath, "row_alph.json")
        bin_path  = os.path.join(dirpath, "row_alph.bin")
        with open(meta_path, "rb") as f:
            meta_obj = json.loads(f.read().decode("utf-8"))
        meta = RowAlphabetMeta(
            num_rows=int(meta_obj["num_rows"]),
            cols_per_row=list(map(int, meta_obj["cols_per_row"])),
            format=str(meta_obj.get("format","")),
        )
        with open(bin_path, "rb") as f:
            tbl = f.read()
        return RowAlphabetMap(meta, tbl)

    def get_col(self, row: int, byte_val: int) -> int:
        if not (0 <= row < self.meta.num_rows):
            raise IndexError("row out of range")
        if not (0 <= byte_val <= 255):
            raise ValueError("byte_val must be 0..255")
        idx = row * 256 + byte_val
        return self._tbl[idx]

    def num_cols(self, row: int) -> int:
        return self.meta.cols_per_row[row]