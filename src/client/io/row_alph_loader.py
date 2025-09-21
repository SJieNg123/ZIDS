# src/client/io/row_alph_loader.py
from __future__ import annotations
import json
import os
from dataclasses import dataclass
from typing import List

@dataclass(frozen=True)
class RowAlphabetMeta:
    num_rows: int
    cols_per_row: List[int]
    format: str  # JSON 里写什么都接收，但不要用它做强约束

class RowAlphabetMap:
    """
    Row Alphabet 映射（客户端稳定 API）：
      - 旧/默认二进制布局：row_alph.bin = num_rows × 256 字节（行主序），
        每项是该行该字节映射到的“单个列索引”（0..m-1）。
        → 本实现**优先以长度判别**此布局（len == num_rows*256），与 meta.format 无关。
      - 未来如果引入多映射布局（支持 cmax>1 的显式编码），
        再增加新分支（建议带魔数/版本号），**不破坏**既有行为。

    公开 API（稳定面）：
      - num_rows() / num_cols(row)            -> int
      - get_col(row, byte)                    -> int          （历史兼容）
      - get_cols(row, byte)                   -> List[int]    （候选列集合；旧布局退化为 [get_col]）
    """

    # ---- 装载（目录） ----
    @staticmethod
    def load(dirpath: str) -> "RowAlphabetMap":
        meta_path = os.path.join(dirpath, "row_alph.json")
        bin_path  = os.path.join(dirpath, "row_alph.bin")
        with open(meta_path, "rb") as f:
            meta_obj = json.loads(f.read().decode("utf-8"))
        meta = RowAlphabetMeta(
            num_rows=int(meta_obj["num_rows"]),
            cols_per_row=list(map(int, meta_obj["cols_per_row"])),
            format=str(meta_obj.get("format", "")),
        )
        with open(bin_path, "rb") as f:
            tbl = f.read()
        return RowAlphabetMap(meta, tbl)

    # ---- 初始化 ----
    def __init__(self, meta: RowAlphabetMeta, table_bytes: bytes):
        # 基本校验
        if len(meta.cols_per_row) != meta.num_rows:
            raise ValueError("cols_per_row length mismatch with num_rows")
        for r, m in enumerate(meta.cols_per_row):
            if m <= 0 or m > 256:
                raise ValueError(f"cols_per_row[{r}] out of supported range: {m}")

        self.meta = meta

        # 以长度判别旧/默认布局（单映射，单字节索引，行主序）
        single_layout_len = meta.num_rows * 256
        if len(table_bytes) == single_layout_len:
            self._layout = "single8"   # 旧布局
            self._tbl = table_bytes    # bytes；索引结果是 0..255 的 int
        else:
            # 未来新布局：建议定义带魔数/版本的自描述格式；这里先拒绝，避免“猜错破坏用户空间”
            raise NotImplementedError(
                f"unsupported row_alph layout: bin_size={len(table_bytes)} "
                f"expected={single_layout_len}; meta.format='{meta.format}'"
            )

    # ---- 公共 API ----
    @property
    def num_rows(self) -> int:
        return self.meta.num_rows

    def num_cols(self, row: int) -> int:
        self._check_row(row)
        return self.meta.cols_per_row[row]

    def get_col(self, row: int, byte_val: int) -> int:
        """历史兼容：旧布局返回单个列索引。"""
        self._check_row(row)
        b = self._check_byte(byte_val)
        if self._layout == "single8":
            idx = row * 256 + b
            col = self._tbl[idx]
            m = self.meta.cols_per_row[row]
            if col >= m:
                # 工件不配套/损坏：单字节索引超出该行列数
                raise ValueError(f"row_alph mapping out of range: row={row} byte={b} -> col={col} (m={m})")
            return col
        raise NotImplementedError(f"get_col unsupported for layout={self._layout}")

    def get_cols(self, row: int, byte_val: int) -> List[int]:
        """
        候选列集合（≤ cmax）：
          - 旧布局退化为 [get_col(row, byte)]
          - 新布局（未来）返回多列
        """
        if self._layout == "single8":
            return [self.get_col(row, byte_val)]
        raise NotImplementedError(f"get_cols unsupported for layout={self._layout}")

    # ---- 内部校验 ----
    @staticmethod
    def _check_byte(byte_val: int) -> int:
        if not (0 <= byte_val <= 255):
            raise ValueError("byte_val must be 0..255")
        return byte_val

    def _check_row(self, row: int) -> None:
        if not (0 <= row < self.meta.num_rows):
            raise IndexError("row out of range")

# ===== 新增：方便函数，讓 engine.init_for_cli() 可以匯入 =====
def load_row_alph(path_or_dir: str) -> RowAlphabetMap:
    """
    載入 RowAlphabetMap：
      - 給「目錄」：目錄下必須有 row_alph.json + row_alph.bin
      - 給「檔案路徑」（通常是 row_alph.bin）：會到**同一目錄**找 row_alph.json
    """
    if os.path.isdir(path_or_dir):
        return RowAlphabetMap.load(path_or_dir)

    # 檔案路徑
    dirpath = os.path.dirname(path_or_dir) or "."
    meta_path = os.path.join(dirpath, "row_alph.json")
    if not os.path.exists(meta_path):
        raise FileNotFoundError(f"row_alph.json not found beside '{path_or_dir}'")

    with open(meta_path, "rb") as f:
        meta_obj = json.loads(f.read().decode("utf-8"))
    meta = RowAlphabetMeta(
        num_rows=int(meta_obj["num_rows"]),
        cols_per_row=list(map(int, meta_obj["cols_per_row"])),
        format=str(meta_obj.get("format", "")),
    )
    with open(path_or_dir, "rb") as f:
        tbl = f.read()
    return RowAlphabetMap(meta, tbl)