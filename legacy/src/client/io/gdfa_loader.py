# src/client/io/gdfa_loader.py
from __future__ import annotations

import json
import os
import struct
import hashlib
from dataclasses import dataclass
from typing import Optional, List

_MAGIC = b"ZIDSv1\0"


@dataclass(frozen=True)
class GDFAHeader:
    alphabet_size: int
    outmax: int
    cmax: int
    num_states: int
    start_row: int
    permutation: List[int]
    cell_bytes: int
    row_bytes: int
    aid_bits: int


class GDFAImage:
    """
    Read-only view over GDFA rows (ciphertext cells).

    支援兩種離線制品：
      1) container (.gdfa):  MAGIC | len(header) | header(JSON) | rows | sha256(rows)
      2) jsonbin (dir)     :  header.json(.gz) + rows.bin  (+ 可選 row_aids.bin)

    也會自動嘗試載入輔助檔：
      - row_aids (優先讀 header 內嵌；否則讀 artifacts 目錄下的 row_aids.bin)
        * 允許 uint16_le 或 uint32_le（自動判別）
    """
    def __init__(self, header: GDFAHeader, rows_blob: bytes, art_dir: Optional[str] = None):
        self.h = header
        self._rows = rows_blob
        self._art_dir = art_dir  # artifact 目錄（.gdfa 所在目錄 / jsonbin 目錄）

        # --- 基本 sanity ---
        if len(rows_blob) != header.num_states * header.row_bytes:
            raise ValueError(f"rows blob size mismatch: {len(rows_blob)} != num_states*row_bytes "
                             f"({header.num_states}*{header.row_bytes})")
        if header.row_bytes % header.cell_bytes != 0:
            raise ValueError("row_bytes must be a multiple of cell_bytes")
        if header.alphabet_size != 256:
            raise ValueError("this client assumes alphabet_size=256")
        if header.cmax != 1:
            raise ValueError("this client assumes cmax=1 (partition per row)")
        if header.outmax <= 0 or header.cell_bytes <= 0:
            raise ValueError("bad outmax/cell_bytes in header")

        # --- permutation / inverse permutation（可能為空=identity）---
        self._perm: List[int] = list(header.permutation or [])
        if self._perm:
            if len(self._perm) != header.num_states:
                raise ValueError("permutation length mismatch")
            inv = [0] * len(self._perm)
            for new_row, old_state in enumerate(self._perm):
                if not (0 <= old_state < len(self._perm)):
                    raise ValueError("permutation value out of range")
                inv[old_state] = new_row
            self._inv_perm: Optional[List[int]] = inv
        else:
            self._inv_perm = None  # identity

        # --- row_aids（optional）---
        self.row_aids: Optional[List[int]] = None  # PER(new_row) 空間
        # 若 header 內嵌 row_aids，先用它
        # 允許 list[int] 或 dict{row:int}（都會轉成 list）
        # 若 header 沒有，才嘗試讀 artifacts 目錄的 row_aids.bin
        # 注意：這裡只做載入；引擎的 semantic（row/col 命中排序）另行處理
        embedded = None
        try:
            # 一些 packager 可能把 header 保存為普通 dict；這裡嘗試讀出來
            # 若外層傳入的是 dataclass，我們沒辦法直接抓；沒關係，會走 bin 檔回退。
            if isinstance(self.h, GDFAHeader):
                # dataclass：沒有內嵌 row_aids 欄位
                embedded = None
            else:
                embedded = None
        except Exception:
            embedded = None

        if embedded and isinstance(embedded, list) and len(embedded) == self.h.num_states:
            self.row_aids = [int(x or 0) for x in embedded]
        else:
            # 讀 artifacts 目錄旁路檔
            if self._art_dir:
                self._maybe_load_row_aids_sidefile(self._art_dir)

    # ---------- properties ----------
    @property
    def start_row(self) -> int:
        return self.h.start_row

    @property
    def num_states(self) -> int:
        return self.h.num_states

    @property
    def num_rows(self) -> int:  # 別名，部分呼叫相容
        return self.h.num_states

    @property
    def outmax(self) -> int:
        return self.h.outmax

    @property
    def cell_bytes(self) -> int:
        return self.h.cell_bytes

    @property
    def row_bytes(self) -> int:
        return self.h.row_bytes

    @property
    def aid_bits(self) -> int:
        return self.h.aid_bits

    # ---------- core access ----------
    def row_slice(self, row: int) -> memoryview:
        if not (0 <= row < self.h.num_states):
            raise IndexError("row out of range")
        s = row * self.h.row_bytes
        return memoryview(self._rows)[s:s + self.h.row_bytes]

    def get_cell_cipher(self, row: int, col: int) -> bytes:
        if not (0 <= row < self.h.num_states):
            raise IndexError("row out of range")
        cols_per_row = self.h.row_bytes // self.h.cell_bytes
        if not (0 <= col < cols_per_row):
            raise IndexError("col out of range in row stride")
        base = row * self.h.row_bytes + col * self.h.cell_bytes
        return self._rows[base: base + self.h.cell_bytes]

    # 新引擎優先調用這個名稱；與 get_cell_cipher 等價
    def get_cell_bytes(self, row: int, col: int) -> bytes:
        return self.get_cell_cipher(row, col)

    # ---------- permutation helpers ----------
    def inv_permute(self, row: int) -> int:
        """Map physical row index back to logical via inverse permutation (if any)."""
        if self._inv_perm is None:
            return row
        if not (0 <= row < len(self._inv_perm)):
            return row
        return self._inv_perm[row]

    # ---------- acceptance / AID ----------
    def _maybe_load_row_aids_sidefile(self, art_dir: str) -> None:
        """
        Optional aux table: row_aids.bin = num_states × (uint16_le or uint32_le)
        自動判定長度；兩種都支援。
        """
        path = os.path.join(art_dir, "row_aids.bin")
        if not os.path.exists(path):
            return  # optional
        with open(path, "rb") as f:
            buf = f.read()

        n = self.h.num_states
        if len(buf) == n * 2:
            # uint16_le
            self.row_aids = [struct.unpack_from("<H", buf, 2 * i)[0] for i in range(n)]
            return
        if len(buf) == n * 4:
            # uint32_le
            self.row_aids = [struct.unpack_from("<I", buf, 4 * i)[0] for i in range(n)]
            return
        # 長度不合就忽略（不 raise，以免舊版制品阻斷）
        # 你也可以選擇 raise 以盡快發現資料問題：
        # raise ValueError(f"row_aids.bin size mismatch: {len(buf)} not in {{n*2, n*4}}")

    def get_row_aid(self, row: int) -> int:
        """Return >0 if row is accepting with that attack-id; 0 otherwise."""
        if self.row_aids is None:
            return 0
        if 0 <= row < len(self.row_aids):
            return int(self.row_aids[row])
        return 0

    def is_accepting(self, row: int) -> bool:
        return self.get_row_aid(row) > 0


# ---------- loaders ----------

def _parse_header_obj(obj: dict) -> GDFAHeader:
    req = [
        "alphabet_size", "outmax", "cmax", "num_states", "start_row",
        "permutation", "cell_bytes", "row_bytes", "aid_bits"
    ]
    for k in req:
        if k not in obj:
            raise ValueError(f"header missing field: {k}")
    return GDFAHeader(
        alphabet_size=int(obj["alphabet_size"]),
        outmax=int(obj["outmax"]),
        cmax=int(obj["cmax"]),
        num_states=int(obj["num_states"]),
        start_row=int(obj["start_row"]),
        permutation=list(map(int, obj.get("permutation", []))),
        cell_bytes=int(obj["cell_bytes"]),
        row_bytes=int(obj["row_bytes"]),
        aid_bits=int(obj.get("aid_bits", 0)),
    )


def load_from_container(path: str) -> GDFAImage:
    with open(path, "rb") as f:
        blob = f.read()
    if not blob.startswith(_MAGIC):
        raise ValueError("bad container magic")
    p = len(_MAGIC)

    (hlen,) = struct.unpack_from(">I", blob, p); p += 4
    hbytes = blob[p:p + hlen]; p += hlen
    header_obj = json.loads(hbytes.decode("utf-8"))

    rows_end = len(blob) - 32  # sha256 digest
    if rows_end < p:
        raise ValueError("container truncated (rows_end < header_end)")
    rows_blob = blob[p:rows_end]
    digest = blob[rows_end:]
    if hashlib.sha256(rows_blob).digest() != digest:
        raise ValueError("container rows sha256 mismatch")

    header = _parse_header_obj(header_obj)

    # artifact dir = where the .gdfa sits (aux tables live here)
    art_dir = os.path.dirname(os.path.abspath(path))
    img = GDFAImage(header, rows_blob, art_dir=art_dir)

    # 若 header 內嵌 row_aids（例如某些打包器可能會放進 header），就直接使用
    try:
        ra = header_obj.get("row_aids", None)
        if isinstance(ra, list) and len(ra) == header.num_states:
            img.row_aids = [int(x or 0) for x in ra]
    except Exception:
        pass

    return img


def load_from_jsonbin(dirpath: str) -> GDFAImage:
    # header.json（或 header.json.gz） + rows.bin
    header_path = os.path.join(dirpath, "header.json")
    hbytes: bytes
    if os.path.exists(header_path):
        with open(header_path, "rb") as f:
            hbytes = f.read()
    else:
        # try gz
        gz_path = header_path + ".gz"
        import gzip
        with gzip.open(gz_path, "rb") as f:
            hbytes = f.read()

    header_obj = json.loads(hbytes.decode("utf-8"))

    rows_path = os.path.join(dirpath, "rows.bin")
    with open(rows_path, "rb") as f:
        rows_blob = f.read()

    # optional rows_sha256 for verification
    if "rows_sha256" in header_obj:
        if hashlib.sha256(rows_blob).hexdigest() != header_obj["rows_sha256"]:
            raise ValueError("rows.bin sha256 mismatch against header")

    header = _parse_header_obj(header_obj)
    img = GDFAImage(header, rows_blob, art_dir=os.path.abspath(dirpath))

    # 同樣支援 header 內嵌 row_aids
    try:
        ra = header_obj.get("row_aids", None)
        if isinstance(ra, list) and len(ra) == header.num_states:
            img.row_aids = [int(x or 0) for x in ra]
    except Exception:
        pass

    return img


def load_gdfa(path: str) -> GDFAImage:
    """
    Auto-detect by extension: *.gdfa => container, else treat as directory for jsonbin.
    """
    if os.path.isdir(path):
        return load_from_jsonbin(path)
    if path.lower().endswith(".gdfa"):
        return load_from_container(path)
    # if it's a file but not .gdfa, attempt container anyway
    return load_from_container(path)