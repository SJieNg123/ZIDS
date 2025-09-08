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
    permutation: list[int]
    cell_bytes: int
    row_bytes: int
    aid_bits: int

class GDFAImage:
    """
    Read-only view over GDFA rows (ciphertext cells).
    Supports both:
      - container (.gdfa): header + rows + sha256
      - jsonbin (dir):    header.json(+.gz) + rows.bin
    Optionally loads auxiliary tables from the artifact directory:
      - row_aids.bin : num_states × uint32_le  (line-level AID table)
    """
    def __init__(self, header: GDFAHeader, rows_blob: bytes, art_dir: Optional[str] = None):
        self.h = header
        self._rows = rows_blob
        self._art_dir = art_dir  # base dir for aux tables (may be None for raw buffers)

        # ---- quick sanity ----
        if len(rows_blob) != header.num_states * header.row_bytes:
            raise ValueError("rows blob size mismatch against header")
        if header.row_bytes % header.cell_bytes != 0:
            raise ValueError("row_bytes must be a multiple of cell_bytes")
        if header.alphabet_size != 256:
            raise ValueError("this client assumes alphabet_size=256")
        if header.cmax != 1:
            raise ValueError("this client assumes cmax=1 (partition per row)")

        # ---- permutation / inverse permutation (optional) ----
        self._perm: List[int] = list(header.permutation or [])
        if self._perm and len(self._perm) != header.num_states:
            raise ValueError("permutation length mismatch")
        if self._perm:
            inv = [0] * len(self._perm)
            for i, p in enumerate(self._perm):
                if not (0 <= p < len(self._perm)):
                    raise ValueError("permutation value out of range")
                inv[p] = i
            self._inv_perm: Optional[List[int]] = inv
        else:
            self._inv_perm = None  # identity

        # ---- optional aux tables ----
        self.row_aids: Optional[List[int]] = None
        if self._art_dir:
            self._maybe_load_row_aids(self._art_dir)

    # ---------- properties ----------
    @property
    def start_row(self) -> int:
        return self.h.start_row

    @property
    def num_states(self) -> int:
        return self.h.num_states

    # 有些调用会尝试 num_rows；给个别名以提高兼容性
    @property
    def num_rows(self) -> int:
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

    # 新引擎优先调用 get_cell_bytes；这里与 get_cell_cipher 等价
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
    def _maybe_load_row_aids(self, art_dir: str) -> None:
        """
        Optional aux table: row_aids.bin = num_states × uint32_le
        """
        path = os.path.join(art_dir, "row_aids.bin")
        if not os.path.exists(path):
            # optional
            return
        with open(path, "rb") as f:
            buf = f.read()
        exp = self.h.num_states * 4
        if len(buf) != exp:
            raise ValueError(f"row_aids.bin size mismatch: {len(buf)} != {exp}")
        self.row_aids = [struct.unpack_from("<I", buf, 4 * i)[0] for i in range(self.h.num_states)]

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
    req = ["alphabet_size","outmax","cmax","num_states","start_row",
           "permutation","cell_bytes","row_bytes","aid_bits"]
    for k in req:
        if k not in obj:
            raise ValueError(f"header missing field: {k}")
    return GDFAHeader(
        alphabet_size=int(obj["alphabet_size"]),
        outmax=int(obj["outmax"]),
        cmax=int(obj["cmax"]),
        num_states=int(obj["num_states"]),
        start_row=int(obj["start_row"]),
        permutation=list(map(int, obj["permutation"])),
        cell_bytes=int(obj["cell_bytes"]),
        row_bytes=int(obj["row_bytes"]),
        aid_bits=int(obj["aid_bits"]),
    )

def load_from_container(path: str) -> GDFAImage:
    with open(path, "rb") as f:
        blob = f.read()
    if not blob.startswith(_MAGIC):
        raise ValueError("bad container magic")
    p = len(_MAGIC)
    (hlen,) = struct.unpack_from(">I", blob, p)
    p += 4
    hbytes = blob[p:p+hlen]; p += hlen
    header_obj = json.loads(hbytes.decode("utf-8"))
    rows_end = len(blob) - 32  # sha256 digest
    rows_blob = blob[p:rows_end]
    digest = blob[rows_end:]
    if hashlib.sha256(rows_blob).digest() != digest:
        raise ValueError("container rows sha256 mismatch")
    header = _parse_header_obj(header_obj)

    # artifact dir = where the .gdfa sits (aux tables live here)
    art_dir = os.path.dirname(os.path.abspath(path))
    return GDFAImage(header, rows_blob, art_dir=art_dir)

def load_from_jsonbin(dirpath: str) -> GDFAImage:
    # header.json (optionally gz) + rows.bin
    header_path = os.path.join(dirpath, "header.json")
    if not os.path.exists(header_path):
        # try gz
        gz_path = header_path + ".gz"
        import gzip
        with gzip.open(gz_path, "rb") as f:
            hbytes = f.read()
    else:
        with open(header_path, "rb") as f:
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
    return GDFAImage(header, rows_blob, art_dir=os.path.abspath(dirpath))

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