# src/client/io/gdfa_loader.py
from __future__ import annotations
import json
import os
import struct
import hashlib
from dataclasses import dataclass
from typing import Optional

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
    Supports both container (.gdfa) and jsonbin (header.json + rows.bin).
    """
    def __init__(self, header: GDFAHeader, rows_blob: bytes):
        self.h = header
        self._rows = rows_blob
        # quick sanity
        if len(rows_blob) != header.num_states * header.row_bytes:
            raise ValueError("rows blob size mismatch against header")
        if header.row_bytes % header.cell_bytes != 0:
            raise ValueError("row_bytes must be a multiple of cell_bytes")
        if header.alphabet_size != 256:
            raise ValueError("this client assumes alphabet_size=256")
        if header.cmax != 1:
            raise ValueError("this client assumes cmax=1 (partition per row)")

    @property
    def start_row(self) -> int:
        return self.h.start_row

    @property
    def num_states(self) -> int:
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

    def row_slice(self, row: int) -> memoryview:
        if not (0 <= row < self.h.num_states):
            raise IndexError("row out of range")
        s = row * self.h.row_bytes
        return memoryview(self._rows)[s:s + self.h.row_bytes]

    def get_cell_cipher(self, row: int, col: int) -> bytes:
        if not (0 <= col < (self.h.row_bytes // self.h.cell_bytes)):
            raise IndexError("col out of range in row stride")
        base = row * self.h.row_bytes + col * self.h.cell_bytes
        return self._rows[base: base + self.h.cell_bytes]

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
    return GDFAImage(header, rows_blob)

def load_from_jsonbin(dirpath: str) -> GDFAImage:
    # header.json (optionally gz) + rows.bin
    header_path = os.path.join(dirpath, "header.json")
    if not os.path.exists(header_path):
        # try gz
        header_path += ".gz"
        import gzip
        with gzip.open(header_path, "rb") as f:
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
    return GDFAImage(header, rows_blob)

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
