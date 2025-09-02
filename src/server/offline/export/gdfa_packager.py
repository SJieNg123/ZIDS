# src/server/export/gdfa_packager.py
from __future__ import annotations
import json
import os
import struct
import hashlib
from typing import Iterable

from src.server.offline.gdfa_builder import GDFAPublicHeader

_MAGIC = b"ZIDSv1\0"

def write_jsonbin(outdir: str, pub: GDFAPublicHeader, rows: Iterable[bytes], *, gzip_header: bool = False) -> None:
    import gzip

    os.makedirs(outdir, exist_ok=True)
    header_path = os.path.join(outdir, "header.json" + (".gz" if gzip_header else ""))
    rows_path   = os.path.join(outdir, "rows.bin")

    rows_list = list(rows)
    for i, r in enumerate(rows_list):
        if len(r) != pub.row_bytes:
            raise ValueError(f"row {i} length {len(r)} != row_bytes {pub.row_bytes}")
    rows_blob = b"".join(rows_list)
    expected = pub.num_states * pub.row_bytes
    if len(rows_blob) != expected:
        raise ValueError(f"rows total length {len(rows_blob)} != {expected}")

    header_obj = {
        "alphabet_size": pub.alphabet_size,
        "outmax": pub.outmax,
        "cmax": pub.cmax,
        "num_states": pub.num_states,
        "start_row": pub.start_row,
        "permutation": pub.permutation,
        "cell_bytes": pub.cell_bytes,
        "row_bytes": pub.row_bytes,
        "aid_bits": pub.aid_bits,
        "rows_sha256": hashlib.sha256(rows_blob).hexdigest(),
    }
    header_bytes = json.dumps(header_obj, indent=2, sort_keys=True).encode("utf-8")

    if gzip_header:
        with gzip.open(header_path, "wb") as gz:
            gz.write(header_bytes)
    else:
        with open(header_path, "wb") as f:
            f.write(header_bytes)

    with open(rows_path, "wb") as f:
        f.write(rows_blob)

def write_container(container_path: str, pub: GDFAPublicHeader, rows: Iterable[bytes]) -> None:
    os.makedirs(os.path.dirname(container_path) or ".", exist_ok=True)

    rows_list = list(rows)
    for i, r in enumerate(rows_list):
        if len(r) != pub.row_bytes:
            raise ValueError(f"row {i} length {len(r)} != row_bytes {pub.row_bytes}")
    rows_blob = b"".join(rows_list)
    expected = pub.num_states * pub.row_bytes
    if len(rows_blob) != expected:
        raise ValueError(f"rows total length {len(rows_blob)} != {expected}")

    header_obj = {
        "alphabet_size": pub.alphabet_size,
        "outmax": pub.outmax,
        "cmax": pub.cmax,
        "num_states": pub.num_states,
        "start_row": pub.start_row,
        "permutation": pub.permutation,
        "cell_bytes": pub.cell_bytes,
        "row_bytes": pub.row_bytes,
        "aid_bits": pub.aid_bits,
    }
    hdr_bytes = json.dumps(header_obj, separators=(",", ":")).encode("utf-8")
    body_hash = hashlib.sha256(rows_blob).digest()

    with open(container_path, "wb") as f:
        f.write(_MAGIC)
        f.write(struct.pack(">I", len(hdr_bytes)))
        f.write(hdr_bytes)
        f.write(rows_blob)
        f.write(body_hash)
