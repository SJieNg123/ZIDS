# src/client/online/engine.py
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple, Optional, Protocol, Dict

from src.client.io.gdfa_loader import GDFAImage
from src.client.io.row_alph_loader import RowAlphabetMap
from src.common.odfa.seed_rules import seed_from_gk, seed_info, i2osp, PRG_LABEL_CELL
from src.common.crypto.prg import prg  # assumes prg(seed, label, out_len) -> bytes

class OTChooser(Protocol):
    """
    Minimal OT client interface expected by the engine.
    It must perform a 1-of-m OT to obtain GK[row][col] from the server, using `aad` for binding.

    Returns the selected GK bytes (length is determined by the server-side configuration).
    """
    def acquire_gk(self, *, row_id: int, m: int, col: int, aad: bytes) -> bytes: ...

@dataclass
class EngineConfig:
    # Build AAD as in server SessionState.aad_for_row: b"ZIDS|GK|sid=<ascii>|row=<4B>"
    session_id: str
    enable_gk_cache: bool = True

class ZIDSEngine:
    """
    Minimal online engine:
      - walks the DFA over input bytes
      - for each step, maps (row, byte) -> col via RowAlphabetMap
      - uses OT chooser to fetch GK for (row, col) with per-row AAD
      - derives SEED = PRF(GK, seed_info(row,col)), expands to cell_bytes via PRG
      - XORs pad with ciphertext cell to recover plaintext: (next_row, attack_id)
    """

    def __init__(self, gdfa: GDFAImage, row_alph: RowAlphabetMap, ot: OTChooser, cfg: EngineConfig):
        # basic checks
        if gdfa.num_states != row_alph.meta.num_rows:
            raise ValueError("gdfa.num_states != row_alph.num_rows")
        self.gdfa = gdfa
        self.row_alph = row_alph
        self.ot = ot
        self.cfg = cfg
        self._gk_cache: Dict[Tuple[int,int], bytes] = {}

    def _aad_for_row(self, row_id: int) -> bytes:
        return b"ZIDS|GK" + b"|sid=" + self.cfg.session_id.encode("ascii") + b"|row=" + i2osp(row_id, 4)

    def _decode_cell_plain(self, plain: bytes) -> Tuple[int, int]:
        """
        Cell layout: big-endian integer where low 'aid_bits' are attack_id, high bits are next_row.
        """
        if len(plain) != self.gdfa.cell_bytes:
            raise ValueError("cell plaintext length mismatch")
        x = int.from_bytes(plain, "big")
        aid_mask = (1 << self.gdfa.aid_bits) - 1
        aid = x & aid_mask
        next_row = x >> self.gdfa.aid_bits
        # range checks (defensive)
        if not (0 <= next_row < self.gdfa.num_states):
            # If packing reserved more bits than needed, next_row could still be in range; else treat as invalid.
            raise ValueError("decoded next_row out of range")
        return next_row, aid

    def _get_gk(self, row: int, col: int) -> bytes:
        if self.cfg.enable_gk_cache:
            key = (row, col)
            if key in self._gk_cache:
                return self._gk_cache[key]
        aad = self._aad_for_row(row)
        m = self.row_alph.num_cols(row)
        gk = self.ot.acquire_gk(row_id=row, m=m, col=col, aad=aad)
        if self.cfg.enable_gk_cache:
            self._gk_cache[(row, col)] = gk
        return gk

    def _open_cell(self, row: int, col: int) -> Tuple[int, int]:
        """
        Returns (next_row, attack_id) by opening ciphertext cell (row,col).
        """
        cipher = self.gdfa.get_cell_cipher(row, col)
        gk = self._get_gk(row, col)
        seed = seed_from_gk(gk, row, col, self.gdfa.cell_bytes)
        pad = prg(seed, PRG_LABEL_CELL, self.gdfa.cell_bytes)
        plain = bytes(a ^ b for a, b in zip(cipher, pad))
        return self._decode_cell_plain(plain)

    def run(self, data: bytes, *, collect_all_hits: bool = True) -> List[Tuple[int, int]]:
        """
        Walk the automaton over 'data' and return a list of (offset, attack_id) hits.
        offset = index in 'data' at which the transition producing the accepting row occurred.
        """
        row = self.gdfa.start_row
        hits: List[Tuple[int, int]] = []
        for i, b in enumerate(data):
            col = self.row_alph.get_col(row, b)
            # sanity: col must be within row's m and also within outmax stride
            m = self.row_alph.num_cols(row)
            if not (0 <= col < m):
                raise ValueError("mapped col out of row's group count")
            next_row, aid = self._open_cell(row, col)
            if aid:
                hits.append((i, aid))
                if not collect_all_hits:
                    break
            row = next_row
        return hits