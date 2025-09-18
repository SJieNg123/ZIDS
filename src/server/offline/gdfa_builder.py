# src/server/offline/gdfa_builder.py
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, List, Optional

from src.common.odfa.params import (
    SecurityParams,
    SparsityParams,
    PackingParams,
    make_packing,
)
from src.common.odfa.matrix import ODFA, ODFARow, pad_row_to_outmax
from src.common.odfa.packing import CellFormat, plan_cell_format
from src.common.odfa.permutation import inverse_perm, sample_perm
from src.common.crypto.prg import prg
from src.common.odfa.seed_rules import PRG_LABEL_CELL

# =========================
# Byte packing for a cell
# =========================

def _pack_bits(next_row_perm: int, attack_id: int, fmt: CellFormat) -> bytes:
    """
    生成定长明文 cell（LE 布局）：
      - [next_row (fmt.ns_bits)] + [aid (fmt.aid_bits，如>0)] + [zero padding]
    允许 aid_bits==0：此时不写 AID 段。
    超出位宽的 AID 会被掩码到 fmt.aid_bits，避免构建因越界中断。
    """
    assert fmt.total_bytes > 0 and fmt.ns_bits >= 1
    ns_mask = (1 << fmt.ns_bits) - 1
    out = (int(next_row_perm) & ns_mask)

    if getattr(fmt, "aid_bits", 0) > 0:
        aid_mask = (1 << fmt.aid_bits) - 1
        out |= (int(attack_id) & aid_mask) << fmt.ns_bits

    # pad_bits 全 0；按总字节数导出
    return int(out).to_bytes(fmt.total_bytes, "little", signed=False)

# =========================
# Outputs (public header / secrets / stream)
# =========================

@dataclass
class GDFAPublicHeader:
    """
    Public metadata the client needs to parse GDFA rows.
    """
    alphabet_size: int
    outmax: int
    cmax: int
    num_states: int
    start_row: int          # PER(start_state)
    permutation: List[int]  # PER: new_row_id -> old_state_id
    cell_bytes: int         # bytes per cell
    row_bytes: int          # bytes per row (= outmax * cell_bytes)
    aid_bits: int


@dataclass
class GDFASecrets:
    """
    Server-only secrets:
      - pad_seeds[new_row][col] : k-byte seed for PRG pad expansion
      - inv_permutation         : old_state -> new_row
    """
    pad_seeds: List[List[bytes]]
    inv_permutation: List[int]


@dataclass
class GDFAStream:
    """
    Offline product:
      - public: header with sizes and permutation
      - secrets: server-only materials
      - rows: iterator yielding encrypted rows in PER order
      - 可选属性（由 builder 附加）:
          row_aids : List[int]  (PER(new_row) 空间的行级 AID 表)
    """
    public: GDFAPublicHeader
    secrets: GDFASecrets
    rows: Iterable[bytes]  # yields row_bytes per row in PER order


# =========================
# Builder
# =========================

def build_gdfa_stream(
    odfa: ODFA,
    sec: SecurityParams,
    sp: SparsityParams,
    *,
    aid_bits: int = 16,
    # Optional: plug the online GK→seed rule so offline rows match online decryption.
    # Signature: pad_seed_fn(new_row: int, col: int, k_bytes: int) -> bytes  (len == k_bytes)
    pad_seed_fn: Optional[Callable[[int, int, int], bytes]] = None,
) -> GDFAStream:
    """
    Build a GDFA row-stream using common ODFA types, packing, and permutation helpers.

    Consistency contract with the online engine:
      seed = PRF(GK[row][col], b"ZIDS|SEED|row="||I2OSP(row,4)||b"|col="||I2OSP(col,2), k_bytes)
      pad  = PRG(seed, PRG_LABEL_CELL, cell_bytes)   # byte mode, not bit mode
      plain_cell = (next_row << aid_bits) | aid      # little-endian bytes of size cell_bytes
      cipher_cell = plain_cell XOR pad
    """
    # 1) Packing params and sanity checks
    pack: PackingParams = make_packing(sec, sp)
    odfa.sanity_check(outmax=sp.outmax)

    # 2) Decide cell layout
    fmt: CellFormat = plan_cell_format(num_states=odfa.num_states, pack=pack, aid_bits=aid_bits)
    assert fmt.total_bits == pack.gdfa_cell_pad_bits, "packing mismatch"
    cell_bytes = fmt.total_bytes
    row_bytes = sp.outmax * cell_bytes

    # 3) Permutation (PER) and its inverse
    perm: List[int] = sample_perm(odfa.num_states)    # new_row -> old_state
    inv_perm: List[int] = inverse_perm(perm)          # old_state -> new_row
    start_row: int = inv_perm[odfa.start_state]

    # ===== 在“逻辑状态(= old_state)空间”聚合行级 AID；稍后映射到 PER(new_row) 空间 =====
    row_aids_logical: List[int] = [0] * odfa.num_states

    # 4) Pre-sample per-cell seeds (server-only)
    pad_seeds: List[List[bytes]] = []
    for new_row in range(odfa.num_states):
        row_seeds: List[bytes] = []
        for c in range(sp.outmax):
            if pad_seed_fn is None:
                seed = os.urandom(sec.k_bytes)
            else:
                seed = pad_seed_fn(new_row, c, sec.k_bytes)
                if not isinstance(seed, (bytes, bytearray)) or len(seed) != sec.k_bytes:
                    raise ValueError("pad_seed_fn must return bytes of length k_bytes")
            row_seeds.append(bytes(seed))
        pad_seeds.append(row_seeds)

    public = GDFAPublicHeader(
        alphabet_size=sec.alphabet_size,
        outmax=sp.outmax,
        cmax=sp.cmax,
        num_states=odfa.num_states,
        start_row=start_row,
        permutation=perm,
        cell_bytes=cell_bytes,
        row_bytes=row_bytes,
        aid_bits=aid_bits,
    )
    secrets = GDFASecrets(pad_seeds=pad_seeds, inv_permutation=inv_perm)

    # 5) Row generator in PER order
    def _row_iter() -> Iterator[bytes]:
        for new_row, old_state in enumerate(perm):
            base_row: ODFARow = odfa.rows[old_state]
            padded: ODFARow = pad_row_to_outmax(base_row, outmax=sp.outmax)

            cells_enc: List[bytes] = []
            for c, edge in enumerate(padded.edges):
                # ---- 提取逻辑目标状态（0 是合法值，不能用“or”）----
                ns_logical = None
                for _name in ("next_state", "dst", "to"):
                    if hasattr(edge, _name):
                        ns_logical = getattr(edge, _name)
                        break
                if ns_logical is None:
                    # 某些占位边可能不带字段；保守自环，避免构建中断
                    ns_logical = old_state

                ns_logical = int(ns_logical)
                if not (0 <= ns_logical < odfa.num_states):
                    raise ValueError(f"bad next_state {ns_logical} at row={old_state} col={c}")

                # ---- 提取 AID（兼容不同字段名；None 视作 0）----
                aid_val = 0
                for _name in ("attack_id", "aid", "accept_id", "rule_id"):
                    if hasattr(edge, _name):
                        v = getattr(edge, _name)
                        aid_val = int(v) if v is not None else 0
                        break

                # ===== 在逻辑空间聚合：把 AID 记到目标状态（首个非零为准）=====
                if aid_val > 0 and row_aids_logical[ns_logical] == 0:
                    row_aids_logical[ns_logical] = aid_val

                # ---- PER 映射 + 打包/加密 ----
                ns_perm = inv_perm[ns_logical]  # 目标状态映射到 PER 行号
                plain  = _pack_bits(ns_perm, aid_val, fmt)
                seed   = secrets.pad_seeds[new_row][c]
                pad    = prg(seed, PRG_LABEL_CELL, cell_bytes)
                ct     = bytes(a ^ b for a, b in zip(plain, pad))
                cells_enc.append(ct)

            row_buf = b"".join(cells_enc)
            assert len(row_buf) == row_bytes
            yield row_buf

    # 构造 stream（rows 采用一次性生成器对象）
    stream = GDFAStream(public=public, secrets=secrets, rows=_row_iter())

    # ===== 关键：把“逻辑空间”的 row_aids 映射到 PER(new_row) 空间，写回 stream =====
    row_aids_per: List[int] = [0] * odfa.num_states
    for new_row, old_state in enumerate(perm):
        row_aids_per[new_row] = row_aids_logical[old_state]

    # 挂载给离线导出器使用（写 row_aids.bin）
    setattr(stream, "row_aids", row_aids_per)

    return stream
