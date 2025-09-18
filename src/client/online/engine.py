# src/client/online/engine.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Tuple, Protocol, Iterable, List

from src.client.io.gdfa_loader import GDFAImage
from src.client.io.row_alph_loader import RowAlphabetMap
from src.common.odfa.seed_rules import seed_from_gk, i2osp, PRG_LABEL_CELL
from src.common.crypto.prg import prg
from src.common.urlnorm import canonicalize


# ---- OT chooser 协议（兼容多实现）--------------------------------------------
class OTChooser(Protocol):
    # 新式接口（推荐）
    def choose_one(self, row: int, col: int) -> bytes: ...
    def ensure_row_payload_cached(self, row: int) -> None: ...
    # 旧式接口（保留兼容）
    def acquire_gk(self, *, row_id: int, m: int, col: int, aad: bytes) -> bytes: ...


@dataclass
class EngineConfig:
    session_id: str
    enable_gk_cache: bool = True
    k_bytes: int = 16  # = manifest.crypto_params.k // 8


class ZIDSEngine:
    """
    在线解密执行：
      - 每字节：按 RowAlphabet 把列集合映射到 GK；解密 cell；解析 next_row；迁移
      - 命中：进入 next_row 后，优先用行级 AID（row_aids.bin），cell 内 AID 兜底
    """
    def __init__(self, gdfa: GDFAImage, row_alph: RowAlphabetMap, chooser: OTChooser, cfg: EngineConfig):
        # 基础一致性
        if gdfa.num_states != row_alph.meta.num_rows:
            raise ValueError("gdfa.num_states != row_alph.num_rows")
        self.gdfa = gdfa
        self.row_alph = row_alph
        self.chooser = chooser
        self.cfg = cfg
        self._gk_cache: Dict[Tuple[int, int], bytes] = {}

    # ----------------- 内部工具 -----------------
    def _aad_for_row(self, row_id: int) -> bytes:
        return (b"ZIDS|GK|sid=" + self.cfg.session_id.encode("ascii") +
                b"|row=" + i2osp(row_id, 4))

    def _derive_seed(self, gk: bytes, row: int, col: int) -> bytes:
        # 与离线构建严格一致的种子派生
        return seed_from_gk(gk, row, col, self.cfg.k_bytes)

    def _prg(self, seed: bytes, nbytes: int) -> bytes:
        return prg(seed, PRG_LABEL_CELL, nbytes)

    def _get_gk(self, row: int, col: int) -> bytes:
        if self.cfg.enable_gk_cache:
            key = (row, col)
            gk = self._gk_cache.get(key)
            if gk is not None:
                return gk

        # 优先使用新式 chooser 接口
        if hasattr(self.chooser, "ensure_row_payload_cached"):
            self.chooser.ensure_row_payload_cached(row)
        if hasattr(self.chooser, "choose_one"):
            gk = self.chooser.choose_one(row, col)
        elif hasattr(self.chooser, "acquire_gk"):
            # 旧式接口兜底
            m = self.row_alph.num_cols(row)
            aad = self._aad_for_row(row)
            gk = self.chooser.acquire_gk(row_id=row, m=m, col=col, aad=aad)  # type: ignore[attr-defined]
        else:
            raise RuntimeError("OT chooser does not provide a supported API")

        if self.cfg.enable_gk_cache:
            self._gk_cache[(row, col)] = gk
        return gk

    def _decode_cell_plain(self, plain: bytes) -> tuple[int, int]:
        """
        解析明文 cell：
          布局（LE）: [next_row (row_bits)] + [aid (aid_bits, 可为 0)] + [padding]
          若读出 next_row 超界，再尝试回退布局 [aid][next_row]（兼容旧工件）
        """
        num_rows = self.gdfa.num_states
        row_bits = max(1, (num_rows - 1).bit_length())
        row_bytes = (row_bits + 7) // 8

        aid_bits = getattr(self.gdfa, "aid_bits", 0) or 0
        aid_bytes = (aid_bits + 7) // 8 if aid_bits > 0 else 0

        mask_row = (1 << row_bits) - 1
        mask_aid = (1 << aid_bits) - 1 if aid_bits > 0 else 0

        # 布局 A: [next_row][aid]
        nr = int.from_bytes(plain[:row_bytes], "little") & mask_row
        aid = 0
        if aid_bits:
            aid = int.from_bytes(plain[row_bytes:row_bytes + aid_bytes], "little") & mask_aid
        if 0 <= nr < num_rows:
            return nr, aid

        # 布局 B 回退: [aid][next_row]
        if aid_bits:
            aid2 = int.from_bytes(plain[:aid_bytes], "little") & mask_aid
            nr2 = int.from_bytes(plain[aid_bytes:aid_bytes + row_bytes], "little") & mask_row
            if 0 <= nr2 < num_rows:
                return nr2, aid2

        raise ValueError("decoded next_row out of range")

    def _open_cell(self, row: int, col: int) -> tuple[int, int]:
        ct = self.gdfa.get_cell_cipher(row, col)
        gk = self._get_gk(row, col)
        seed = self._derive_seed(gk, row, col)
        pad = self._prg(seed, self.gdfa.cell_bytes)
        plain = bytes(a ^ b for a, b in zip(ct, pad))
        return self._decode_cell_plain(plain)

    # ----------------- 主流程 -----------------
    def run(self, data: bytes) -> List[int]:
        """
        执行匹配：
          - 输入先 canonicalize（与离线一致）
          - 逐字节按照 RowAlphabet 选择列，解密迁移
          - 命中检查在“进入 next_row 之后”，优先 row_aids
        返回：命中 AID 列表（可能多个）
        """
        data = canonicalize(data)

        hits: List[int] = []
        row = self.gdfa.start_row

        for b in data:
            cols: Iterable[int] = self.row_alph.get_cols(row, b)
            # 兼容实现：get_cols 可能返回 int
            if isinstance(cols, int):
                cols = [cols]

            next_row = None
            last_err: Exception | None = None

            for col in cols:
                try:
                    nr, aid_cell = self._open_cell(row, col)
                    next_row = nr
                    # 进入 next_row 后再判定命中（优先 row_aids）
                    row = next_row
                    aid_row = self.gdfa.get_row_aid(row) if hasattr(self.gdfa, "get_row_aid") else 0
                    if aid_row > 0:
                        hits.append(aid_row)
                    elif aid_cell > 0:
                        hits.append(aid_cell)
                    break
                except Exception as e:
                    last_err = e
                    continue

            if next_row is None:
                raise ValueError(f"no valid column among {list(cols)} at row={row} byte={b} ({last_err})")

        return hits