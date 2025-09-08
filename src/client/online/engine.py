# src/client/online/engine.py
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple, Dict, Protocol, Optional

from src.client.io.gdfa_loader import GDFAImage
from src.client.io.row_alph_loader import RowAlphabetMap
from src.common.odfa.seed_rules import seed_from_gk, i2osp, PRG_LABEL_CELL
from src.common.crypto.prg import prg


class OTChooser(Protocol):
    # 线上真 OT 至少实现这个
    def acquire_gk(self, *, row_id: int, m: int, col: int, aad: bytes) -> bytes: ...
    # 本地评测假 OT 可实现以下三个（可选）
    def ensure_row_payload_cached(self, row: int) -> None: ...
    def get_row_payload(self, row: int) -> Tuple[bytes, List[bytes]]: ...
    def choose_one(self, row: int, col: int) -> bytes: ...


@dataclass
class EngineConfig:
    session_id: str
    enable_gk_cache: bool = True
    # manifest.crypto_params.k // 8；新字段 seed_k_bytes 优先，k_bytes 作为兼容
    k_bytes: int = 16
    seed_k_bytes: Optional[int] = None


class ZIDSEngine:
    def __init__(self, gdfa: GDFAImage, row_alph: RowAlphabetMap, chooser: OTChooser, cfg: EngineConfig):
        if getattr(gdfa, "num_states", None) != row_alph.num_rows:
            raise ValueError("gdfa.num_states != row_alph.num_rows")
        self.gdfa = gdfa
        self.row_alph = row_alph
        self.cfg = cfg
        self.chooser = chooser
        self._gk_cache: Dict[Tuple[int, int], bytes] = {}

    # ----------------- 基础助手 -----------------
    def _seed_len(self) -> int:
        v = self.cfg.seed_k_bytes if self.cfg.seed_k_bytes is not None else self.cfg.k_bytes
        if not isinstance(v, int) or v <= 0:
            raise ValueError("EngineConfig missing seed length (seed_k_bytes/k_bytes)")
        return v

    def _aad_for_row(self, row_id: int) -> bytes:
        return b"ZIDS|GK|sid=" + self.cfg.session_id.encode("ascii") + b"|row=" + i2osp(row_id, 4)

    def _derive_seed(self, gk: bytes, row: int, col: int) -> bytes:
        return seed_from_gk(gk, row, col, self._seed_len())

    def _prg(self, seed: bytes, out_len: int) -> bytes:
        return prg(seed, PRG_LABEL_CELL, out_len)

    def _get_cell_bytes(self, row: int, col: int) -> bytes:
        if hasattr(self.gdfa, "get_cell_bytes"):
            return self.gdfa.get_cell_bytes(row, col)
        if hasattr(self.gdfa, "get_cell_cipher"):
            return self.gdfa.get_cell_cipher(row, col)
        if hasattr(self.gdfa, "cell_at"):
            return self.gdfa.cell_at(row, col)
        raise AttributeError("GDFA image does not expose cell bytes; add get_cell_bytes(row,col)")

    def _ensure_row_cached(self, row: int) -> None:
        if hasattr(self.chooser, "ensure_row_payload_cached"):
            try:
                self.chooser.ensure_row_payload_cached(row)  # 本地评测：整行缓存
            except TypeError:
                pass

    def _choose_one(self, row: int, col: int) -> bytes:
        # 本地评测假 OT 优先（直接从缓存按逻辑列取 GK；内部可有“槽位探测”）
        if hasattr(self.chooser, "choose_one"):
            return self.chooser.choose_one(row, col)
        # 线上真 OT：按逻辑列做 1-of-m
        key = (row, col)
        if self.cfg.enable_gk_cache and key in self._gk_cache:
            return self._gk_cache[key]
        m = self.row_alph.num_cols(row)
        aad = self._aad_for_row(row)
        gk = self.chooser.acquire_gk(row_id=row, m=m, col=col, aad=aad)
        if self.cfg.enable_gk_cache:
            self._gk_cache[key] = gk
        return gk

    # ----------------- 明文解码（自适应）-----------------
    def _decode_cell_plain(self, plain: bytes) -> Tuple[int, int]:
        # 行数/位宽
        num_rows = getattr(self.gdfa, "num_states", None) \
            or getattr(self.gdfa, "num_rows", None) \
            or getattr(self.row_alph, "num_rows", None)
        if not isinstance(num_rows, int) or num_rows <= 0:
            raise ValueError("cannot determine num_rows")

        row_bits = (num_rows - 1).bit_length()
        row_bytes = (row_bits + 7) // 8

        # AID 位宽（若不存在则为 0）
        aid_bits = getattr(self.gdfa, "aid_bits", 0) or 0
        aid_bytes = (aid_bits + 7) // 8 if aid_bits > 0 else 0

        mask_row = (1 << row_bits) - 1
        mask_aid = (1 << aid_bits) - 1 if aid_bits > 0 else 0

        # 四种组合：布局 A/B × 是否逆置换
        def try_layout(aid_first: bool, apply_invperm: bool):
            if aid_first and aid_bits:
                off_aid = 0
                off_nr = aid_bytes
                aid_val = int.from_bytes(plain[off_aid:off_aid + aid_bytes], "little") & mask_aid
            else:
                off_nr = 0
                aid_val = 0

            nr = int.from_bytes(plain[off_nr:off_nr + row_bytes], "little") & mask_row

            if apply_invperm and hasattr(self.gdfa, "inv_permute") and callable(self.gdfa.inv_permute):
                nr = self.gdfa.inv_permute(nr)

            if 0 <= nr < num_rows:
                return nr, aid_val
            return None

        for aid_first in (False, True):
            for apply_perm in (False, True):
                res = try_layout(aid_first, apply_perm)
                if res is not None:
                    return res

        raise ValueError("decoded next_row out of range")

    # ----------------- 行级 AID 兜底 -----------------
    def _row_aid(self, row: int) -> int:
        g = self.gdfa

        # 方法
        func = getattr(g, "get_row_aid", None)
        if callable(func):
            try:
                v = func(row)
                if isinstance(v, int) and v > 0:
                    return v
            except Exception:
                pass

        # 列表/数组
        for name in ("row_aids", "accept_ids", "aid_table"):
            arr = getattr(g, name, None)
            if arr is not None:
                try:
                    v = arr[row]
                    if isinstance(v, int) and v > 0:
                        return v
                except Exception:
                    pass

        # 字典
        for name in ("accepting_map", "accepting_ids", "row_to_aid"):
            mp = getattr(g, name, None)
            if isinstance(mp, dict):
                v = mp.get(row, 0)
                if isinstance(v, int) and v > 0:
                    return v

        # 只有接受布尔（无具体 id）
        func2 = getattr(g, "is_accepting", None)
        if callable(func2):
            try:
                if func2(row):
                    return 1
            except Exception:
                pass

        for name in ("accepting_rows", "accept_rows"):
            s = getattr(g, name, None)
            if s is not None:
                try:
                    if row in s:
                        return 1
                except Exception:
                    pass

        return 0

    # ----------------- 主循环 -----------------
    def run(self, data: bytes):
        hits: List[int] = []
        row = self.gdfa.start_row
        for b in data:
            cols = self.row_alph.get_cols(row, b)  # 候选集合（旧工件退化为 [单值]）
            self._ensure_row_cached(row)

            next_row = None
            last_err: Optional[Exception] = None
            for col in cols:
                try:
                    gk = self._choose_one(row, col)
                    seed = self._derive_seed(gk, row, col)
                    pad = self._prg(seed, self.gdfa.cell_bytes)
                    ct = self._get_cell_bytes(row, col)
                    plain = bytes(a ^ p for a, p in zip(ct, pad))
                    nr, aid = self._decode_cell_plain(plain)
                    next_row = nr

                    # 命中判定：cell AID 优先；没有则行级 AID 兜底
                    if not aid:
                        aid = self._row_aid(next_row)
                    if aid:
                        hits.append(aid)

                    break  # 成功，跳出候选循环
                except Exception as e:
                    last_err = e
                    continue

            if next_row is None:
                raise ValueError(f"no valid column among {cols} at row={row} byte={b} ({last_err})")
            row = next_row

        return hits