# src/client/online/engine.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple, Protocol, Iterable, List, Optional
import importlib
from pathlib import Path

from src.client.io.gdfa_loader import GDFAImage
from src.client.io.row_alph_loader import RowAlphabetMap, load_row_alph
from src.common.odfa.seed_rules import seed_from_gk, i2osp, PRG_LABEL_CELL
from src.common.crypto.prg import prg
from src.common.urlnorm import canonicalize  # 舊管線入口用

# ---------------- OT chooser 介面 ----------------
class OTChooser(Protocol):
    # 新式接口（推薦）
    def choose_one(self, row: int, col: int) -> bytes: ...
    def ensure_row_payload_cached(self, row: int) -> None: ...
    # 舊式接口（兼容）
    def acquire_gk(self, *, row_id: int, m: int, col: int, aad: bytes) -> bytes: ...

# ---------------- 引擎設定 ----------------
@dataclass
class EngineConfig:
    session_id: str
    enable_gk_cache: bool = True
    k_bytes: int = 16  # = manifest.crypto_params.k // 8

# ---------------- 主引擎 ----------------
class ZIDSEngine:
    """
    真引擎（GDFA + OT）：
      - 逐 byte：RowAlphabet 映射 → OT 取 GK → 派生 pad → XOR 解 cell → 取 next_row, aid
      - 命中判定：遷移到 next_row 後，先看 row_aid，再看 cell_aid
      - 回傳：命中的 AID 列表（AID 應對齊你的離線規則編號策略）
    """
    def __init__(self, gdfa: GDFAImage, row_alph: RowAlphabetMap, chooser: OTChooser, cfg: EngineConfig):
        if gdfa.num_states != row_alph.num_rows:
            raise ValueError(f"gdfa.num_states({gdfa.num_states}) != row_alph.num_rows({row_alph.num_rows})")
        self.gdfa = gdfa
        self.row_alph = row_alph
        self.chooser = chooser
        self.cfg = cfg
        self._gk_cache: Dict[Tuple[int, int], bytes] = {}

    # ----- GK/PRG -----
    def _aad_for_row(self, row_id: int) -> bytes:
        return (b"ZIDS|GK|sid=" + self.cfg.session_id.encode("ascii") +
                b"|row=" + i2osp(row_id, 4))

    def _derive_seed(self, gk: bytes, row: int, col: int) -> bytes:
        return seed_from_gk(gk, row, col, self.cfg.k_bytes)

    def _prg(self, seed: bytes, nbytes: int) -> bytes:
        return prg(seed, PRG_LABEL_CELL, nbytes)

    def _get_gk(self, row: int, col: int) -> bytes:
        if self.cfg.enable_gk_cache:
            key = (row, col)
            if key in self._gk_cache:
                return self._gk_cache[key]

        # 優先新式接口
        if hasattr(self.chooser, "ensure_row_payload_cached"):
            self.chooser.ensure_row_payload_cached(row)
        if hasattr(self.chooser, "choose_one"):
            gk = self.chooser.choose_one(row, col)  # type: ignore[attr-defined]
        elif hasattr(self.chooser, "acquire_gk"):
            m = self.row_alph.num_cols(row)
            gk = self.chooser.acquire_gk(row_id=row, m=m, col=col, aad=self._aad_for_row(row))  # type: ignore[attr-defined]
        else:
            raise RuntimeError("OT chooser does not provide choose_one()/acquire_gk()")

        if self.cfg.enable_gk_cache:
            self._gk_cache[(row, col)] = gk
        return gk

    # ----- 解 cell -----
    def _decode_cell_plain(self, plain: bytes) -> tuple[int, int]:
        """
        明文佈局（LE）：
          A 方案：[next_row(row_bits)][aid(aid_bits)][padding]
          若 next_row 超界，回退為：
          B 方案：[aid(aid_bits)][next_row(row_bits)][padding]
        """
        num_rows = self.gdfa.num_states
        row_bits = max(1, (num_rows - 1).bit_length())
        row_bytes = (row_bits + 7) // 8

        aid_bits = getattr(self.gdfa, "aid_bits", 0) or 0
        aid_bytes = (aid_bits + 7) // 8 if aid_bits > 0 else 0

        mask_row = (1 << row_bits) - 1
        mask_aid = (1 << aid_bits) - 1 if aid_bits > 0 else 0

        nr = int.from_bytes(plain[:row_bytes], "little") & mask_row
        aid = 0
        if aid_bits:
            aid = int.from_bytes(plain[row_bytes:row_bytes + aid_bytes], "little") & mask_aid
        if 0 <= nr < num_rows:
            return nr, aid

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

    # ----- 執行（舊 URL 正規化入口；保留相容） -----
    def run(self, data: bytes) -> List[int]:
        data = canonicalize(data)
        return self._run_bytes(data)

    # ----- 執行（ABP 已正規化 payload；不要再 canonicalize） -----
    def run_abp_payload(self, payload: str | bytes) -> List[int]:
        data = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        return self._run_bytes(data)

    # ----- 內部主迴圈 -----
    def _run_bytes(self, data: bytes) -> List[int]:
        hits: List[int] = []
        row = self.gdfa.start_row

        for b in data:
            cols: Iterable[int] = self.row_alph.get_cols(row, b)
            if isinstance(cols, int):
                cols = [cols]

            next_row: Optional[int] = None
            last_err: Optional[Exception] = None

            for col in cols:
                try:
                    nr, aid_cell = self._open_cell(row, col)
                    row = nr  # 遷移
                    # 命中：先 row_aid，再 cell_aid
                    aid_row = self.gdfa.get_row_aid(row) if hasattr(self.gdfa, "get_row_aid") else 0
                    if aid_row > 0:
                        hits.append(aid_row)
                    elif aid_cell > 0:
                        hits.append(aid_cell)
                    next_row = nr
                    break
                except Exception as e:
                    last_err = e
                    continue

            if next_row is None:
                raise ValueError(f"no valid column among {list(cols)} at row={row} byte={b} ({last_err})")

        return hits

# ---------------- 模組級入口（給 CLI/工具呼叫） ----------------
ENGINE: Optional[ZIDSEngine] = None  # 由 init_for_cli() 或服務啟動時注入

def set_engine(engine: ZIDSEngine) -> None:
    global ENGINE
    ENGINE = engine

def eval_rule_ids(payload: str | bytes):
    """
    CLI/工具統一入口：
      - 輸入：canonicalize_for_abp() 產出的 META+URL 串
      - 回傳：命中的 AID 列表（把 AID 當作 rule_id 使用）
    """
    if ENGINE is None:
        raise RuntimeError("ENGINE is not initialized. Call init_for_cli(...) or set_engine(...).")
    return ENGINE.run_abp_payload(payload)

# ---------------- CLI 初始化（只支援真引擎；不再提供 regex 後備） ----------------
def init_for_cli(cfg: dict) -> None:
    """
    需要：
      {
        "gdfa":    "path/to/gdfa.bin",
        "rowalph": "path/to/row_alph.bin",  # 同目錄要有 row_alph.json
        "session_id": "cli",
        "chooser_cls": "pkg.mod:ClassName",
        "chooser_kwargs": { ... }
      }
    """
    # 基本校驗
    gdfa_path = _require_path(cfg, "gdfa")
    row_path  = _require_path(cfg, "rowalph")
    sid       = str(cfg.get("session_id", "cli"))
    cls_spec  = cfg.get("chooser_cls")
    if not cls_spec:
        raise RuntimeError("init_for_cli: missing 'chooser_cls' (e.g., 'src.client.online.chooser_http:HttpChooser')")

    # 動態載入 chooser 類
    mod_name, cls_name = cls_spec.split(":")
    mod = importlib.import_module(mod_name)
    chooser_cls = getattr(mod, cls_name)
    chooser_kwargs = cfg.get("chooser_kwargs", {}) or {}
    chooser: OTChooser = chooser_cls(**chooser_kwargs)

    # 載入工件
    from src.client.io.gdfa_loader import load_gdfa  # 避免循環 import 放這裡
    gdfa = load_gdfa(gdfa_path)

    # RowAlphabet：允許給 .bin 或 目錄（我們用 load_row_alph 包起來）
    row_alph = load_row_alph(row_path)

    # 一些一致性 sanity check
    if gdfa.num_states != row_alph.num_rows:
        raise ValueError(f"inconsistent artifacts: gdfa.num_states={gdfa.num_states} vs row_alph.num_rows={row_alph.num_rows}")
    if getattr(gdfa, "alphabet_size", 256) != 256:
        raise ValueError("this client assumes 256-byte input alphabet; got gdfa.alphabet_size != 256")

    set_engine(ZIDSEngine(gdfa, row_alph, chooser, EngineConfig(session_id=sid)))

def _require_path(cfg: dict, key: str) -> str:
    p = cfg.get(key)
    if not p:
        raise RuntimeError(f"init_for_cli: missing '{key}'")
    p = str(p)
    if not Path(p).exists():
        raise FileNotFoundError(f"init_for_cli: path '{p}' does not exist")
    return p