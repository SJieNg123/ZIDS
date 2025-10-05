# src/client/online/engine.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Tuple, Protocol, Iterable, List, Optional
import importlib
from pathlib import Path
import re
from src.client.io.gdfa_loader import GDFAImage
from src.client.io.row_alph_loader import RowAlphabetMap, load_row_alph
from src.common.odfa.seed_rules import seed_from_gk, i2osp, PRG_LABEL_CELL
from src.common.crypto.prg import prg
from src.common.urlnorm import canonicalize  # 舊管線入口用
from src.client.io.gdfa_loader import load_gdfa as _load_gdfa  # 避免與區域變數名衝突
from src.client.io.row_alph_loader import load_row_alph as _load_row_alph

class _OTRowChooser:
    """
    极简 OT chooser：用 token_source 批量把一行的 GK 拉到本地缓存，
    暴露 choose_one(row, col) / ensure_row_payload_cached(row) 给引擎用。
    """
    def __init__(self, token_source, session_id: str, row_alph, k_bytes: int):
        self.ts = token_source
        self.sid = session_id
        self.row_alph = row_alph
        self.k_bytes = int(k_bytes)
        self._cache = {}  # (row, col) -> gk(bytes)

    def ensure_row_payload_cached(self, row: int) -> None:
        m = self.row_alph.num_cols(row)
        need = [c for c in range(m) if (row, c) not in self._cache]
        if not need:
            return
        gks = self.ts.get_gks(self.sid, row=row, choices=need, k_bytes=self.k_bytes)
        if len(gks) != len(need):
            raise RuntimeError("token source returned mismatched GK count")
        for c, gk in zip(need, gks):
            self._cache[(row, c)] = gk

    def choose_one(self, row: int, col: int) -> bytes:
        if (row, col) not in self._cache:
            self.ensure_row_payload_cached(row)
        return self._cache[(row, col)]

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
        self._pad_mode: str | None = None  # "rowcol" or "gkonly"        
        self._gk_row_index_mode: str | None = None   # "per" or "logical"

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
        """
        解一個 cell，支援：
        - pad 規則： "rowcol"（seed_from_gk(GK,row,col)）或 "gkonly"（PRG(GK)）
        - GK 行序： "per"（PER/new_row）或 "logical"（old_state = inv_permute(new_row)）
        首次探測成功後鎖定；若鎖定組合在後續某步失敗，會「自救」改試另一組，並更新鎖定。
        """
        ct = self.gdfa.get_cell_cipher(row, col)
        n  = self.gdfa.cell_bytes

        def _fetch_gk(row_now: int, col_now: int, gkmode: str) -> bytes:
            if gkmode == "per":
                return self._get_gk(row_now, col_now)
            elif gkmode == "logical":
                old_state = self.gdfa.inv_permute(row_now)  # 透過 GDFA 的逆置換拿 old_state
                if hasattr(self.chooser, "ensure_row_payload_cached"):
                    self.chooser.ensure_row_payload_cached(old_state)  # type: ignore[attr-defined]
                if hasattr(self.chooser, "choose_one"):
                    return self.chooser.choose_one(old_state, col_now)  # type: ignore[attr-defined]
                elif hasattr(self.chooser, "acquire_gk"):
                    m = self.row_alph.num_cols(row_now)
                    aad = self._aad_for_row(old_state)
                    return self.chooser.acquire_gk(row_id=old_state, m=m, col=col_now, aad=aad)  # type: ignore[attr-defined]
                raise RuntimeError("OT chooser does not provide a supported API")
            raise RuntimeError(f"unknown gk_row_index_mode: {gkmode}")

        def _try_once(pmode: str, gkmode: str) -> tuple[int, int]:
            gk = _fetch_gk(row, col, gkmode)
            if pmode == "rowcol":
                seed = self._derive_seed(gk, row, col)
                pad  = self._prg(seed, n)
            elif pmode == "gkonly":
                pad  = self._prg(gk, n)
            else:
                raise RuntimeError(f"unknown pad mode: {pmode}")
            plain = bytes(a ^ b for a, b in zip(ct, pad))
            return self._decode_cell_plain(plain)

                # 若已鎖定模式（init_for_cli 設定），就只用該組合，失敗直接報錯，不再 fallback
        if self._pad_mode and self._gk_row_index_mode:
            nr, aid = _try_once(self._pad_mode, self._gk_row_index_mode)
            return nr, aid

        # 否則才進入探測：先 rowcol/per，再 gkonly/logical
        pad_order = ("rowcol", "gkonly")
        gk_order  = ("per", "logical")
        last_err: Exception | None = None
        for pmode in pad_order:
            for gkmode in gk_order:
                try:
                    nr, aid = _try_once(pmode, gkmode)
                    # 一旦成功，鎖定下來（後續請求就固定）
                    self._pad_mode = pmode
                    self._gk_row_index_mode = gkmode
                    print(f"[engine] pad mode selected: {pmode}", flush=True)
                    print(f"[engine] GK row index mode: {gkmode}", flush=True)
                    return nr, aid
                except Exception as e:
                    last_err = e
                    continue

        raise ValueError(
            f"cell decrypt failed at row={row} col={col} "
            f"(pad_order={pad_order}, gk_order={gk_order}; last={last_err})"
        )

    # ----- 執行（舊 URL 正規化入口；保留相容） -----
    def run(self, data: bytes) -> List[int]:
        data = canonicalize(data)
        return self._run_bytes(data)

    # ----- 執行（ABP 已正規化 payload；不要再 canonicalize） -----
    def run_abp_payload(self, payload: str | bytes) -> List[int]:
        data = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        return self._run_bytes(data)

    def _run_bytes(self, data: bytes) -> List[int]:
        hits: List[int] = []
        row = self.gdfa.start_row

        for b in data:
            row_for_alph = self.gdfa.inv_permute(row)   # PER/new_row -> 邏輯 old_state
            cols: Iterable[int] = self.row_alph.get_cols(row_for_alph, b)
            if isinstance(cols, int):
                cols = [cols]

            next_row: Optional[int] = None
            last_err: Optional[Exception] = None

            for col in cols:
                try:
                    nr, aid_cell = self._open_cell(row, col)
                    row = nr  # 遷移

                    # 命中：先 row-level，再 cell-level（row 優先保證和離線聚合一致）
                    aid_row = self.gdfa.get_row_aid(row) if hasattr(self.gdfa, "get_row_aid") else 0
                    if aid_row > 0: hits.append(aid_row)
                    elif aid_cell > 0: hits.append(aid_cell)

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
    CLI 初始化（给 tools/run_dfa_with_abp.py 的 --engine-init 使用）。

    支持两种路径：
      A) regex 后备： cfg = {"easylist": "..."}
      B) 真引擎（GDFA + RowAlphabet + 真 OT 或本地 GK）：见下
    """
    # A) regex 后备
    if "easylist" in cfg:
        _compile_regex_from_easylist(str(cfg["easylist"]))
        return

    # B) 真引擎路径
    gdfa_path = _require_path(cfg, "gdfa")
    row_path  = _require_path(cfg, "rowalph")
    sid       = cfg.get("session_id", "cli")

    # 可选：构造 token source（HTTP）
    token_source = None
    ts_spec = cfg.get("token_source_cls")
    if ts_spec:
        mod_name, cls_name = ts_spec.split(":")
        mod = importlib.import_module(mod_name)
        TS  = getattr(mod, cls_name)
        ts_kwargs = cfg.get("token_source_kwargs", {}) or {}
        token_source = TS(**ts_kwargs)

    # 加载工件
    gdfa = _load_gdfa(gdfa_path)
    row_alph = _load_row_alph(row_path)

    # k_bytes 优先取 cfg.k_bytes；否则取 chooser_kwargs.gk_bytes；最后默认 16
    ckwargs = dict(cfg.get("chooser_kwargs", {}) or {})
    k_bytes = int(cfg.get("k_bytes", ckwargs.get("gk_bytes", 16)))

    # 若 token_source 可启动会话（/ot/start），先启动
    if token_source is not None and hasattr(token_source, "start"):
        token_source.start(sid, k_bytes, 128)

    chooser = None
    chooser_cls_spec = cfg.get("chooser_cls")

    if chooser_cls_spec:
        # 如果用户给了 chooser_cls，则先检查它是否接受 token_source
        mod_name, cls_name = chooser_cls_spec.split(":")
        mod = importlib.import_module(mod_name)
        Chooser = getattr(mod, cls_name)

        import inspect
        params = inspect.signature(Chooser.__init__).parameters
        accepts_token = "token_source" in params

        if token_source is not None and not accepts_token:
            # 关键信号：想走真 OT，但该 chooser 不支持 token_source
            # ——> 直接使用 _OTRowChooser，避免去实例化 MasterChooser 触发 ValueError
            chooser = _OTRowChooser(token_source, sid, row_alph, k_bytes)
        else:
            # 能接受 token_source 的话就注入；否则按原 kwargs
            ckwargs2 = dict(ckwargs)
            if token_source is not None and accepts_token:
                ckwargs2["token_source"] = token_source

            # 如果实例化失败且我们有 token_source，就 fallback 到包装器
            try:
                chooser = Chooser(**ckwargs2)
            except Exception:
                if token_source is not None:
                    chooser = _OTRowChooser(token_source, sid, row_alph, k_bytes)
                else:
                    raise
    else:
        # 没有 chooser_cls，但有 token_source：直接用包装器
        if token_source is not None:
            chooser = _OTRowChooser(token_source, sid, row_alph, k_bytes)

    if chooser is None:
        raise RuntimeError("No usable chooser: provide chooser_cls, or token_source_cls for OT-backed chooser.")

    eng = ZIDSEngine(gdfa, row_alph, chooser, EngineConfig(session_id=sid, k_bytes=k_bytes))

    # 可锁定 pad/GK 行序；否则引擎会自动探测
    if "pad_mode" in cfg:
        eng._pad_mode = str(cfg["pad_mode"])
    if "gk_index" in cfg:
        eng._gk_row_index_mode = str(cfg["gk_index"])

    set_engine(eng)
    ra = getattr(gdfa, "row_aids", None)
    nz = sum(1 for a in (ra or []) if a > 0)
    print(f"[engine] row_aids: {'yes' if ra else 'no'}; nonzero={nz}", flush=True)
    print(f"[engine] init ok: k_bytes={eng.cfg.k_bytes}, chooser={chooser.__class__.__name__}", flush=True)

def _require_path(cfg: dict, key: str) -> str:
    p = cfg.get(key)
    if not p:
        raise RuntimeError(f"init_for_cli: missing '{key}'")
    p = str(p)
    if not Path(p).exists():
        raise FileNotFoundError(f"init_for_cli: path '{p}' does not exist")
    return p

# === regex 後備引擎（給 init_for_cli({'easylist': ...}) 用）=====================
from typing import Pattern

_REGEX_COMPILED: list[tuple[Pattern[str], int]] = []
_REGEX_EASYLIST: str | None = None

def _compile_regex_from_easylist(easylist_path: str) -> None:
    """
    讀 EasyList -> RuleSpec[] -> 編譯成 regex 清單。
    rid = 載入序（與 export_id_to_action 的順序一致）。
    """
    # 避免循環 import，延遲載入
    from src.server.io import rule_loader as _rl  # type: ignore
    # 兼容不同專案的命名：LoaderConfig / LoadRulesConfig
    LoaderCfg = getattr(_rl, "LoaderConfig", None) or getattr(_rl, "LoadRulesConfig", None)
    if LoaderCfg is None:
        raise RuntimeError("rule_loader.LoaderConfig / LoadRulesConfig not found")
    specs = _rl.load_rules([easylist_path], LoaderCfg())

    out: list[tuple[Pattern[str], int]] = []
    for i, s in enumerate(specs):
        pat = getattr(s, "pattern")
        flags = 0
        if getattr(s, "ignore_case", False):
            flags |= re.IGNORECASE
        if getattr(s, "dotall", False):
            flags |= re.DOTALL
        try:
            rx = re.compile(pat, flags)
        except re.error as e:
            # 跟 smoke 一樣：壞規則跳過不終止
            print(f"[regex][skip] {getattr(s,'label',f'rule#{i}')}: {e}\npattern={pat}", flush=True)
            continue
        out.append((rx, i))
    global _REGEX_COMPILED, _REGEX_EASYLIST
    _REGEX_COMPILED = out
    _REGEX_EASYLIST = easylist_path
    print(f"[regex] compiled {len(out)} rules from {easylist_path}", flush=True)

def _regex_eval_rule_ids(payload: str | bytes) -> list[int]:
    if not _REGEX_COMPILED:
        raise RuntimeError("regex backend not initialized; call init_for_cli({'easylist': ...}) first")
    s = payload if isinstance(payload, str) else payload.decode("utf-8", errors="ignore")
    hits: list[int] = []
    for rx, rid in _REGEX_COMPILED:
        if rx.search(s):
            hits.append(rid)
    return hits

# 可選：把頂層 eval_rule_ids 換成這版，ENGINE 未初始化時自動走 regex 後備
def eval_rule_ids(payload: str | bytes):
    if ENGINE is not None:
        return ENGINE.run_abp_payload(payload)
    if _REGEX_COMPILED:
        return _regex_eval_rule_ids(payload)
    raise RuntimeError("Neither ENGINE initialized nor regex backend compiled; call init_for_cli(...) first.")