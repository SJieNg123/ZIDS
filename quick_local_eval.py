# -*- coding: utf-8 -*-
import os, json
from src.client.io.gdfa_loader import load_gdfa
from src.client.io.row_alph_loader import RowAlphabetMap
from src.client.online.engine import ZIDSEngine, EngineConfig
from src.client.online.ot_client import LocalTrivialOTChooser
from src.server.online.handler import ZIDSServerApp, ServerConfig
from src.server.online.ot_response_builder import RowAlphMeta

from src.server.online.ot_response_builder import RowAlphMeta
from src.common.odfa.seed_rules import seed_from_gk, PRG_LABEL_CELL
from src.common.crypto.prg import prg

def print_accept_stats(gdfa):
    num_rows = getattr(gdfa, "num_states", None) or getattr(gdfa, "num_rows", None)
    if not isinstance(num_rows, int):
        print("!!! cannot determine num_rows"); return
    total_accept = 0
    names_hit = []

    # 方法
    f = getattr(gdfa, "get_row_aid", None)
    if callable(f):
        cnt = sum(1 for r in range(num_rows) if isinstance(f(r), int) and f(r) > 0)
        print(f"[accept] get_row_aid(): {cnt}")
        total_accept = max(total_accept, cnt); names_hit.append("get_row_aid")

    # 列表/数组
    for name in ("row_aids", "accept_ids", "aid_table"):
        arr = getattr(gdfa, name, None)
        if arr is not None:
            try:
                cnt = sum(1 for r in range(num_rows) if isinstance(arr[r], int) and arr[r] > 0)
                print(f"[accept] {name}: {cnt}")
                total_accept = max(total_accept, cnt); names_hit.append(name)
            except Exception:
                pass

    # 字典
    for name in ("accepting_map", "accepting_ids", "row_to_aid"):
        mp = getattr(gdfa, name, None)
        if isinstance(mp, dict):
            cnt = sum(1 for r in range(num_rows) if isinstance(mp.get(r, 0), int) and mp.get(r, 0) > 0)
            print(f"[accept] {name}: {cnt}")
            total_accept = max(total_accept, cnt); names_hit.append(name)

    # 布尔
    f2 = getattr(gdfa, "is_accepting", None)
    if callable(f2):
        cnt = sum(1 for r in range(num_rows) if f2(r))
        print(f"[accept] is_accepting(): {cnt}")
        total_accept = max(total_accept, cnt); names_hit.append("is_accepting()")
    for name in ("accepting_rows", "accept_rows"):
        s = getattr(gdfa, name, None)
        if s is not None:
            try:
                cnt = sum(1 for r in range(num_rows) if r in s)
                print(f"[accept] {name}: {cnt}")
                total_accept = max(total_accept, cnt); names_hit.append(name)
            except Exception:
                pass

    if total_accept == 0:
        print("!!! NO accepting/AID information found in GDFA artifacts")
    else:
        print(f"==> accepting present via: {', '.join(names_hit)}; max_count={total_accept}")

ART = "dist/zids_easy"
TESTS = "dist/urltests/tests.json"

def diag_probe_once(engine, app, meta, gdfa, row_alph, session_id, sample_bytes):
    row0 = gdfa.start_row
    b0   = sample_bytes[0]

    # get_cols() 一定返回 list[int]（<= cmax）
    cols0 = row_alph.get_cols(row0, b0)
    m     = row_alph.num_cols(row0)
    assert isinstance(cols0, list) and len(cols0) > 0, f"no candidate cols at row={row0} b0={b0}"
    assert all(isinstance(c, int) for c in cols0), f"non-int col in {cols0}"
    assert all(0 <= c < m for c in cols0), f"bad col mapping row={row0} b0={b0} cols={cols0} (m={m})"

    # 先用第一个候选做对齐检查（不在这里枚举所有候选；真正的多候选尝试在 engine.run 里做）
    col0 = cols0[0]

    # 从服务端拿这一行的整行载荷（aad, payload）
    aad, payload = app.ot_row_payload(session_id, row0)
    print("row0=", row0, "m=", m, "payload_len=", len(payload))
    print("payload_len_ok?", len(payload) == m)

    gk = payload[col0]
    print("gk_len=", len(gk), "expect_gk_bytes=", GK_BYTES, "gk_len_ok?", len(gk) == GK_BYTES)

    seed_cli = seed_from_gk(gk, row0, col0, SEED_K_BYTES)
    seed_srv = app.sessions.derive_seed(session_id, row0, col0, SEED_K_BYTES)
    print("seed_equal?", seed_cli == seed_srv)

    pad = prg(seed_cli, PRG_LABEL_CELL, gdfa.cell_bytes)
    print("pad_len_ok?", len(pad) == gdfa.cell_bytes, "cell_bytes=", gdfa.cell_bytes)

def find_gdfa_path(art_dir: str) -> str:
    cont = os.path.join(art_dir, "gdfa.gdfa")
    if os.path.exists(cont): return cont
    if os.path.exists(os.path.join(art_dir, "rows.bin")) and (
        os.path.exists(os.path.join(art_dir, "header.json")) or
        os.path.exists(os.path.join(art_dir, "header.json.gz"))
    ):
        return art_dir
    raise FileNotFoundError(f"Artifacts not found under {art_dir}")

# 单一真源（SSOT）
MANIFEST_PATH = os.path.join(ART, "manifest.json")
manifest = json.load(open(MANIFEST_PATH, "rb"))
SEED_K_BYTES = int(manifest["crypto_params"]["k"]) // 8
GK_BYTES     = int(manifest.get("gk_bytes", 32))

# 载入工件
gdfa     = load_gdfa(find_gdfa_path(ART))
row_alph = RowAlphabetMap.load(ART)
meta     = RowAlphMeta.load(os.path.join(ART, "row_alph.json"))

# 服务端：默认用离线 GK 文件模式（别用 master，除非你确定离线是同一把 master）
app = ZIDSServerApp(
    meta,
    ServerConfig(manifest_path=MANIFEST_PATH, gk_files_dir=ART, gk_bytes=GK_BYTES)
)
sid = app.init_session()["session_id"]

# 客户端引擎
engine = ZIDSEngine(
    gdfa, row_alph,
    LocalTrivialOTChooser(server=app, session_id=sid, seed_k_bytes=SEED_K_BYTES),
    EngineConfig(session_id=sid, enable_gk_cache=True,
                 seed_k_bytes=SEED_K_BYTES)  # 或 k_bytes=SEED_K_BYTES（引擎已兼容）
)

# 评测
if os.path.exists(TESTS):
    items = json.load(open(TESTS, "rb"))
    base = os.path.dirname(os.path.abspath(TESTS))
    for it in items:
        for kind in ("positive_req", "negative_req"):
            rel = it[kind].replace("\\", "/")
            p = os.path.normpath(os.path.join(base, rel))
            with open(p, "rb") as fp:
                data = fp.read()
            
            # data 就是你准备送进 engine.run 的数据
            diag_probe_once(engine, app, meta, gdfa, row_alph, sid, data if len(data)>0 else b'G')

            hits = engine.run(data)
            print(kind, it["index"], "HITS" if hits else "nohit", hits)
else:
    data = b"GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"
    print(engine.run(data))