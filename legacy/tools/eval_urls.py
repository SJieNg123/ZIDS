# -*- coding: utf-8 -*-
import os, sys, json
from src.client.io.gdfa_loader import load_gdfa
from src.client.io.row_alph_loader import RowAlphabetMap
from src.client.online.engine import ZIDSEngine, EngineConfig
from src.client.online.ot_client import LocalTrivialOTChooser
from src.server.online.handler import ZIDSServerApp, ServerConfig
from src.server.online.ot_response_builder import RowAlphMeta

def canonicalize(u: str) -> bytes:
    # EasyList MVP：统一小写，非 ASCII 丢弃
    return u.strip().lower().encode("ascii", errors="ignore")

def main(art_dir: str, url_file: str, use_master: bool = False, master_hex: str = ""):
    manifest_path = os.path.join(art_dir, "manifest.json")
    mani = json.load(open(manifest_path, "rb"))
    seed_k_bytes = int(mani["crypto_params"]["k"]) // 8
    gk_bytes = int(mani.get("gk_bytes", 32))

    gdfa = load_gdfa(os.path.join(art_dir, "gdfa.gdfa"))
    row_alph = RowAlphabetMap.load(art_dir)
    meta = RowAlphMeta.load(os.path.join(art_dir, "row_alph.json"))

    if use_master:
        cfg = ServerConfig(manifest_path=manifest_path, master_key=bytes.fromhex(master_hex), gk_bytes=gk_bytes)
    else:
        cfg = ServerConfig(manifest_path=manifest_path, gk_files_dir=art_dir, gk_bytes=gk_bytes)
    app = ZIDSServerApp(meta, cfg)
    sid = app.init_session()["session_id"]

    engine = ZIDSEngine(
        gdfa, row_alph,
        LocalTrivialOTChooser(server=app, session_id=sid),
        EngineConfig(session_id=sid, enable_gk_cache=True, k_bytes=seed_k_bytes)
    )

    with open(url_file, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            data = canonicalize(line)
            hits = engine.run(data)
            print(f"{i}\t{'HIT' if hits else 'NOHIT'}\t{line.strip()}")

if __name__ == "__main__":
    art = sys.argv[1] if len(sys.argv) > 1 else "dist/easylist_art"
    urls = sys.argv[2] if len(sys.argv) > 2 else "urls.txt"
    main(art, urls)