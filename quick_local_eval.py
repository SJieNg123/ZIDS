# quick_local_eval.py
import os, json
from src.client.io.gdfa_loader import load_gdfa
from src.client.io.row_alph_loader import RowAlphabetMap
from src.client.online.engine import ZIDSEngine, EngineConfig
from src.client.online.ot_client import LocalTrivialOTChooser
from src.server.online.handler import ZIDSServerApp, ServerConfig
from src.server.online.ot_response_builder import RowAlphMeta

ART = "dist/zids_easy"
TESTS = "dist/urltests/tests.json"
MASTER = bytes.fromhex("00112233445566778899aabbccddeeff")

gdfa = load_gdfa(os.path.join(ART, "gdfa.gdfa"))
row_alph = RowAlphabetMap.load(ART)
meta = RowAlphMeta.load(os.path.join(ART, "row_alph.json"))
app = ZIDSServerApp(meta, ServerConfig(master_key=MASTER, k_bytes=32))
sid = app.sessions.create_session().session_id
engine = ZIDSEngine(gdfa, row_alph, LocalTrivialOTChooser(app, sid), EngineConfig(session_id=sid))

with open(TESTS, "rb") as f:
    items = json.load(f)
base = os.path.dirname(TESTS)

for it in items:
    for kind in ("positive_req", "negative_req"):
        p = os.path.join(base, it[kind])
        data = open(p, "rb").read()
        hits = engine.run(data)
        print(kind, it["index"], "HITS" if hits else "nohit", hits)
