# src/client/online/token_http.py
from __future__ import annotations
import requests, json
from typing import Optional

class _OTRowChooser:
    """
    Minimal OT chooser over HTTP endpoints.

    Expected server API:
      POST {base}/ot/start    body: {"sid": "<session_id>"}        -> 200 {"ok": true}
      POST {base}/ot/choose   body: {"row":int,"col":int,"k_bytes":int,"master_hex":str,"sid":str}
                              -> 200 {"gk_hex": "<hex bytes>"}

    Notes
    -----
    - This class is intentionally tiny; the client (engine) will set eng.cfg.k_bytes.
      If present, we also accept chooser_kwargs.k_bytes (optional).
    - For benchmarking, we keep simple application-layer counters:
        tx_bytes: approximate outgoing JSON body size (no HTTP headers/TLS)
        rx_bytes: response body size in bytes
        rpc_calls: number of HTTP calls made
    """

    def __init__(
        self,
        url_base: str,
        master_hex: str,
        session_id: str = "cli",
        timeout: float = 2.0,
        k_bytes: Optional[int] = None,
    ):
        if not url_base.startswith("http://") and not url_base.startswith("https://"):
            url_base = "http://" + url_base
        if url_base.endswith("/"):
            url_base = url_base[:-1]
        self.base = url_base
        self.master_hex = master_hex
        self.session_id = session_id
        self.timeout = float(timeout)

        # engine.init_for_cli 會按需要覆寫；這裡給個預設
        self.k_bytes = int(k_bytes) if k_bytes is not None else 32

        # bench