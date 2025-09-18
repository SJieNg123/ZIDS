# src/common/abp_canonicalize.py
from __future__ import annotations

import re
import urllib.parse
from typing import Tuple, Optional

# ====== 與 easylist_loader 對齊的哨兵 ======
SEP = "\x1f"       # <SEP>：ABP 的 ^（一個「分隔符」字元）
DOMSTART = "\x1e"  # <DOMSTART>：host 欄位開始
META_SEP = SEP     # META 與 URL 之間用同一個 SEP

# ====== 請求類型代碼（與 easylist_loader.TYPE_CODE 對齊） ======
TYPE_CODE = {
    "script": "S",
    "image": "I",
    "stylesheet": "C",
    "font": "F",
    "xmlhttprequest": "X",
    "xhr": "X",
    "media": "M",
    "subdocument": "D",
    "object": "O",
    "beacon": "B",
    "other": "O",
}
DEFAULT_TYPE_CHAR = "O"

_ALLOWED_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.%")
_IPV6_RE = re.compile(r"^\[?[0-9a-f:]+\]?$", re.IGNORECASE)

_COMMON_MULTI_TLDS = {
    "co.uk", "org.uk", "ac.uk",
    "com.au", "net.au", "org.au",
    "com.br", "com.cn", "com.tw", "net.tw", "org.tw", "edu.tw",
    "co.jp", "ne.jp", "or.jp",
}

def _etld1(host: str) -> str:
    host = host.strip(".")
    if not host or host.startswith("[") or _IPV6_RE.match(host) or host.replace(".", "").isdigit():
        return host.lower()
    try:
        import tldextract  # type: ignore
        ext = tldextract.extract(host)
        rd = ext.registered_domain or host
        return rd.lower()
    except Exception:
        pass
    try:
        from publicsuffix2 import get_sld  # type: ignore
        rd = get_sld(host)
        return (rd or host).lower()
    except Exception:
        pass
    labels = host.lower().split(".")
    if len(labels) <= 2:
        return host.lower()
    tail2 = ".".join(labels[-2:])
    tail3 = ".".join(labels[-3:])
    if tail2 in _COMMON_MULTI_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    if tail3 in _COMMON_MULTI_TLDS and len(labels) >= 4:
        return ".".join(labels[-4:])
    return tail2

def _idna_punycode(host: str) -> str:
    out = []
    for lbl in host.strip(".").split("."):
        if not lbl:
            continue
        try:
            out.append(lbl.encode("idna").decode("ascii").lower())
        except Exception:
            out.append(lbl.lower())
    return ".".join(out)

def _split_host_port(netloc: str) -> Tuple[str, Optional[int]]:
    if netloc.startswith("["):
        if "]" in netloc:
            host = netloc[1:netloc.index("]")]
            rest = netloc[netloc.index("]") + 1:]
            port = None
            if rest.startswith(":"):
                try:
                    port = int(rest[1:])
                except Exception:
                    port = None
            return host, port
        return netloc, None
    if ":" in netloc:
        h, p = netloc.rsplit(":", 1)
        try:
            return h, int(p)
        except Exception:
            return netloc, None
    return netloc, None

def _strip_default_port(scheme: str, port: Optional[int]) -> Optional[int]:
    if port is None:
        return None
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return None
    return port

def _to_sep_encoded(s: str) -> str:
    # 將非 [A-Za-z0-9-_.%] 的字元映為單一 SEP；不解碼 %xx
    return "".join(SEP if ch not in _ALLOWED_CHARS else ch for ch in s)

def _canon_host_and_url(req_url: str) -> Tuple[str, str]:
    u = urllib.parse.urlsplit(req_url)
    scheme = u.scheme.lower()
    host_raw, port = _split_host_port(u.netloc)
    port = _strip_default_port(scheme, port)

    host = _idna_punycode(host_raw.lower())
    if port is not None and not _IPV6_RE.match(host_raw):
        host = f"{host}:{port}"

    path = u.path or "/"
    path_q = f"{path}?{u.query}" if u.query else path
    return host, _to_sep_encoded(path_q)

def _type_char(req_type: str | None) -> str:
    if not req_type:
        return DEFAULT_TYPE_CHAR
    return TYPE_CODE.get(req_type.strip().lower(), DEFAULT_TYPE_CHAR)

def _party_char(req_host: str, doc_host: str) -> str:
    req_etld1 = _etld1(req_host)
    doc_etld1 = _etld1(doc_host)
    return "F" if (req_etld1 and doc_etld1 and req_etld1 == doc_etld1) else "T"

def canonicalize_for_abp(req_url: str, doc_url: str, req_type: str | None = None) -> str:
    """
    產生 DFA 輸入串：
      <TYPE><PARTY><docdomain><META_SEP><DOMSTART><host><SEP><path?query(SEP化)>
    - host/docdomain：小寫 + IDNA；去預設埠；不解碼 %xx
    - 路徑與查詢中非 [A-Za-z0-9-_.%] 的字元會變為 SEP
    """
    du = urllib.parse.urlsplit(doc_url)
    doc_host_raw, _ = _split_host_port(du.netloc)
    doc_host = _idna_punycode(doc_host_raw.lower())

    req_host, pathq_sep = _canon_host_and_url(req_url)

    meta = f"{_type_char(req_type)}{_party_char(req_host, doc_host)}{doc_host}{META_SEP}"
    urlp = f"{DOMSTART}{req_host}{SEP}{pathq_sep}"
    return meta + urlp