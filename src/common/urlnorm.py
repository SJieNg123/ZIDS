# src/common/urlnorm.py
from __future__ import annotations
import re
import idna
from urllib.parse import urlsplit

_HEX = b'0123456789ABCDEF'
_pct = re.compile(rb'%([0-9a-fA-F]{2})')

def _pct_upper(m: re.Match[bytes]) -> bytes:
    h = m.group(1).upper()
    return b'%' + h

def _norm_percent(bs: bytes) -> bytes:
    # 不解码，只把 %xx 统一为大写十六进制
    return _pct.sub(_pct_upper, bs)

def _norm_host(raw: str) -> str:
    # 去端口，小写，IDNA
    host = raw.strip().split(':', 1)[0].lower()
    if not host:
        return ''
    try:
        # 逐 label 做 IDNA，可兼容混合大小写
        labels = [idna.encode(lbl).decode('ascii') for lbl in host.split('.')]
        return '.'.join(labels)
    except Exception:
        return host

def canonicalize(inp: bytes | str) -> bytes:
    """
    输入：HTTP 请求报文 或 URL（bytes/str）
    输出：b'host/path?query'（若无 path，用 '/'；若无 host，返回原始 bytes）
    """
    if isinstance(inp, str):
        data = inp.encode('utf-8', errors='ignore')
    else:
        data = inp

    # 1) 尝试当作 HTTP 请求
    try:
        head, _, _ = data.partition(b'\r\n\r\n')
        if head:
            lines = head.split(b'\r\n')
            # 请求行: GET /path?x HTTP/1.1
            if lines and b' ' in lines[0]:
                parts = lines[0].split(b' ')
                if len(parts) >= 2:
                    path = parts[1]
                else:
                    path = b'/'
            else:
                path = b'/'
            host = b''
            for ln in lines[1:]:
                if ln.lower().startswith(b'host:'):
                    host = ln.split(b':', 1)[1].strip()
                    break
            if host:
                h = _norm_host(host.decode('latin1', errors='ignore')).encode('ascii')
                p = path if path.startswith(b'/') else b'/' + path
                p = _norm_percent(p)
                return h + p
    except Exception:
        pass

    # 2) 当作 URL
    try:
        url = data.decode('utf-8', errors='ignore')
        sp = urlsplit(url)
        if sp.netloc:
            h = _norm_host(sp.netloc).encode('ascii')
            path = sp.path.encode('utf-8', errors='ignore') or b'/'
            if not path.startswith(b'/'):
                path = b'/' + path
            q = (b'?' + sp.query.encode('utf-8')) if sp.query else b''
            p = _norm_percent(path + q)
            return h + p
    except Exception:
        pass

    # 3) 否则原样返回（让规则自己兜底）
    return data
