"""Caller-supplied request context and an unambiguous byte alphabet encoding."""
from dataclasses import dataclass
from functools import lru_cache
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit, urlunsplit, quote

from .contracts import ProtocolError

RESOURCE_TYPES = ('other','script','image','stylesheet','object','subdocument','websocket',
                  'webrtc','ping','xmlhttprequest','media','font')
REQUEST_TYPES = RESOURCE_TYPES + ('popup','document')
TYPE_CODES = {name: 128+i for i, name in enumerate(REQUEST_TYPES)}
HEADER, REQUEST, DOCUMENT, EOS, URL_START, SEP = b'Z2', 1, 2, 3, 4, 0


def canonical_url(value):
    if type(value) is not str or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ProtocolError('URL must be nonempty and contain no control bytes')
    try:
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        if scheme not in ('http','https','ws','wss') or not parts.hostname:
            raise ValueError('absolute network URL required')
        if parts.username is not None or '\\' in value:
            raise ValueError('credentials and backslashes require caller normalization')
        host = parts.hostname.lower()
        if ':' in host:
            if '%' in host:
                raise ValueError('scoped IPv6 requires caller normalization')
            host = '['+ipaddress.IPv6Address(host).compressed+']'
        else:
            host = host.encode('idna').decode('ascii')
            if not re.fullmatch(r'[a-z0-9_.-]+', host) or '..' in host or host.startswith('.'):
                raise ValueError('invalid hostname')
        port = parts.port
        if port == (443 if scheme in ('https','wss') else 80):
            port = None
        authority = host + (':'+str(port) if port is not None else '')
        path = quote(parts.path or '/', safe="/%:@!$&'()*+,-._~=|")
        # A network input is serialized, not fetched. Do not discard query case.
        query = quote(parts.query, safe="/%?:@!$&'()*+,-._~=|")
        fragment = quote(parts.fragment, safe="/%?:@!$&'()*+,-._~=|")
        return urlunsplit((scheme, authority, path, query, fragment))
    except (ValueError, UnicodeError) as exc:
        raise ProtocolError('unsupported or invalid URL') from exc


def hostname(url):
    host = urlsplit(url).hostname or ''
    return '['+host+']' if ':' in host else host


def is_ip_address(host):
    """The pinned matcher identifies address-shaped, already serialized hosts."""
    return (host.startswith('[') and host.endswith(']')) or bool(re.fullmatch(r'\d+\.\d+\.\d+\.\d+',host,re.ASCII))


@lru_cache(maxsize=1)
def suffixes():
    return json.loads((Path(__file__).parent/'data/public_suffixes.json').read_text(encoding='utf8'))


def base_domain(host):
    parts = host.split('.')
    candidates = ['.'.join(parts[i:]) for i in range(len(parts))]
    for i, candidate in enumerate(candidates):
        offset = suffixes().get(candidate)
        if offset is not None:
            return candidates[max(0, i-offset)]
    return candidates[-2] if len(candidates) > 2 else host


def third_party(url, document_url):
    a, b = hostname(url).rstrip('.'), hostname(document_url).rstrip('.')
    if a == b:
        return False
    if not a or not b:
        return True
    if is_ip_address(a) or is_ip_address(b):
        return True
    return base_domain(a) != base_domain(b)


@dataclass(frozen=True)
class RequestContext:
    url: str
    resource_type: str
    document_url: str
    ancestors: tuple = ()

    def __post_init__(self):
        if type(self.resource_type) is not str or self.resource_type not in TYPE_CODES:
            raise ProtocolError('unknown resource type')
        if type(self.ancestors) not in (tuple, list) or len(self.ancestors) > 16:
            raise ProtocolError('invalid ancestor chain')
        object.__setattr__(self, 'url', canonical_url(self.url))
        object.__setattr__(self, 'document_url', canonical_url(self.document_url))
        object.__setattr__(self, 'ancestors', tuple(canonical_url(x) for x in self.ancestors))

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or not {'url','resource_type','document_url'} <= set(value):
            raise ProtocolError('URL, resource_type and document_url are required')
        if set(value)-{'url','resource_type','document_url','ancestors'}:
            raise ProtocolError('unknown request context field')
        return cls(**value)

    def frames(self):
        yield REQUEST, TYPE_CODES[self.resource_type], self.url, self.document_url
        chain = (self.document_url,)+self.ancestors
        for i, url in enumerate(chain):
            parent = chain[i+1] if i+1 < len(chain) else url
            yield DOCUMENT, TYPE_CODES['document'], url, parent

    def encode(self):
        result = bytearray(HEADER)
        for kind, type_code, url, document in self.frames():
            result.extend((kind, type_code, 16+int(third_party(url, document))))
            result.extend(hostname(document).rstrip('.').encode('ascii'))
            result.extend((SEP, URL_START))
            result.extend(url.encode('ascii'))
            result.append(SEP)
        result.append(EOS)
        return bytes(result)
