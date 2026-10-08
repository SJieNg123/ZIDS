"""Typed EasyList network rules. Diagnostics and sources stay server-private."""
from collections import Counter
from dataclasses import dataclass, asdict
import hashlib
import ipaddress
import re

from .context import RESOURCE_TYPES, REQUEST_TYPES, RequestContext, hostname, third_party, is_ip_address
from .contracts import ProtocolError
from .dfa import NOMATCH, BLOCK, ALLOW

PROFILE = 'abp-core-0.11.1-network-v1'
SPECIAL = ('genericblock','elemhide','generichide')
OPTIONS = re.compile(r'\$(~?[\w-]+(?:=[^,]*)?(?:,~?[\w-]+(?:=[^,]*)?)*)$', re.ASCII)
OUTSIDE = {'csp','rewrite','header','addheader','removeparam','redirect','replace'}
ALIASES = {'background':'image','xbl':'other','dtd':'other'}
SEPARATOR = r'[\x00-\x24\x26-\x2c\x2f\x3a-\x40\x5b-\x5e\x60\x7b-\x7f]'


@dataclass(frozen=True)
class Rule:
    rule_id: str
    source: str
    line: int
    raw: str
    text: str
    pattern: str
    action: int
    types: tuple
    domains: tuple
    third_party: object
    match_case: bool
    has_domain_includes: bool

    @property
    def generic(self):
        return not self.has_domain_includes

    def domain_active(self, domain):
        if is_ip_address(domain):
            return dict(self.domains).get(domain,self.generic)
        for suffix, include in sorted(self.domains, key=lambda item: len(item[0]), reverse=True):
            if domain == suffix or domain.endswith('.'+suffix):
                return include
        return self.generic

    @property
    def regex_source(self):
        p = self.pattern if self.match_case else self.pattern.lower()
        if len(p) >= 2 and p[0] == p[-1] == '/':
            return p[1:-1]
        p = re.sub(r'\*+', '*', p).strip('*')
        if p.endswith('^|'):
            p = p[:-1]
        prefix, suffix = '', ''
        if p.startswith('||'):
            prefix, p = r'^[\w-]+:/+(?:[^/]+\.)?', p[2:]
        elif p.startswith('|'):
            prefix, p = '^', p[1:]
        if p.endswith('|'):
            suffix, p = '$', p[:-1]
        body = ''.join('.*' if c == '*' else '(?:'+SEPARATOR+'|$)' if c == '^'
                       else re.escape(c) for c in p)
        return prefix+body+suffix


def parse_line(raw, source, line):
    text = raw.strip()
    identity = hashlib.sha256((source+'\x00'+str(line)+'\x00'+raw).encode()).hexdigest()[:24]
    record = {'rule_id':identity,'source':source,'line':line,'raw':raw,'status':'metadata','reason':''}
    if not text or text.startswith(('!','[')):
        return None, record
    if re.search(r'#(?:[@?$]|@\?|@\$)?#', text):
        record.update(status='out_of_scope', reason='cosmetic or scriptlet rule')
        return None, record
    text = re.sub(r'\s+', '', text)
    action = ALLOW if text.startswith('@@') else BLOCK
    body = text[2:] if action == ALLOW else text
    match = OPTIONS.search(body)
    pattern = body[:match.start()] if match else body
    options = match[1].split(',') if match else []
    types, domains, party, case, had_include = None, {}, None, False, False
    try:
        for option in options:
            name, equal, value = option.partition('=')
            negative = name.startswith('~')
            name = ALIASES.get(name.lstrip('~').lower(), name.lstrip('~').lower())
            if name in OUTSIDE:
                record.update(status='out_of_scope', reason='browser action or response condition: '+name)
                return None, record
            if name in REQUEST_TYPES+SPECIAL:
                if equal:
                    raise ValueError('type option cannot have a value')
                if types is None:
                    types = set(RESOURCE_TYPES) if negative else set()
                types.discard(name) if negative else types.add(name)
            elif name in ('third-party','match-case'):
                if equal:
                    raise ValueError('boolean option cannot have a value')
                if name == 'third-party':
                    party = not negative
                else:
                    case = not negative
            elif name == 'domain' and equal and value and not negative:
                for item in value.lower().split('|'):
                    domain = item[1:] if item.startswith('~') else item
                    if domain.startswith('[') and domain.endswith(']'):
                        ipaddress.IPv6Address(domain[1:-1])
                    elif not domain or not re.fullmatch(r'[a-z0-9_.-]+', domain):
                        raise ValueError('invalid domain option')
                    domains[domain] = not item.startswith('~')
                    had_include |= not item.startswith('~')
            else:
                record.update(status='unsupported', reason='unknown option: '+name)
                return None, record
        types = set(RESOURCE_TYPES) if types is None else types
        network_types = types.intersection(REQUEST_TYPES+('genericblock',))
        if not network_types:
            record.update(status='out_of_scope', reason='only cosmetic allowing flags or empty type mask')
            return None, record
        minimum = 4 + (2 if pattern.startswith('||') else 1 if pattern.startswith('|') else 0)
        if not domains and len(pattern) < minimum and '*' not in pattern:
            raise ValueError('pattern below pinned reference minimum length')
        if not pattern.isascii():
            record.update(status='unsupported', reason='non-ASCII rule pattern')
            return None, record
        rule = Rule(identity,source,line,raw,text,pattern,action,tuple(sorted(network_types)),
                    tuple(domains.items()),party,case,had_include)
        re.compile(rule.regex_source, re.ASCII)
    except (ValueError, re.error) as exc:
        record.update(status='invalid', reason=str(exc))
        return None, record
    record.update(status='supported')
    return rule, record


def parse_sources(sources, *, require_coverage=True):
    rules, records = [], []
    for source, text in sources:
        for line, raw in enumerate(text.splitlines(), 1):
            rule, record = parse_line(raw, source, line)
            records.append(record)
            if rule is not None:
                rules.append(rule)
    coverage = {'profile':PROFILE, 'counts':dict(Counter(r['status'] for r in records)), 'records':records}
    if require_coverage and any(r['status'] in ('unsupported','invalid') for r in records):
        raise CoverageError(coverage)
    return rules, coverage


class CoverageError(ProtocolError):
    def __init__(self, coverage):
        super().__init__('EasyList profile coverage failed')
        self.coverage = coverage


def plain_match(rules, context: RequestContext):
    """Trusted diagnostic matcher only, never a client protocol fallback."""
    allow, generic_block, specific_block, generic_disabled = False, False, False, False
    for rule in rules:
        regex = re.compile(rule.regex_source, re.ASCII)
        for kind, _, url, document in context.frames():
            domain = hostname(document).rstrip('.')
            if not rule.domain_active(domain):
                continue
            if rule.third_party is not None and rule.third_party != third_party(url, document):
                continue
            if not regex.search(url if rule.match_case else url.lower()):
                continue
            if kind == 1 and context.resource_type in rule.types:
                if rule.action == ALLOW:
                    allow = True
                elif rule.generic:
                    generic_block = True
                else:
                    specific_block = True
            elif kind == 2 and rule.action == ALLOW:
                if 'document' in rule.types:
                    allow = True
                if 'genericblock' in rule.types:
                    generic_disabled = True
    return ALLOW if allow else BLOCK if specific_block or (generic_block and not generic_disabled) else NOMATCH
