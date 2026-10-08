"""Deterministic per-rule candidate generation. Oracle supplies final labels."""
from dataclasses import asdict
from urllib.parse import urlsplit

from src.zids.context import RequestContext, REQUEST_TYPES
from src.zids.contracts import ProtocolError
from src.zids.dfa import ALLOW
from src.zids.easylist import plain_match


def candidates(rule):
    pattern = rule.pattern
    if pattern.startswith('/') and pattern.endswith('/'):
        return []
    body = pattern.strip('|').replace('^','/')
    values = []
    for replacement in ('','probe'):
        text = body.replace('*',replacement)
        if pattern.startswith('||'):
            values.extend(('https://'+text,'http://'+text))
        elif '://' in text:
            values.append(text)
        else:
            values.append('https://probe.invalid/'+text.lstrip('/'))
    return values


def rule_cases(rules):
    records, uncovered = [], []
    for rule in rules:
        positive = None
        includes = [domain for domain,include in rule.domains if include]
        documents = ['https://'+domain+'/' for domain in includes] or ['https://site.example/']
        kinds = [kind for kind in rule.types if kind in REQUEST_TYPES]
        for url in candidates(rule):
            try:
                parts = urlsplit(url)
                local = parts.scheme+'://'+parts.netloc+'/'
                for document in documents+[local]:
                    for kind in kinds:
                        context = RequestContext(url,kind,document)
                        if plain_match([rule],context) == rule.action:
                            positive = context
                            break
                    if positive:
                        break
                    if rule.action == ALLOW and 'document' in rule.types:
                        context = RequestContext('https://probe.invalid/advert.js','script',url,(document,))
                        if plain_match([rule],context) == ALLOW:
                            positive = context
                            break
            except (ValueError,ProtocolError):
                continue
            if positive:
                break
        if positive is None:
            uncovered.append({'rule_id':rule.rule_id,'line':rule.line,
                              'reason':'no automatic witness, manual or regex-specific fixture required'})
            continue
        records.append({'rule_id':rule.rule_id,'kind':'single-rule-positive','context':asdict(positive)})
        # Mutations are candidates, never assumed to be negative under the full policy.
        mutations = [RequestContext('https://clean.invalid/control','image','https://clean.invalid/'),
                     RequestContext(positive.url,'image' if positive.resource_type!='image' else 'script',
                                    positive.document_url,positive.ancestors),
                     RequestContext(positive.url,positive.resource_type,'https://unrelated.invalid/')]
        for domain,include in rule.domains:
            if not include:
                mutations.append(RequestContext(positive.url,positive.resource_type,'https://'+domain+'/'))
        records.extend({'rule_id':rule.rule_id,'kind':'context-mutation','context':asdict(c)} for c in mutations)
    return records,{'rules':len(rules),'witnessed_rules':len(rules)-len(uncovered),
                    'unwitnessed':uncovered,'generated_cases':len(records)}
