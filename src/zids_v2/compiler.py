"""A single output-policy DFA over private, framed request context bytes."""
from collections import deque
import hashlib
from time import perf_counter

from .automata import NFA, HOST_BYTES, URL_BYTES, bits, minimize, RegexUnsupported
from .context import HEADER, REQUEST, DOCUMENT, EOS, URL_START, TYPE_CODES
from .contracts import ProtocolError
from .dfa import ALLOW, DFA, group_characters
from .easylist import PROFILE, CoverageError, parse_sources

COMPILER_VERSION = 'policy-dfa-v1'


def domain_fragment(nfa, domains):
    if not domains:
        return nfa.join([nfa.loop(HOST_BYTES), nfa.char(1)])
    # Aho suffix machine with a virtual leading dot enforces label boundaries.
    children, failure, values = [{}], [0], [None]
    for domain, include in domains:
        state = 0
        for byte in ('.'+domain).encode('ascii'):
            if byte not in children[state]:
                children[state][byte] = len(children)
                children.append({})
                failure.append(0)
                values.append(None)
            state = children[state][byte]
        values[state] = (len(domain), include)
    queue = deque(children[0].values())
    while queue:
        state = queue.popleft()
        for byte, dest in children[state].items():
            queue.append(dest)
            parent = failure[state]
            while parent and byte not in children[parent]:
                parent = failure[parent]
            failure[dest] = children[parent].get(byte, 0)
            if values[dest] is None:
                values[dest] = values[failure[dest]]
    states = [nfa.state() for _ in children]
    end = nfa.state()
    default = not any(include for _, include in domains)
    for state in range(len(children)):
        groups = {}
        for byte in bits(HOST_BYTES):
            parent = state
            while parent and byte not in children[parent]:
                parent = failure[parent]
            dest = children[parent].get(byte, 0)
            groups[dest] = groups.get(dest, 0) | (1 << byte)
        for dest, mask in groups.items():
            nfa.edge(states[state], states[dest], mask)
        if values[state][1] if values[state] is not None else default:
            nfa.edge(states[state], end, 1)
    return states[children[0][ord('.')]], end


def any_frame(nfa, kind):
    types = tuple(TYPE_CODES.values()) if kind == REQUEST else (TYPE_CODES['document'],)
    return nfa.join([nfa.char(1 << kind), nfa.char(sum(1 << t for t in types)),
                     nfa.char((1 << 16) | (1 << 17)), domain_fragment(nfa, ()),
                     nfa.char(1 << URL_START), nfa.loop(URL_BYTES), nfa.char(1)])


def matched_frame(nfa, rule, kind):
    types = [TYPE_CODES[t] for t in rule.types if t in TYPE_CODES] if kind == REQUEST else [TYPE_CODES['document']]
    party = (1 << 16) | (1 << 17) if rule.third_party is None else 1 << (16+int(rule.third_party))
    return nfa.join([nfa.char(1 << kind), nfa.char(sum(1 << t for t in types)), nfa.char(party),
                     domain_fragment(nfa, rule.domains), nfa.char(1 << URL_START),
                     nfa.loop(URL_BYTES), nfa.regex(rule.regex_source, match_case=rule.match_case),
                     nfa.loop(URL_BYTES), nfa.char(1)])


def regex_coverage(rules):
    """Feature validation is independent of the whole-policy resource budget."""
    failures = []
    for rule in rules:
        try:
            NFA().regex(rule.regex_source, match_case=rule.match_case)
        except RegexUnsupported as exc:
            failures.append({'rule_id':rule.rule_id, 'source':rule.source, 'line':rule.line,
                             'status':'unsupported', 'reason':str(exc)})
    return failures


def compile_rules(rules, **bounds):
    started = perf_counter()
    failures = regex_coverage(rules)
    if failures:
        raise CoverageError({'profile':PROFILE, 'records':failures, 'counts':{'unsupported':len(failures)}})
    nfa = NFA(**bounds)
    start, request_start = nfa.literal(HEADER)
    request = any_frame(nfa, REQUEST)
    nfa.eps[request_start].append(request[0])
    document_start = request[1]
    document = any_frame(nfa, DOCUMENT)
    nfa.eps[document_start].append(document[0])
    nfa.eps[document[1]].append(document_start)
    suffixes = {}
    for flag in (1, 2, 4, 8):
        suffix = any_frame(nfa, DOCUMENT)
        nfa.eps[suffix[1]].append(suffix[0])
        finish = nfa.char(1 << EOS)
        nfa.eps[suffix[0]].append(finish[0])
        nfa.outputs[finish[1]] = flag
        suffixes[flag] = suffix[0]
    for rule in rules:
        if any(t in TYPE_CODES for t in rule.types):
            fragment = matched_frame(nfa, rule, REQUEST)
            nfa.eps[request_start].append(fragment[0])
            flag = 4 if rule.action == ALLOW else 1 if rule.generic else 2
            nfa.eps[fragment[1]].append(suffixes[flag])
        if rule.action == ALLOW and ('document' in rule.types or 'genericblock' in rule.types):
            fragment = matched_frame(nfa, rule, DOCUMENT)
            nfa.eps[document_start].append(fragment[0])
            if 'document' in rule.types:
                nfa.eps[fragment[1]].append(suffixes[4])
            if 'genericblock' in rule.types:
                nfa.eps[fragment[1]].append(suffixes[8])
    construction = perf_counter()-started
    dfa, alphabet_classes = nfa.determinize(start)
    raw_q = dfa.q
    determinized = perf_counter()
    dfa = minimize(dfa, check=nfa.check, symbols=nfa.symbols)
    groups = group_characters(dfa.padded())
    stats = {'nfa_states':len(nfa.edges), 'raw_q':raw_q, 'q':dfa.q, 'alphabet_classes':alphabet_classes,
             'outmax':groups.outmax, 'cmax':groups.cmax, 'groups':len(groups.catalog),
             'construction_seconds':construction, 'determinize_seconds':determinized-started-construction,
             'minimize_seconds':perf_counter()-determinized, 'compile_seconds':perf_counter()-started}
    return dfa, stats


def compile_sources(sources, **bounds):
    sources = list(sources)
    rules, coverage = parse_sources(sources)
    dfa, stats = compile_rules(rules, **bounds)
    provenance = {'profile':PROFILE, 'compiler':COMPILER_VERSION,
                  'sources':[{'name':name, 'sha256':hashlib.sha256(text.encode('utf8')).hexdigest()}
                             for name, text in sources], 'stats':stats, 'coverage_counts':coverage['counts']}
    return dfa, provenance, coverage


def policy_dict(dfa, provenance):
    return {'version':COMPILER_VERSION, 'profile':PROFILE, 'transitions':dfa.transitions,
            'outputs':dfa.outputs, 'start':dfa.start, 'provenance':provenance}


def policy_dfa(value):
    if type(value) is not dict or set(value) != {'version','profile','transitions','outputs','start','provenance'}:
        raise ProtocolError('invalid private policy fields')
    if value['version'] != COMPILER_VERSION or value['profile'] != PROFILE:
        raise ProtocolError('unsupported private policy')
    return DFA(tuple(tuple(row) for row in value['transitions']), tuple(value['outputs']), value['start'])
