"""Private rule-group construction statistics, without whole-policy determinization."""
import argparse
import hashlib
import json
from pathlib import Path

from src.zids_v2.artifacts import write_json
from src.zids_v2.automata import NFA
from src.zids_v2.easylist import parse_sources


def describe(rules):
    grouped = {}
    for rule in rules:
        # These are the exact grouping fields used by compile_rules.
        key = (rule.action,rule.types,rule.domains,rule.generic,rule.third_party,rule.match_case)
        grouped.setdefault(key,[]).append(rule)
    result = []
    for key, members in grouped.items():
        nfa = NFA()
        nfa.regex_union([rule.regex_source for rule in members],match_case=key[-1])
        condition = dict(zip(('action','types','domains','generic','third_party','match_case'),key))
        result.append({'group_id':hashlib.sha256(json.dumps(condition,sort_keys=True).encode()).hexdigest(),
                       'condition':condition,'rules':len(members),'url_union_nfa_states':len(nfa.edges),
                       'rule_ids':[rule.rule_id for rule in members]})
    return {'rules':len(rules),'groups':sorted(result,key=lambda g:(-g['url_union_nfa_states'],g['group_id'])),
            'measurement':'URL regex union only, excludes context guards and policy suffixes',
            'limitation':'NFA size does not predict reachable subset combinations or minimized DFA size'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rules',nargs='+',required=True)
    parser.add_argument('--output',required=True)
    args = parser.parse_args()
    sources = [(name,Path(name).read_text(encoding='utf8')) for name in args.rules]
    rules, coverage = parse_sources(sources)
    report = describe(rules)
    report['sources'] = [{'name':name,'sha256':hashlib.sha256(text.encode('utf8')).hexdigest()}
                         for name,text in sources]
    report['coverage_counts'] = coverage['counts']
    write_json(args.output,report)
    print(json.dumps({'output':args.output,'rules':report['rules'],'groups':len(report['groups'])}))


if __name__ == '__main__':
    main()
