"""Verify that later compiler changes preserve already measured policy languages."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from src.zids_v2.artifacts import read_json, write_json
from src.zids_v2.compiler import compile_sources, policy_dfa
from src.zids_v2.context import RequestContext

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_FILES = ('__init__','artifacts','base_ot','batch_ot','codec','contracts','crypto','dfa',
                  'gdfa','lifecycle','ot256','protocol','wire')


def canonical_digest(dfa):
    """Canonical BFS numbering of a reachable minimal, labelled byte DFA."""
    order, indices = [dfa.start], {dfa.start:0}
    digest = hashlib.sha256()
    for state in order:
        row = []
        for dest in dfa.transitions[state]:
            if dest not in indices:
                indices[dest] = len(order)
                order.append(dest)
            row.append(indices[dest])
        digest.update(bytes([dfa.outputs[state]]))
        digest.update(struct.pack('!256I',*row))
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run',required=True)
    parser.add_argument('--output',required=True)
    args = parser.parse_args()
    directory = Path(args.run)
    measured = read_json(directory/'report.json',limit=16*1024*1024)
    unchanged = {name: hashlib.sha256((ROOT/('src/zids_v2/'+name+'.py')).read_bytes()).hexdigest()
                 == measured['implementation_sha256']['src/zids_v2/'+name+'.py'] for name in PROTOCOL_FILES}
    result = {'protocol_files_unchanged':unchanged,'policies':[]}
    for record in measured['scales']:
        if record['compile']['status'] != 'ok':
            continue
        name = record['name']
        old = policy_dfa(read_json(directory/name/'policy.json',limit=128*1024*1024))
        text = (directory/name/'rules.abp').read_text(encoding='utf8')
        new, provenance, _ = compile_sources([(name,text)])
        samples = record.get('secure',[])
        samples_valid = all(len(RequestContext.from_dict(s['request']).encode()) == s['n']
                            and new.evaluate(RequestContext.from_dict(s['request']).encode()) == s['expected']
                            for s in samples)
        old_digest, new_digest = canonical_digest(old),canonical_digest(new)
        result['policies'].append({'name':name,'measured_q':old.q,'current_q':new.q,
                                   'measured_dfa_sha256':old_digest,'current_dfa_sha256':new_digest,
                                   'isomorphic':old.q == new.q and old_digest == new_digest,
                                   'secure_sample_inputs_valid':samples_valid,'current_compile':provenance['stats']})
    write_json(args.output,result)
    print(json.dumps(result,sort_keys=True))
    return 0 if all(unchanged.values()) and all(p['isomorphic'] and p['secure_sample_inputs_valid']
                                               for p in result['policies']) else 2


if __name__ == '__main__':
    raise SystemExit(main())
