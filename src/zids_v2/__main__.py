"""Supported v2 CLI. No legacy chooser or simulated OT backend is exposed."""
import argparse
import json
from pathlib import Path
import sys
from time import perf_counter

from .artifacts import prepare, read_json, write_json, digest_file
from .codec import Params
from .compiler import compile_sources, policy_dict, policy_dfa, regex_coverage
from .context import RequestContext
from .contracts import ProtocolError
from .dfa import LABELS, group_characters
from .easylist import parse_sources, CoverageError
from .lifecycle import state, recover
from .protocol import serve, receive
from .policy_io import open_policy, save_policy


def context_file(path):
    # Exactly one JSON object per invocation. JSONL is handled as independent sessions.
    return RequestContext.from_dict(read_json(path, limit=1024*1024))


def parser():
    cli = argparse.ArgumentParser(description='ZIDS v2 EasyList policy and real base OT')
    commands = cli.add_subparsers(dest='command', required=True)
    for name in ('compile','coverage'):
        item = commands.add_parser(name)
        item.add_argument('--rules', nargs='+', required=True)
        item.add_argument('--output', required=True)
        if name == 'compile':
            item.add_argument('--checkpoint', help='private SQLite state, automatically resume matching work')
            item.add_argument('--max-nfa', type=int, help='optional NFA state cap, default unlimited')
            item.add_argument('--max-dfa', type=int, help='optional DFA state cap, default unlimited')
            item.add_argument('--seconds', type=float, help='optional compiler time cap, default unlimited')
    item = commands.add_parser('length')
    item.add_argument('--request', required=True)
    for name in ('estimate','prepare'):
        item = commands.add_parser(name)
        item.add_argument('--policy', required=True)
        item.add_argument('--length', required=True, type=int)
        if name == 'prepare':
            item.add_argument('--output', required=True)
    for name in ('serve','evaluate'):
        item = commands.add_parser(name)
        item.add_argument('--host', default='127.0.0.1')
        item.add_argument('--port', type=int, default=8787)
        item.add_argument('--cert')
        item.add_argument('--key')
        item.add_argument('--ca')
        if name == 'serve':
            item.add_argument('--session', required=True)
            item.add_argument('--batch-size', default=16, type=int)
        else:
            item.add_argument('--request', required=True)
            item.add_argument('--output', required=True)
            item.add_argument('--server-name')
    for name in ('status','recover'):
        item = commands.add_parser(name)
        item.add_argument('--session', required=True)
    return cli


def run(args):
    command = args.command
    if command in ('compile','coverage'):
        sources = [(str(Path(p)), Path(p).read_text(encoding='utf8')) for p in args.rules]
        output = Path(args.output)
        output.mkdir(parents=True, exist_ok=False, mode=0o700)
        rules, coverage = parse_sources(sources, require_coverage=False)
        failures = regex_coverage(rules)
        by_id = {r['rule_id']:r for r in failures}
        for record in coverage['records']:
            if record['rule_id'] in by_id:
                record.update(status='unsupported', reason=by_id[record['rule_id']]['reason'])
        from collections import Counter
        coverage['counts'] = dict(Counter(r['status'] for r in coverage['records']))
        coverage['sources'] = [{'name':p, 'sha256':digest_file(p)} for p in args.rules]
        write_json(output/'coverage.json', coverage)
        if coverage['counts'].get('unsupported',0) or coverage['counts'].get('invalid',0):
            raise CoverageError(coverage)
        if command == 'coverage':
            return coverage['counts']
        try:
            dfa, provenance, _ = compile_sources(sources, max_nfa=args.max_nfa, max_dfa=args.max_dfa,
                                                 seconds=args.seconds, checkpoint=args.checkpoint)
        except ProtocolError as exc:
            write_json(output/'failure.json', {'error':str(exc), 'coverage_counts':coverage['counts']})
            raise
        save_policy(output/'policy.bin',dfa,provenance)
        return provenance
    if command == 'length':
        return {'n':len(context_file(args.request).encode())}
    if command in ('estimate','prepare'):
        with open_policy(args.policy) as (dfa,provenance):
            dfa = dfa.padded()
            groups = group_characters(dfa)
            params = Params(args.length, dfa.q, groups.outmax, groups.cmax)
            params.enforce_limits()
            if command == 'estimate':
                return params.estimate()
            provenance = dict(provenance,policy_sha256=digest_file(args.policy))
            started = perf_counter()
            manifest = prepare(dfa, args.length, args.output, provenance=provenance)
            return {'session':manifest['session'], 'params':manifest['params'], 'prepare_seconds':perf_counter()-started}
    if command == 'serve':
        return serve(args.session,args.host,args.port,batch_size=args.batch_size,cert=args.cert,key=args.key,ca=args.ca,
                     ready=lambda port: print(json.dumps({'listening':port}), flush=True))
    if command == 'evaluate':
        result = receive(context_file(args.request),args.output,args.host,args.port,cert=args.cert,key=args.key,ca=args.ca,
                         server_name=args.server_name)
        result['label'] = LABELS[result['decision']]
        write_json(Path(args.output)/'result.json',result)
        return result
    return recover(args.session) if command == 'recover' else state(args.session)


def main():
    args = parser().parse_args()
    try:
        print(json.dumps(run(args), sort_keys=True), flush=True)
    except (ProtocolError, OSError, ValueError) as exc:
        # This is local stderr only. No URL, input bytes, state path or error frame is sent.
        print(json.dumps({'error':str(exc)}), file=sys.stderr, flush=True)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
