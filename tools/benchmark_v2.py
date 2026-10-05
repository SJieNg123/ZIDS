"""Fresh-session measurements with an independent oracle and explicit failures."""
import argparse
from dataclasses import asdict
import hashlib
import json
import multiprocessing as mp
import os
from pathlib import Path
import platform
import queue as queue_module
import subprocess
import sys
from time import perf_counter, process_time

from src.zids_v2 import OT_SUITE
from src.zids_v2.artifacts import prepare, read_json, write_json
from src.zids_v2.codec import Params
from src.zids_v2.compiler import compile_sources, policy_dict, policy_dfa, regex_coverage
from src.zids_v2.context import RequestContext
from src.zids_v2.contracts import ProtocolError
from src.zids_v2.dfa import group_characters
from src.zids_v2.easylist import parse_sources
from src.zids_v2.measure import peak_rss_bytes
from src.zids_v2.protocol import serve, receive

ROOT = Path(__file__).resolve().parents[1]


def worker(operation, payload, result, ready=None):
    wall, cpu = perf_counter(), process_time()
    try:
        if operation == 'compile':
            text = Path(payload['rules']).read_text(encoding='utf8')
            bounds = dict(payload.get('bounds',{}))
            bounds.setdefault('checkpoint',str(Path(payload['output'])/'compiler.sqlite'))
            with (Path(payload['output'])/'compile-progress.jsonl').open('x',encoding='utf8',buffering=1) as log:
                def progress(value):
                    event = dict(value, worker_pid=os.getpid(), wall_seconds=perf_counter()-wall,
                                 peak_rss_bytes=peak_rss_bytes())
                    log.write(json.dumps(event)+'\n')
                    print(json.dumps(dict(event, scale=Path(payload['output']).name)),flush=True)
                dfa, provenance, coverage = compile_sources([(Path(payload['rules']).name,text)],
                                                            progress=progress, **bounds)
                progress({'stage':'policy_write','q':dfa.q})
            write_json(Path(payload['output'])/'policy.json',policy_dict(dfa,provenance))
            value = provenance
        elif operation == 'prepare':
            policy = read_json(payload['policy'],limit=128*1024*1024)
            manifest = prepare(policy_dfa(policy),payload['n'],payload['output'],provenance=policy['provenance'])
            value = {'params':manifest['params'],'session':manifest['session']}
        elif operation == 'serve':
            value = serve(payload['root'],port=0,ready=lambda port: ready.put(port))
        else:
            value = receive(RequestContext.from_dict(payload['request']),payload['output'],port=payload['port'])
        result.put({'status':'ok','result':value,'wall_seconds':perf_counter()-wall,
                    'cpu_seconds':process_time()-cpu,'peak_rss_bytes':peak_rss_bytes()})
    except Exception as exc:
        result.put({'status':'failed','error_type':type(exc).__name__,'error':str(exc),
                    'wall_seconds':perf_counter()-wall,'cpu_seconds':process_time()-cpu,
                    'peak_rss_bytes':peak_rss_bytes()})


def isolated(operation, payload, *, timeout=None):
    ctx = mp.get_context('spawn')
    queue = ctx.Queue()
    proc = ctx.Process(target=worker,args=(operation,payload,queue))
    proc.start()
    started = perf_counter()
    try:
        while True:
            elapsed = perf_counter()-started
            remaining = None if timeout is None else timeout-elapsed
            if remaining is not None and remaining <= 0:
                return {'status':'failed','error_type':'WorkerTimeout',
                        'error':'worker did not return within the requested measurement bound',
                        'wall_seconds':elapsed,'exit_code':proc.exitcode}
            try:
                record = queue.get(timeout=1 if remaining is None else min(1,remaining))
                break
            except queue_module.Empty:
                if not proc.is_alive():
                    # Normal process exit waits for the queue feeder to flush.
                    # A hard OS exit may leave no result, even with no timeout.
                    try:
                        record = queue.get_nowait()
                        break
                    except queue_module.Empty:
                        return {'status':'failed','error_type':'WorkerExit',
                                'error':'worker exited without returning a result',
                                'wall_seconds':perf_counter()-started,'exit_code':proc.exitcode}
        proc.join()
        if proc.exitcode != 0:
            raise RuntimeError('measurement worker exited abnormally')
        return record
    finally:
        if proc.is_alive():
            proc.terminate()
            proc.join()
        queue.close()


def reference(rules, contexts):
    started = perf_counter()
    data = {'rules':[r.text for r in rules],'requests':[asdict(c) for c in contexts]}
    proc = subprocess.run(['node',str(ROOT/'tools/reference_matcher.cjs')],input=json.dumps(data),
                          encoding='utf8',text=True,capture_output=True,check=True,timeout=120,cwd=ROOT)
    value = json.loads(proc.stdout)
    if value['diagnostics']:
        raise ProtocolError('reference rejected a declared supported rule')
    return [v['decision'] for v in value['outputs']], perf_counter()-started


def secure_sample(policy_path, context, output, expected):
    output.mkdir()
    session = output/'server'
    total_started = perf_counter()
    preparation = isolated('prepare',{'policy':str(policy_path),'n':len(context.encode()),'output':str(session)})
    if preparation['status'] != 'ok':
        record = {'status':'failed','prepare':preparation}
        write_json(output/'record.json',record)
        return record
    ctx = mp.get_context('spawn')
    server_result, client_result, ready = ctx.Queue(),ctx.Queue(),ctx.Queue()
    server = ctx.Process(target=worker,args=('serve',{'root':str(session)},server_result,ready))
    client = None
    server.start()
    try:
        port = ready.get(timeout=30)
        client = ctx.Process(target=worker,args=('receive',{'request':asdict(context),'port':port,
                             'output':str(output/'client')},client_result))
        client.start()
        receiver = client_result.get(timeout=600)
        sender = server_result.get(timeout=30)
        for process in (client,server):
            process.join(10)
            if process.exitcode != 0:
                raise RuntimeError('online worker exited abnormally')
        okay = receiver['status'] == sender['status'] == 'ok'
        if okay:
            sent, received = sender['result']['metrics'], receiver['result']['metrics']
            okay = (receiver['result']['decision'] == expected
                    and sent['sent_bytes'] == received['received_bytes']
                    and sent['received_bytes'] == received['sent_bytes']
                    and sent['base_transfers'] == received['base_transfers'] == 8*len(context.encode()))
        record = {'status':'ok' if okay else 'failed','expected':expected,'request':asdict(context),
                'n':len(context.encode()),'prepare':preparation,'server':sender,'client':receiver,
                'fresh_request_wall_seconds':perf_counter()-total_started,
                'disk_bytes':sum(p.stat().st_size for p in output.rglob('*') if p.is_file())}
        write_json(output/'record.json',record)
        return record
    except Exception as exc:
        record = {'status':'failed','prepare':preparation,'error_type':type(exc).__name__,'error':str(exc)}
        write_json(output/'record.json',record)
        return record
    finally:
        for process in (client,server):
            if process is not None and process.is_alive():
                process.terminate()
                process.join()
        for queue in (server_result,client_result,ready):
            queue.close()


def fixtures(full_text):
    full_rules, _ = parse_sources([('easylist.txt',full_text)])
    context200 = (ROOT/'tests_v2/fixtures/context200.abp').read_text(encoding='utf8')
    request = lambda url,kind='image',doc='https://site.example/': RequestContext(url,kind,doc)
    fixed = [request('https://0cdn.xyz/ad'),request('https://0cdn.xyz/allow'),request('https://clean.invalid/control'),
             request('https://v2-context.example/a','script'),
             request('https://v2-context.example/a','script','https://private.site.example/'),
             request('https://v2-context.example/a','image')]
    stored200 = [RequestContext.from_dict(json.loads(line)['context'])
                 for line in (ROOT/'tests_v2/fixtures/context200.jsonl').read_text(encoding='utf8').splitlines()]
    negative = [request('https://clean.invalid/control-'+str(i)) for i in range(200)]
    return [
        ('synthetic','*ad*\n@@*ok*',[RequestContext('https://a/'+p,'image','https://b/') for p in ('ad','adok','xx')]),
        ('small',(ROOT/'rules/small.abp').read_text(encoding='utf8'),
         [request('https://0cf.io/ad'),request('https://adv.gg/ok'),request('https://clean.invalid/control')]),
        ('context200',context200,stored200),
        ('profile2000','\n'.join(r.raw for r in full_rules[:2000])+'\n',fixed+negative[:10]),
        ('full',full_text,fixed+negative[:10]),
    ]


def run(output, *, scales=None, secure_scales=('synthetic','small'), seconds=None, max_nfa=None, max_dfa=None):
    output = Path(output)
    output.mkdir(parents=True,exist_ok=False)
    report = {'suite':OT_SUITE,'platform':platform.platform(),'python':sys.version,
              'reference':read_json(ROOT/'tools/reference-lock.json'),'scales':[],
              'measurement':'fresh spawned workers, wall clock, process CPU and OS peak RSS',
              'secure_selection':'first three cases per requested successful scale',
              'requested_scales':scales,'secure_scales':list(secure_scales),
              'extension':False,'browser_execution':False}
    report['compile_bounds'] = {'seconds':seconds,'max_nfa':max_nfa,'max_dfa':max_dfa}
    report['implementation_sha256'] = {str(p.relative_to(ROOT)).replace('\\','/'):
        hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT/'src/zids_v2').glob('*.py'))}
    write_json(output/'report.json',report)
    for relative in list(report['implementation_sha256'])+['requirements-v2.txt','tools/benchmark_v2.py',
                        'tools/reference_matcher.cjs','tools/reference-lock.json','tools/setup_reference.py',
                        'src/zids_v2/data/public_suffixes.json','src/zids_v2/data/ABP-LICENSE.txt',
                        'src/zids_v2/data/NOTICE.md']:
        target = output/'implementation'/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes((ROOT/relative).read_bytes())
    full_text = (ROOT/'rules/easylist.txt').read_text(encoding='utf8')
    for name, text, contexts in fixtures(full_text):
        if scales and name not in scales:
            continue
        print(json.dumps({'scale':name,'stage':'coverage'}),flush=True)
        directory = output/name
        directory.mkdir()
        source = directory/'rules.abp'
        source.write_text(text,encoding='utf8',newline='\n')
        rule_list, coverage = parse_sources([(name,text)])
        failures = regex_coverage(rule_list)
        coverage['regex_failures'] = failures
        write_json(directory/'coverage.json',coverage)
        expected, oracle_seconds = reference(rule_list,contexts)
        truth = [{'context':asdict(c),'expected':e} for c,e in zip(contexts,expected)]
        write_json(directory/'ground_truth.json',truth)
        record = {'name':name,'source_sha256':hashlib.sha256(text.encode('utf8')).hexdigest(),
                  'network_rules':len(rule_list),'coverage':coverage['counts'],
                  'regex_failures':len(failures),'reference_cases':len(contexts),
                  'reference_seconds':oracle_seconds,'verdict_counts':{str(i):expected.count(i) for i in range(3)}}
        print(json.dumps({'scale':name,'stage':'compile'}),flush=True)
        compiled = isolated('compile',{'rules':str(source),'output':str(directory),
                                      'bounds':report['compile_bounds']},
                            timeout=None if seconds is None else seconds+180)
        record['compile'] = compiled
        if compiled['status'] == 'ok':
            dfa = policy_dfa(read_json(directory/'policy.json',limit=None))
            outputs = [dfa.evaluate(c.encode()) for c in contexts]
            record['dfa_mismatches'] = sum(a != b for a,b in zip(outputs,expected))
            if record['dfa_mismatches']:
                record['status'] = 'failed'
            else:
                groups = group_characters(dfa.padded())
                params = Params(max(len(c.encode()) for c in contexts),dfa.padded().q,groups.outmax,groups.cmax)
                record['largest_input_forecast'] = params.estimate()
                try:
                    params.enforce_limits()
                    record['resource_check'] = 'ok'
                except ProtocolError as exc:
                    record['resource_check'] = str(exc)
                record['secure'] = []
                if name in secure_scales and record['resource_check'] == 'ok':
                    for i,(context,label) in enumerate(zip(contexts[:3],expected[:3])):
                        print(json.dumps({'scale':name,'stage':'secure','case':i}),flush=True)
                        record['secure'].append(secure_sample(directory/'policy.json',context,directory/('request-'+str(i)),label))
                if name in secure_scales and record['resource_check'] != 'ok':
                    record['status'] = 'resource_limit'
                else:
                    record['status'] = 'ok' if all(r['status']=='ok' for r in record['secure']) else 'failed'
        else:
            record['status'] = 'compile_limit' if compiled['error_type']=='CompileLimit' else 'failed'
        report['scales'].append(record)
        write_json(directory/'record.json',record)
        write_json(output/'report.json',report,exclusive=False)
        print(json.dumps({'scale':name,'status':record['status']}),flush=True)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output',required=True)
    parser.add_argument('--scales',nargs='+',choices=['synthetic','small','context200','profile2000','full'])
    parser.add_argument('--secure-scales',nargs='*',default=['synthetic','small'])
    parser.add_argument('--seconds',type=float,help='optional compiler time cap, default unlimited')
    parser.add_argument('--max-nfa',type=int,help='optional NFA state cap, default unlimited')
    parser.add_argument('--max-dfa',type=int,help='optional DFA state cap, default unlimited')
    args = parser.parse_args()
    result = run(args.output,scales=args.scales,secure_scales=args.secure_scales,seconds=args.seconds,
                 max_nfa=args.max_nfa,max_dfa=args.max_dfa)
    return 2 if any(r['status']=='failed' for r in result['scales']) else 0


if __name__ == '__main__':
    raise SystemExit(main())
