"""Owned loopback HTTP + real finite threshold carrier + durable SQLite workflow.

Test-only keys cross plaintext loopback to measure RPC cost, not secure deployment.
No external targets, production watermark, TLS, replica or power-loss claim.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import argparse
import hashlib
import http.client
import importlib.metadata
import json
import math
import os
import platform
import socket
import sqlite3
import statistics
import sys
import threading
import time

from contextmark.canonical import canonical_bytes
from contextmark.compiler import ContextMarkCompiler, ContextMarkError, MarkingError, make_demo_program
from contextmark.threshold_backend import ThresholdCarrierAdapter

DEPTHS = (1, 8, 32)
SAMPLES, WARMUPS = 5, 1
PROTOCOL = {
    'depths': DEPTHS, 'samples': SAMPLES, 'warmups': WARMUPS, 'seed': 29,
    'program': 'make_demo_program(2)', 'backend': 'real ThresholdCarrierAdapter(n=5,t=3)',
    'transport': 'HTTP on OS-assigned 127.0.0.1 port; one connection/call; no implicit retries; timeout 5s',
    'comparison': 'session vs full-prefix stateless issue; identical programs, metadata, keys, backend and durable policy',
    'ordering': 'alternate first path by sample parity; retain all samples including warmups',
    'total_boundary': 'program/server acquisition, DB creation/open, issue/export, verify, serialization, close, reopen, all exact retries, close, server teardown',
    'network_bytes': 'HTTP header and body bytes only; excludes IP/TCP framing, retransmits and TLS',
    'security_scope': 'owned benign finite models; plaintext deterministic test keys; not secure remote deployment or production robustness',
}


class OwnedService:
    def __init__(self, registry_path):
        self.path = Path(registry_path)
        self.events = []
        self.client_events = []
        self.delegate = ThresholdCarrierAdapter(n=5, t=3)
        self.drop_next = None
        service = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                started = time.perf_counter_ns()
                size = int(self.headers.get('Content-Length', '0'))
                if self.path not in ('/mark', '/read') or not 0 < size <= 2**21:
                    self.send_error(400)
                    return
                body = self.rfile.read(size)
                data = json.loads(body)
                operation = self.path[1:]
                key = bytes.fromhex(data['test_key_hex'])
                event = {'operation': operation, 'input': data, 'request_body_bytes': len(body),
                         'request_header_bytes': len(self.raw_requestline)+2+
                             sum(len(k.encode('latin-1'))+len(v.encode('latin-1'))+4
                                 for k,v in self.headers.items())}
                if operation == 'mark':
                    # Observe the committed reservation using a distinct SQL connection.
                    with closing(sqlite3.connect(service.path)) as db:
                        row = db.execute('SELECT body FROM attempts WHERE context=?', (data['payload'],)).fetchone()
                    event['committed_status_before_mark'] = json.loads(row[0])['status'] if row else None
                    if event['committed_status_before_mark'] != 'pending':
                        raise AssertionError('owned mark entered without committed pending state')
                    output = service.delegate.mark(key, data['program'], data['payload'])
                else:
                    output = service.delegate.read(key, data['artifact'])
                response = canonical_bytes({'result': output})
                event.update(output=output, crypto_and_inspection_ms=(time.perf_counter_ns()-started)/1e6)
                event['response_lost'] = service.drop_next == operation
                if event['response_lost']:
                    service.drop_next = None
                    service.events.append(event)
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(response)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(response)
                self.wfile.flush()
                service.events.append(event)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError('owned server did not stop')

    def call(self, operation, data):
        started = time.perf_counter_ns()
        body = canonical_bytes(data)
        event = {'operation': operation, 'request_body_bytes': len(body),
                 'response_header_bytes': 0, 'response_body_bytes': 0, 'error': None}
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_address[1], timeout=5)
        try:
            connection.request('POST', '/'+operation, body=body,
                               headers={'Content-Type':'application/json', 'Connection':'close'})
            response = connection.getresponse()
            raw = response.read()
            event['response_body_bytes'] = len(raw)
            status = f'HTTP/{response.version//10}.{response.version%10} {response.status} {response.reason}\r\n'
            event['response_header_bytes'] = len(status.encode('latin-1'))+2+sum(
                len(k.encode('latin-1'))+len(v.encode('latin-1'))+4 for k,v in response.getheaders())
            if response.status != 200:
                raise ValueError('owned RPC failed')
            return json.loads(raw)['result']
        except Exception as exc:
            event['error'] = type(exc).__name__
            raise
        finally:
            connection.close()
            event['rpc_ms'] = (time.perf_counter_ns()-started)/1e6
            self.client_events.append(event)

    def mark(self, key, program, payload):
        return self.call('mark', {'test_key_hex': key.hex(), 'program': program, 'payload': payload})

    def read(self, key, artifact):
        return self.call('read', {'test_key_hex': key.hex(), 'artifact': artifact})


def compiler(path, service):
    return ContextMarkCompiler.deterministic(['builder'], seed=29, chain_id='owned-loopback-cost',
        backend=service, registry_path=str(path))


def trial(folder, mode, depth, sample):
    started = time.perf_counter_ns()
    folder.mkdir(parents=True, exist_ok=False)
    path = folder/'state.sqlite'
    program = make_demo_program(2)
    service = OwnedService(path)
    issuer = compiler(path, service)
    acquired = time.perf_counter_ns()
    chain, artifact = [], program
    requests = []
    try:
        session = issuer.begin_session(program) if mode == 'session' else None
        issue_start = time.perf_counter_ns()
        for i in range(depth):
            args = dict(actor='builder', operation='owned-stage', metadata={'stage':i, 'sample':sample})
            if session:
                session.append_private(**args)
            else:
                chain, artifact = issuer.issue(chain, artifact, **args)
        pair = session.snapshot() if session else (chain, artifact)
        issued = time.perf_counter_ns()
        if not issuer.verify(*pair):
            raise AssertionError('owned final pair rejected')
        manifest = issuer.serialize_manifest(pair[0])
        artifact_bytes = issuer.serialize_artifact(pair[1])
        snapshot = issuer.export_registry_snapshot()
        checked = time.perf_counter_ns()
        issuer.close()
        closed = time.perf_counter_ns()
        issuer = compiler(path, service)
        reopened = time.perf_counter_ns()
        if canonical_bytes(issuer.export_registry_snapshot()) != canonical_bytes(snapshot):
            raise AssertionError('owned reopen changed terminal bytes')
        marks = sum(e['operation']=='mark' for e in service.events)
        for entry in sorted(snapshot['entries'], key=lambda e:e['unsigned']['index']):
            request = dict(parent_chain=issuer._reconstruct_chain(entry['context'])[:-1],
                program=json.loads(bytes.fromhex(entry['request_program_hex'])),
                actor=entry['unsigned']['actor'], operation=entry['unsigned']['operation'],
                metadata=entry['unsigned']['metadata'])
            requests.append(deepcopy(request))
            retry_pair = issuer.issue(**request)
            context = retry_pair[0][-1]['context']
            expected = issuer._issued[context]
            if retry_pair != (issuer._reconstruct_chain(context), expected[4]):
                raise AssertionError('exact retry differs')
        if sum(e['operation']=='mark' for e in service.events) != marks:
            raise AssertionError('exact retry resampled')
        retried = time.perf_counter_ns()
        issuer.close()
    finally:
        if not issuer._closed:
            issuer.close()
        service.close()
    end = time.perf_counter_ns()
    row = {'mode': mode, 'depth': depth, 'sample': sample, 'warmup': sample < 0,
           'acquisition_ms': (acquired-started)/1e6, 'issue_export_ms': (issued-issue_start)/1e6,
           'verify_serialize_snapshot_ms': (checked-issued)/1e6, 'first_close_ms': (closed-checked)/1e6,
           'reopen_ms': (reopened-closed)/1e6, 'exact_retry_ms': (retried-reopened)/1e6,
           'final_close_teardown_ms': (end-retried)/1e6, 'full_workflow_ms': (end-started)/1e6,
           'rpc_ms': sum(e['rpc_ms'] for e in service.client_events),
           'mark_calls': marks, 'read_calls': sum(e['operation']=='read' for e in service.events),
           'http_request_bytes': sum(e['request_header_bytes']+e['request_body_bytes'] for e in service.events),
           'http_response_bytes': sum(e['response_header_bytes']+e['response_body_bytes'] for e in service.client_events),
           'database_bytes': path.stat().st_size, 'manifest_bytes': len(manifest), 'artifact_bytes':len(artifact_bytes),
           'all_retries_without_mark': True, 'pending_before_every_mark': True}
    if marks != depth or len(service.events) != 3*depth+1 or len(service.client_events) != len(service.events):
        raise AssertionError('owned RPC coverage')
    record = {'row': row, 'requests': requests, 'pair': list(pair), 'snapshot': snapshot,
              'server_events': service.events, 'client_events': service.client_events}
    (folder/'trace.json').write_text(json.dumps(record, indent=2, sort_keys=True)+'\n', encoding='utf-8')
    return record


def summarize(rows):
    results = []
    for depth in DEPTHS:
        for mode in ('session', 'replay'):
            selected = [r for r in rows if r['depth']==depth and r['mode']==mode and not r['warmup']]
            result = {'depth': depth, 'mode': mode, 'samples': len(selected)}
            for metric in ('acquisition_ms', 'issue_export_ms', 'verify_serialize_snapshot_ms',
                           'reopen_ms', 'exact_retry_ms', 'full_workflow_ms', 'rpc_ms'):
                values = sorted(r[metric] for r in selected)
                result[metric+'_median'] = statistics.median(values)
                result[metric+'_p95'] = values[math.ceil(.95*len(values))-1]
            results.append(result)
    return results


def source_bindings():
    root = Path(__file__).resolve().parent
    names = ('owned_network_workflow.py', 'contextmark/compiler.py', 'contextmark/durable_registry.py',
             'contextmark/threshold_backend.py', 'contextmark/canonical.py')
    return {name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in names}


def measure(output, work, cpu_name, filesystem):
    output.mkdir(parents=True, exist_ok=False)
    work.mkdir(parents=True, exist_ok=False)
    rows, pairs = [], []
    for depth in DEPTHS:
        for sample in range(-WARMUPS, SAMPLES):
            order = ('replay','session') if sample%2 else ('session','replay')
            records = {}
            for mode in order:
                folder = work/f'{depth}-{sample}-{mode}'
                record = trial(folder, mode, depth, sample)
                rows.append(record['row'])
                records[mode] = record
            if (canonical_bytes(records['session']['pair']) != canonical_bytes(records['replay']['pair'])
                    or canonical_bytes(records['session']['snapshot']) != canonical_bytes(records['replay']['snapshot'])
                    or canonical_bytes(records['session']['requests']) != canonical_bytes(records['replay']['requests'])):
                raise AssertionError('matched paths have different inputs or terminal outputs')
            pairs.append({'depth':depth, 'sample':sample, 'warmup':sample<0,
                          'identical_requests':True, 'identical_pairs':True, 'identical_terminal_bytes':True})
            print(f'completed owned loopback depth={depth} sample={sample}', flush=True)
    environment = {'python':platform.python_version(), 'platform':platform.platform(),
        'processor':platform.processor(), 'logical_cpus':os.cpu_count(),
        'cryptography':importlib.metadata.version('cryptography'), 'sqlite':sqlite3.sqlite_version,
        'cpu_name':cpu_name, 'filesystem':filesystem,
        'journal_mode':'DELETE', 'synchronous':'EXTRA (3)', 'tls':False,
        'external_targets':0, 'timer':'perf_counter_ns', 'test_keys_only':True}
    result = {'protocol':PROTOCOL, 'environment':environment, 'source_sha256':source_bindings(),
              'measured_pairs':len([p for p in pairs if not p['warmup']]),
              'warmup_pairs':len([p for p in pairs if p['warmup']]), 'summaries':summarize(rows),
              'mark_calls':sum(r['mark_calls'] for r in rows),
              'read_calls':sum(r['read_calls'] for r in rows),
              'all_requests_outputs_terminal_bytes_match':True,
              'diagnostic_output_writing_timed':False,
              'native_or_production_robustness_claim':False}
    for name, data in [('samples',rows), ('matched_pairs',pairs), ('summary',result)]:
        (output/(name+'.json')).write_text(json.dumps(data, indent=2, sort_keys=True)+'\n', encoding='utf-8')
    return result


def check(output, work):
    rows = json.loads((output/'samples.json').read_text(encoding='utf-8'))
    summary = json.loads((output/'summary.json').read_text(encoding='utf-8'))
    if len(rows)!=36 or summary['summaries'] != summarize(rows) or summary['source_sha256'] != source_bindings():
        raise ValueError('owned workflow summary/source mismatch')
    for row in rows:
        folder = work/f"{row['depth']}-{row['sample']}-{row['mode']}"
        trace = json.loads((folder/'trace.json').read_text(encoding='utf-8'))
        if trace['row'] != row or row['mark_calls'] != row['depth'] or row['read_calls'] != 2*row['depth']+1:
            raise ValueError('owned workflow call/row mismatch')
        marks = [e for e in trace['server_events'] if e['operation']=='mark']
        if any(e['committed_status_before_mark'] != 'pending' for e in marks):
            raise ValueError('owned pending-before-mark observation mismatch')
        if sum(e['request_body_bytes']+e['request_header_bytes'] for e in trace['server_events']) != row['http_request_bytes']:
            raise ValueError('HTTP request bytes mismatch')
        if sum(e['response_body_bytes']+e['response_header_bytes'] for e in trace['client_events']) != row['http_response_bytes']:
            raise ValueError('HTTP response bytes mismatch')
        sibling = work/f"{row['depth']}-{row['sample']}-{'replay' if row['mode']=='session' else 'session'}"/'trace.json'
        other = json.loads(sibling.read_text(encoding='utf-8'))
        if any(canonical_bytes(trace[k]) != canonical_bytes(other[k]) for k in ('pair','snapshot','requests')):
            raise ValueError('matched information/output mismatch')
    return {'status':'consistent', 'path_runs':36, 'matched_pairs':18,
            'mark_calls':sum(r['mark_calls'] for r in rows), 'semantic_or_network_rerun':False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--cpu-name')
    parser.add_argument('--filesystem')
    args = parser.parse_args()
    if args.check:
        result = check(args.out,args.work)
    else:
        if not args.cpu_name or not args.filesystem:
            parser.error('measurement requires observed --cpu-name and --filesystem')
        result = measure(args.out,args.work,args.cpu_name,args.filesystem)
    print(json.dumps(result,indent=2,sort_keys=True))
