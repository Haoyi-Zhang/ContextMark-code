"""Controlled local owner-lifetime schedule using the real finite carrier."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import threading

from contextmark.compiler import ContextMarkCompiler, ContextMarkError, MarkingError, make_demo_program
from contextmark.durable_registry import DurableRegistryError
from contextmark.threshold_backend import ThresholdCarrierAdapter


def owner_schedule(work, mode):
    if mode not in ('reservation-error', 'terminal-ambiguous'):
        raise ValueError('undeclared owned schedule')
    entered, release = threading.Event(), threading.Event()
    class Backend:
        def __init__(self):
            self.calls = []
            self.real = ThresholdCarrierAdapter(n=5, t=3)
        def mark(self, key, program, payload):
            self.calls.append({'module': program['module'], 'context': payload})
            if program['module'] == 'held':
                entered.set()
                if not release.wait(10):
                    raise RuntimeError('owned schedule timed out')
            return self.real.mark(key, program, payload)
        def read(self, key, artifact):
            return self.real.read(key, artifact)
    def args(name):
        program = make_demo_program(2)
        program['module'] = name
        return dict(parent_chain=[], program=program, actor='builder', operation=name)
    def open_issuer(path, backend):
        return ContextMarkCompiler.deterministic(['builder'], seed=29,
            chain_id='owned-owner-lifetime', backend=backend, registry_path=str(path))
    Path(work).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=work, prefix=mode+'-') as folder:
        path = Path(folder)/'state.sqlite'
        backend = Backend()
        issuer = open_issuer(path, backend)
        original = issuer._durable.write_entries
        def fault(entries, *, reserve=False):
            peer = entries[0]['unsigned']['operation'] == 'peer'
            if peer and reserve and mode == 'reservation-error':
                raise DurableRegistryError('owned peer reservation I/O error')
            original(entries, reserve=reserve)
            if peer and not reserve and mode == 'terminal-ambiguous':
                raise DurableRegistryError('owned peer error after terminal commit')
        result = {'mode': mode, 'requests': [args('held'), args('peer')], 'schedule': []}
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(issuer.issue, **args('held'))
            try:
                if not entered.wait(10):
                    raise RuntimeError('owned held backend did not enter')
                result['schedule'].append('held request reserved and backend entered')
                issuer._durable.write_entries = fault
                try:
                    issuer.issue(**args('peer'))
                except ContextMarkError as exc:
                    result['peer_error'] = str(exc)
                else:
                    raise AssertionError('peer I/O error must not release an output')
                result['storage_failed'] = issuer._storage_failed
                result['held_backend_still_active'] = not future.done()
                try:
                    issuer.close()
                except ContextMarkError:
                    result['close_rejected_while_active'] = True
                else:
                    result['close_rejected_while_active'] = False
                try:
                    other = open_issuer(path, Backend())
                except ContextMarkError:
                    result['second_owner_excluded_while_active'] = True
                else:
                    result['second_owner_excluded_while_active'] = False
                    other.close()
            finally:
                release.set()
                try:
                    future.result(timeout=10)
                except ContextMarkError as exc:
                    result['held_error'] = str(exc)
                else:
                    raise AssertionError('uncertain issuer must not release held output')
                if not issuer._closed:
                    issuer.close()
        result['mark_calls_before_recovery'] = backend.calls
        recovered_backend = Backend()
        with open_issuer(path, recovered_backend) as recovered:
            try:
                recovered.issue(**args('held'))
            except MarkingError as exc:
                result['held_retry_error'] = str(exc)
            else:
                raise AssertionError('interrupted held attempt must remain failed')
            pair = recovered.issue(**args('peer'))
            result['peer_retry_verified'] = recovered.verify(*pair)
            result['recovered_snapshot'] = recovered.export_registry_snapshot()
            result['mark_calls_after_recovery'] = recovered_backend.calls
        return result
