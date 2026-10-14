"""Owned real-carrier response-loss/recovery evidence; no transport retries."""
import argparse
import json
from pathlib import Path
from contextmark.compiler import ContextMarkError, MarkingError, make_demo_program
from owned_network_workflow import OwnedService, compiler


def run(output, work):
    output.mkdir(parents=True, exist_ok=False)
    work.mkdir(parents=True, exist_ok=False)
    records = []
    for mode in ('lost-mark-response', 'lost-recovery-read'):
        folder = work/mode
        folder.mkdir()
        path = folder/'state.sqlite'
        service = OwnedService(path)
        args = dict(parent_chain=[], program=make_demo_program(2), actor='builder', operation=mode)
        record = {'case':mode, 'request':args, 'test_keys_only':True,
                  'scope':'owned real finite threshold work over loopback; not native or secure remote deployment'}
        try:
            if mode == 'lost-mark-response':
                service.drop_next = 'mark'
                with compiler(path,service) as issuer:
                    try:
                        issuer.issue(**args)
                    except MarkingError as exc:
                        record['first_error'] = str(exc)
                    else:
                        raise AssertionError('lost response must not release signed output')
                    record['terminal_snapshot'] = issuer.export_registry_snapshot()
                    try:
                        issuer.issue(**args)
                    except MarkingError as exc:
                        record['same_owner_retry_error'] = str(exc)
                    else:
                        raise AssertionError('terminal error was retried')
                with compiler(path,service) as recovered:
                    try:
                        recovered.issue(**args)
                    except MarkingError as exc:
                        record['recovered_retry_error'] = str(exc)
                    else:
                        raise AssertionError('recovered error was retried')
                    assert recovered.export_registry_snapshot() == record['terminal_snapshot']
            else:
                with compiler(path,service) as issuer:
                    pair = issuer.issue(**args)
                    record['pair'] = list(pair)
                    record['terminal_snapshot'] = issuer.export_registry_snapshot()
                service.drop_next = 'read'
                try:
                    compiler(path,service)
                except ContextMarkError as exc:
                    record['recovery_error'] = str(exc)
                else:
                    raise AssertionError('failed semantic recovery opened issuer')
                with compiler(path,service) as recovered:
                    assert recovered.export_registry_snapshot() == record['terminal_snapshot']
                    assert recovered.issue(**args) == pair
            assert sum(e['operation']=='mark' for e in service.events) == 1
        finally:
            service.close()
        record['server_events'], record['client_events'] = service.events, service.client_events
        record['mark_calls'] = sum(e['operation']=='mark' for e in service.events)
        record['read_calls'] = sum(e['operation']=='read' for e in service.events)
        records.append(record)
    (output/'failures.json').write_text(json.dumps(records,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    return {'cases':2, 'mark_calls':sum(r['mark_calls'] for r in records),
            'lost_responses':sum(e['response_lost'] for r in records for e in r['server_events']),
            'all_retry_mark_calls':0, 'production_security_claim':False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--work',type=Path,required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.out,args.work),indent=2))
