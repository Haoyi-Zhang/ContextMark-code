"""Real local TCP calls and finite carrier execution, including lost responses."""
from pathlib import Path
import os
import tempfile
import unittest
from contextmark.canonical import canonical_bytes
from contextmark.compiler import ContextMarkError, MarkingError, make_demo_program
from owned_network_workflow import OwnedService, compiler, trial

WORK = Path(os.environ.get('CONTEXTMARK_OWNED_WORK_ROOT',
                          str(Path(__file__).resolve().parents[1]/'results/owned-network-work')))


class OwnedNetworkTests(unittest.TestCase):
    def setUp(self):
        WORK.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=WORK)
        self.folder = Path(self.temp.name)
    def tearDown(self):
        self.temp.cleanup()

    def test_real_carrier_matched_full_workflows(self):
        session = trial(self.folder/'session','session',3,0)
        replay = trial(self.folder/'replay','replay',3,0)
        for name in ('pair','snapshot','requests'):
            self.assertEqual(canonical_bytes(session[name]),canonical_bytes(replay[name]))
        for record in (session,replay):
            self.assertEqual(record['row']['mark_calls'],3)
            self.assertEqual(record['row']['read_calls'],7)
            self.assertGreater(record['row']['http_request_bytes'],0)
            self.assertGreater(record['row']['http_response_bytes'],0)

    def test_lost_mark_response_is_terminal_not_resampled(self):
        path = self.folder/'state.sqlite'
        service = OwnedService(path)
        args = dict(parent_chain=[], program=make_demo_program(2),actor='builder',operation='owned-lost')
        try:
            service.drop_next = 'mark'
            with compiler(path,service) as issuer:
                with self.assertRaises(MarkingError):
                    issuer.issue(**args)
                self.assertEqual(issuer.registry_status_counts(),(0,1,1))
                with self.assertRaises(MarkingError):
                    issuer.issue(**args)
            with compiler(path,service) as reopened:
                with self.assertRaises(MarkingError):
                    reopened.issue(**args)
            marks = [e for e in service.events if e['operation']=='mark']
            self.assertEqual(len(marks),1)
            self.assertTrue(marks[0]['response_lost'])
            self.assertEqual(marks[0]['committed_status_before_mark'],'pending')
            self.assertTrue(marks[0]['output']['_threshold_carriers'])
        finally:
            service.close()


    def test_recovery_reader_failure_does_not_reset_or_mark(self):
        path = self.folder/'state.sqlite'
        service = OwnedService(path)
        args = dict(parent_chain=[],program=make_demo_program(2),actor='builder',operation='owned-success')
        try:
            with compiler(path,service) as issuer:
                pair = issuer.issue(**args)
                saved = issuer.export_registry_snapshot()
            service.drop_next = 'read'
            with self.assertRaises(ContextMarkError):
                compiler(path,service)
            with compiler(path,service) as reopened:
                self.assertEqual(reopened.export_registry_snapshot(),saved)
                self.assertEqual(reopened.issue(**args),pair)
            self.assertEqual(sum(e['operation']=='mark' for e in service.events),1)
        finally:
            service.close()


if __name__ == '__main__':
    unittest.main()
