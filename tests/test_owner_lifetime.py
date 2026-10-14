"""Owned error interleavings must retain owner exclusion through active work."""
import os
from pathlib import Path
import unittest
from owned_owner_fixture import owner_schedule

WORK = Path(os.environ.get('CONTEXTMARK_OWNED_WORK_ROOT',
                          str(Path(__file__).resolve().parents[1]/'results/owned-owner-work')))


class OwnerLifetimeTests(unittest.TestCase):
    def check_schedule(self, mode):
        result = owner_schedule(WORK, mode)
        self.assertTrue(result['storage_failed'])
        self.assertTrue(result['held_backend_still_active'])
        self.assertTrue(result['close_rejected_while_active'], result)
        self.assertTrue(result['second_owner_excluded_while_active'], result)
        self.assertIn('InterruptedAttempt', result['held_retry_error'])
        self.assertTrue(result['peer_retry_verified'])
        expected = 1 if mode == 'reservation-error' else 2
        self.assertEqual(len(result['mark_calls_before_recovery']), expected)
        # An uncommitted peer reservation permits its first call, not a resample.
        expected_fresh = 1 if mode == 'reservation-error' else 0
        self.assertEqual(len(result['mark_calls_after_recovery']), expected_fresh)

    def test_peer_reservation_error_does_not_release_live_owner(self):
        self.check_schedule('reservation-error')

    def test_peer_ambiguous_commit_does_not_release_live_owner(self):
        self.check_schedule('terminal-ambiguous')
