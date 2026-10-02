"""Boundary and equivalence regressions for the stated security contracts."""
from __future__ import annotations
import unittest
from copy import deepcopy
from itertools import combinations, product
from unittest.mock import patch
import contextmark.threshold_backend as tb
from contextmark.bounds import first_hit_probability, fixed_schedule_product, survival_weighted_certificate
from contextmark.compiler import ContextMarkCompiler, make_demo_program


class CarrierClosureRegression(unittest.TestCase):
    def setUp(self):
        self.key = b'k' * 32
        self.payload = b'p' * 32
        self.issued = tb.mark(self.key, make_demo_program(8), self.payload, n=5, t=3)

    def test_duplicate_replay_preserves_reader_and_public_authorization(self):
        x=deepcopy(self.issued); x[tb.CARRIER_FIELD].append(deepcopy(x[tb.CARRIER_FIELD][0]))
        self.assertEqual(tb.read(self.key,x),self.payload)
        self.assertTrue(tb.public_authorized_derivative(self.issued,x,threshold=3))

    def test_canonical_junk_preserves_reader_and_public_authorization(self):
        for junk in [None, 42, 'noise', {'unissued':'junk'}]:
            with self.subTest(junk=junk):
                x=deepcopy(self.issued); x[tb.CARRIER_FIELD].append(junk)
                self.assertEqual(tb.read(self.key,x),self.payload)
                self.assertTrue(tb.public_authorized_derivative(self.issued,x,threshold=3))

    def test_duplicate_insufficient_positions_never_reach_threshold(self):
        x=deepcopy(self.issued); x[tb.CARRIER_FIELD]=x[tb.CARRIER_FIELD][:2]*5
        self.assertIsNone(tb.read(self.key,x))
        self.assertFalse(tb.public_authorized_derivative(self.issued,x,threshold=3))

    def test_nonminimal_hex_is_not_an_exact_authenticated_carrier(self):
        for prefix in ['0','+',' ','0x']:
            with self.subTest(prefix=prefix):
                x=deepcopy(self.issued)
                for c in x[tb.CARRIER_FIELD]: c['value']=prefix+c['value']
                self.assertIsNone(tb.read(self.key,x))
                self.assertFalse(tb.public_authorized_derivative(self.issued,x,threshold=3))

    def test_noncanonical_container_fails_closed_in_reader_and_public_predicate(self):
        x=deepcopy(self.issued); x[tb.CARRIER_FIELD].append({'bad':float('nan')})
        self.assertIsNone(tb.read(self.key,x))
        self.assertFalse(tb.public_authorized_derivative(self.issued,x,threshold=3))

    def test_strict_integer_threshold_rejects_boolean(self):
        self.assertFalse(tb.public_authorized_derivative(self.issued,self.issued,threshold=True))
        with self.assertRaises(tb.ThresholdCarrierError): tb.mark(self.key,self.issued,self.payload,n=5,t=True)

    def test_out_of_field_share_fails_closed(self):
        x=deepcopy(self.issued)
        for c in x[tb.CARRIER_FIELD]: c['value']=format(tb.P,'x')
        self.assertIsNone(tb.read(self.key,x))

    def test_small_instance_authorization_matches_reader_under_noise(self):
        for bits in product([0,1],repeat=5):
            x=deepcopy(self.issued)
            keep=[deepcopy(c) for c,b in zip(x[tb.CARRIER_FIELD],bits) if b]
            x[tb.CARRIER_FIELD]=keep+deepcopy(keep)+[None,{'noise':'unauthenticated'}]
            expected=sum(bits)>=3
            self.assertEqual(tb.read(self.key,x)==self.payload,expected)
            self.assertEqual(tb.public_authorized_derivative(self.issued,x,threshold=3),expected)

    def test_full_supported_threshold_is_executable(self):
        x=tb.mark(self.key,make_demo_program(8),self.payload,n=32,t=16)
        self.assertEqual(tb.read(self.key,x),self.payload)
        x[tb.CARRIER_FIELD]=x[tb.CARRIER_FIELD][:16]
        self.assertEqual(tb.read(self.key,x),self.payload)
        x[tb.CARRIER_FIELD].pop()
        self.assertIsNone(tb.read(self.key,x))

    def test_additional_authenticated_off_polynomial_point_rejects(self):
        x=deepcopy(self.issued); c=x[tb.CARRIER_FIELD][-1]
        value=(int(c['value'],16)+1)%tb.P; c['value']=format(value,'x')
        c['tag']=tb._tag(self.key,tb.binder(x),c['commitment'],c['index'],value,c['n'],c['t'])
        # This deliberately uses the key to exercise the proof's forgery exception.
        self.assertIsNone(tb.read(self.key,x))

    def test_threshold_compiler_end_to_end_retained_noise(self):
        c=ContextMarkCompiler.deterministic(['builder'],chain_id='boundary-regression',backend=tb.ThresholdCarrierAdapter())
        chain,x=c.issue([],make_demo_program(8),actor='builder',operation='build')
        issued=deepcopy(x); x[tb.CARRIER_FIELD]=x[tb.CARRIER_FIELD][2:]+[{'junk':True}]
        self.assertTrue(c.verify(chain,x))
        self.assertTrue(tb.public_authorized_derivative(issued,x,threshold=3))


class PolynomialResidualRegression(unittest.TestCase):
    def test_exhaustive_small_field_matches_all_subset_definition(self):
        # 7^4 x 2 assignments are small enough to exhaust, including inconsistent data.
        with patch.object(tb,'P',7):
            for threshold in (2,3):
                for values in product(range(7),repeat=4):
                    points=list(zip(range(1,5),values))
                    basis=points[:threshold]; weights=tb._interpolation_weights(basis)
                    constant=tb._evaluate_interpolant(basis,weights,0)
                    residual=all(tb._evaluate_interpolant(basis,weights,x)==y for x,y in points[threshold:])
                    exhaustive=all(tb._interpolate(list(q))==constant for q in combinations(points,threshold))
                    self.assertEqual(residual,exhaustive)

    def test_all_supported_threshold_pairs_preserve_payload(self):
        for n in range(2,33):
            for t in range(2,n+1):
                artifact=tb.mark(b'c'*32,make_demo_program(2),b'q'*32,n=n,t=t)
                self.assertEqual(tb.read(b'c'*32,artifact),b'q'*32,(n,t))


class HazardEnvelopeRegression(unittest.TestCase):
    def test_upper_certificate_is_not_bounded_by_product_envelope(self):
        self.assertEqual(survival_weighted_certificate([0,0],[.5,.5]),1.0)
        self.assertEqual(fixed_schedule_product([.5,.5]),.75)
        self.assertEqual(first_hit_probability([0,0]),0.0)

    def test_product_bound_applies_to_failure_probability(self):
        for actual in product([0,.25,.5],repeat=3):
            self.assertLessEqual(first_hit_probability(actual),fixed_schedule_product([.5]*3)+1e-15)
            self.assertLessEqual(first_hit_probability(actual),survival_weighted_certificate(actual,[.5]*3)+1e-15)

    def test_survival_certificate_equals_probability_for_exact_hazards(self):
        p=[.1,.2,.3]
        self.assertAlmostEqual(survival_weighted_certificate(p,p),first_hit_probability(p))
