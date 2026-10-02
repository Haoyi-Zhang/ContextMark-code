"""Executable audits for the final-round proof and carrier corrections."""
from __future__ import annotations
from copy import deepcopy
from itertools import combinations, product
from unittest.mock import patch
from . import threshold_backend as tb
from .compiler import AuthenticatedEnvelopeBackend, ContextMarkCompiler, make_demo_program
from .bounds import (
    evidence_conditioned_bound,
    first_hit_probability,
    fixed_schedule_product,
    survival_weighted_certificate,
)
from .canonical import expression_binder


def assurance_checks():
    k=b'r'*32; payload=b'p'*32
    issued=tb.mark(k,make_demo_program(8),payload,n=5,t=3)
    closure=[]
    for bits in product([0,1],repeat=5):
        x=deepcopy(issued); retained=[c for c,b in zip(x[tb.CARRIER_FIELD],bits) if b]
        for noise in ['none','repeat','junk','both']:
            x[tb.CARRIER_FIELD]=deepcopy(retained)
            if noise in ('repeat','both'): x[tb.CARRIER_FIELD]+=deepcopy(retained)
            if noise in ('junk','both'): x[tb.CARRIER_FIELD]+=[None,{'noise':'unauthenticated'}]
            found=tb.read(k,x)==payload; authorized=tb.public_authorized_derivative(issued,x,threshold=3)
            closure.append({'mask':''.join(map(str,bits)),'noise':noise,'read_success':found,'authorized':authorized,'expected':sum(bits)>=3,'passed':found==authorized==(sum(bits)>=3)})
    assignments=0; mismatches=0
    with patch.object(tb,'P',7):
        for t in [2,3]:
            for values in product(range(7),repeat=4):
                points=list(zip(range(1,5),values)); basis=points[:t]; w=tb._interpolation_weights(basis)
                secret=tb._evaluate_interpolant(basis,w,0)
                residual=all(tb._evaluate_interpolant(basis,w,x)==y for x,y in points[t:])
                legacy=all(tb._interpolate(list(q))==secret for q in combinations(points,t))
                assignments+=1;mismatches+=residual!=legacy
    supported=[]
    for n in range(2,33):
        for t in range(2,n+1):
            x=tb.mark(k,make_demo_program(2),payload,n=n,t=t)
            supported.append({'n':n,'t':t,'passed':tb.read(k,x)==payload})
    product_case={'actual_hazards':[0.0,0.0],'upper_hazards':[0.5,0.5],'actual_first_hit':first_hit_probability([0,0]),'upper_certificate':survival_weighted_certificate([0,0],[.5,.5]),'product_probability_bound':fixed_schedule_product([.5,.5])}
    certificate_case={
        'uncapped_certificate':1.5,
        'evidence_conditioned_bound':evidence_conditioned_bound(1.5,calibration_errors=[0.02],key_switch_loss=0.01),
        'passed':evidence_conditioned_bound(1.5,calibration_errors=[0.02],key_switch_loss=0.01)==1.0,
    }
    envelope=AuthenticatedEnvelopeBackend(expression_binder)
    envelope_key=b'e'*32
    envelope_payload='11'*32
    malformed=envelope.mark(envelope_key,make_demo_program(2),envelope_payload)
    malformed['_threshold_carriers']=[1.5]
    envelope_case={
        'binder_ignores_threshold_field':expression_binder(malformed)==expression_binder(make_demo_program(2)),
        'full_artifact_reader_rejects_noncanonical_float':envelope.read(envelope_key,malformed) is None,
    }
    compiler=ContextMarkCompiler.deterministic(['builder'],chain_id='runtime-boundary')
    chain,artifact=compiler.issue([],make_demo_program(2),actor='builder',operation='compile')
    compiler.binder=lambda _artifact: (_ for _ in ()).throw(RuntimeError('injected binder failure'))
    runtime_case={'binder_runtime_rejected':not compiler.verify(chain,artifact)}
    result={'schema':'tdsc-assurance-checks-v2','closure_rows':closure,'closure_count':len(closure),'closure_all_passed':all(r['passed'] for r in closure),'small_field_assignments':assignments,'polynomial_equivalence_mismatches':mismatches,'threshold_parameter_pairs':supported,'threshold_pair_count':len(supported),'threshold_pairs_all_passed':all(r['passed'] for r in supported),'product_certificate_counterexample':product_case,'certificate_saturation_boundary':certificate_case,'envelope_full_artifact_boundary':envelope_case,'public_verifier_runtime_boundary':runtime_case}
    result['passed']=result['closure_all_passed'] and not mismatches and result['threshold_pairs_all_passed'] and certificate_case['passed'] and all(envelope_case.values()) and all(runtime_case.values())
    return result
