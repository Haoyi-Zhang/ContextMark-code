from __future__ import annotations

import hashlib
import math
import unittest
from copy import deepcopy

from contextmark.bounds import (
    PrimitiveRates,
    adaptive_ledger_certificate,
    closed_form_union,
    conditional_kernel_shift,
    enumerate_union_probability,
    evidence_conditioned_bound,
    first_hit_probability,
    fixed_schedule_product,
    independent_model,
    query_caps,
    theorem_bound,
)
from contextmark.calibration import (
    clopper_pearson_upper,
    coverage_grid,
    equal_marginal_history_counterexample,
    repeated_look_noncoverage,
    spending_alpha,
)
from contextmark.campaigns import (
    coarse_binder_alias_witness,
    mutation_campaign,
    negative_control,
    resume_continuity_audit,
    terminal_failure_audit,
    threshold_audit,
    three_stage_fixture,
    _candidate_selection_check,
    _context_trace_check,
)
from contextmark.canonical import CanonicalizationError, canonical_bytes, expression_binder
from contextmark.compiler import (
    AuthenticatedEnvelopeBackend,
    ContextMarkCompiler,
    ContextMarkError,
    MarkingError,
    make_demo_program,
)
from contextmark.finite_model import (
    baseline_matrix,
    omission_matrix,
    safeguard_lattice,
    validate_omission_matrix,
    validate_safeguard_lattice,
)
from contextmark.threshold_backend import (
    CARRIER_FIELD,
    ThresholdCarrierAdapter,
    binder as threshold_binder,
    mark as threshold_mark,
    public_authorized_derivative,
    read as threshold_read,
    payload_commitment,
    read_candidates,
)


class CanonicalTests(unittest.TestCase):
    def test_01_canonical_key_order(self):
        self.assertEqual(canonical_bytes({"b": 1, "a": 2}), b'{"a":2,"b":1}')

    def test_02_canonical_rejects_float(self):
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({"x": 1.0})

    def test_03_canonical_rejects_nonstring_key(self):
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({1: "x"})

    def test_04_expression_binder_ignores_envelope(self):
        program = make_demo_program(4)
        marked = deepcopy(program)
        marked["_contextmark"] = {"x": 1}
        self.assertEqual(expression_binder(program), expression_binder(marked))

    def test_05_threshold_binder_ignores_both_carriers(self):
        program = make_demo_program(4)
        marked = deepcopy(program)
        marked["_contextmark"] = {"x": 1}
        marked[CARRIER_FIELD] = [{"x": 2}]
        self.assertEqual(threshold_binder(program), threshold_binder(marked))


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.key = hashlib.sha256(b"key").digest()
        self.payload = hashlib.sha256(b"payload").hexdigest()
        self.program = make_demo_program(4)
        self.backend = AuthenticatedEnvelopeBackend(expression_binder)

    def test_06_envelope_correctness(self):
        artifact = self.backend.mark(self.key, self.program, self.payload)
        self.assertEqual(self.backend.read(self.key, artifact), self.payload)

    def test_07_envelope_wrong_key_rejects(self):
        artifact = self.backend.mark(self.key, self.program, self.payload)
        self.assertIsNone(self.backend.read(b"0" * 32, artifact))

    def test_08_envelope_tag_tamper_rejects(self):
        artifact = self.backend.mark(self.key, self.program, self.payload)
        artifact["_contextmark"]["tag"] = "0" * 64
        self.assertIsNone(self.backend.read(self.key, artifact))

    def test_09_envelope_host_tamper_rejects(self):
        artifact = self.backend.mark(self.key, self.program, self.payload)
        artifact["module"] = "other"
        self.assertIsNone(self.backend.read(self.key, artifact))

    def test_10_envelope_deletion_is_negative_control(self):
        artifact = self.backend.mark(self.key, self.program, self.payload)
        artifact.pop("_contextmark")
        self.assertIsNone(self.backend.read(self.key, artifact))

    def test_envelope_full_artifact_canonicalization_rejects_hidden_float(self):
        artifact = self.backend.mark(self.key, self.program, self.payload)
        # The expression binder erases this field.  The reader must nevertheless
        # reject the noncanonical complete artifact before binder evaluation.
        artifact["_threshold_carriers"] = [1.5]
        self.assertIsNone(self.backend.read(self.key, artifact))


class ThresholdTests(unittest.TestCase):
    def setUp(self):
        self.key = hashlib.sha256(b"threshold-key").digest()
        self.payload = hashlib.sha256(b"threshold-payload").digest()
        self.program = make_demo_program(4)
        self.artifact = threshold_mark(self.key, self.program, self.payload, n=5, t=3)

    def test_11_threshold_correctness(self):
        self.assertEqual(threshold_read(self.key, self.artifact), self.payload)

    def test_12_threshold_two_carriers_fail(self):
        candidate = deepcopy(self.artifact)
        candidate[CARRIER_FIELD] = candidate[CARRIER_FIELD][:2]
        self.assertIsNone(threshold_read(self.key, candidate))

    def test_13_threshold_three_carriers_pass(self):
        candidate = deepcopy(self.artifact)
        candidate[CARRIER_FIELD] = candidate[CARRIER_FIELD][:3]
        self.assertEqual(threshold_read(self.key, candidate), self.payload)

    def test_14_threshold_wrong_host_rejects(self):
        candidate = deepcopy(self.artifact)
        candidate["module"] = "other"
        self.assertIsNone(threshold_read(self.key, candidate))

    def test_15_threshold_wrong_key_rejects(self):
        self.assertIsNone(threshold_read(b"x" * 32, self.artifact))

    def test_16_threshold_duplicate_slot_does_not_count_twice(self):
        candidate = deepcopy(self.artifact)
        candidate[CARRIER_FIELD] = [deepcopy(candidate[CARRIER_FIELD][0])] * 3
        self.assertIsNone(threshold_read(self.key, candidate))

    def test_17_threshold_public_authorization_accepts_three_exact(self):
        candidate = deepcopy(self.artifact)
        candidate[CARRIER_FIELD] = candidate[CARRIER_FIELD][1:4]
        self.assertTrue(public_authorized_derivative(self.artifact, candidate, threshold=3))

    def test_18_threshold_public_authorization_rejects_two(self):
        candidate = deepcopy(self.artifact)
        candidate[CARRIER_FIELD] = candidate[CARRIER_FIELD][:2]
        self.assertFalse(public_authorized_derivative(self.artifact, candidate, threshold=3))

    def test_19_threshold_public_authorization_ignores_damage_but_counts_exact_retention(self):
        candidate = deepcopy(self.artifact)
        candidate[CARRIER_FIELD][0]["tag"] = "0" * 64
        # Four unchanged positions remain: both robustness and authorization hold.
        self.assertTrue(public_authorized_derivative(self.artifact, candidate, threshold=3))

    def test_20_threshold_multiple_payloads_select_canonical_valid_candidate(self):
        second = hashlib.sha256(b"second").digest()
        mixed = threshold_mark(self.key, self.artifact, second, n=5, t=3)
        candidates = read_candidates(self.key, mixed)
        self.assertEqual(len(candidates), 2)
        self.assertIn(threshold_read(self.key, mixed), {self.payload, second})

    def test_21_threshold_adapter_roundtrip(self):
        adapter = ThresholdCarrierAdapter(n=5, t=3)
        payload_hex = self.payload.hex()
        artifact = adapter.mark(self.key, self.program, payload_hex)
        self.assertEqual(adapter.read(self.key, artifact), payload_hex)

    def test_22_threshold_full_campaign(self):
        report = threshold_audit()
        self.assertTrue(report["passed"])
        self.assertEqual(report["deletion_cases"], 32)
        self.assertEqual(report["single_mutation_cases"], 25)
        self.assertTrue(report["single_mutations_all_still_read"])
        self.assertEqual(report["two_contributor_cells"], 256)
        self.assertEqual(report["three_contributor_cells"], 4096)
        self.assertEqual(report["coalition_cells"], 4352)
        self.assertEqual(report["coalition_trace_mismatches"], 0)
        self.assertEqual(report["coalition_canonical_selection_mismatches"], 0)

    def test_threshold_checker_rejects_nonempty_expected_but_empty_reader(self):
        report = _candidate_selection_check([self.payload], [], None)
        self.assertFalse(report["passed"])
        self.assertFalse(report["candidate_set_matches"])

    def test_threshold_checker_rejects_empty_expected_but_nonempty_reader(self):
        report = _candidate_selection_check([], [(payload_commitment(self.payload), self.payload)], self.payload)
        self.assertFalse(report["passed"])
        self.assertFalse(report["candidate_set_matches"])

    def test_threshold_checker_rejects_wrong_scalar_contributor(self):
        second = hashlib.sha256(b"second-checker").digest()
        actual = sorted(
            [(payload_commitment(self.payload), self.payload), (payload_commitment(second), second)],
            key=lambda item: item[0],
        )
        wrong = actual[-1][1]
        report = _candidate_selection_check([self.payload, second], actual, wrong)
        self.assertFalse(report["passed"])
        self.assertTrue(report["candidate_set_matches"])
        self.assertFalse(report["canonical_selection_matches"])

    def test_compiled_trace_checker_rejects_missing_expected_context(self):
        expected = ["01" * 32]
        report = _context_trace_check(expected, [], None)
        self.assertFalse(report["passed"])
        self.assertFalse(report["trace_set_matches"])


class CompilerTests(unittest.TestCase):
    def test_23_one_stage_roundtrip(self):
        compiler = ContextMarkCompiler.deterministic(["builder"], chain_id="one")
        chain, artifact = compiler.issue([], make_demo_program(4), actor="builder", operation="compile", metadata={"issue_id": "x"})
        self.assertTrue(compiler.verify(chain, artifact))

    def test_24_three_stage_roundtrip(self):
        compiler, chain, artifact, _ = three_stage_fixture(chain_id="three")
        self.assertEqual(len(chain), 3)
        self.assertTrue(compiler.verify(chain, artifact))

    def test_25_signed_field_tamper_rejects(self):
        compiler, chain, artifact, _ = three_stage_fixture(chain_id="tamper")
        chain[1]["operation"] = "other"
        self.assertFalse(compiler.verify(chain, artifact))

    def test_26_parent_splice_rejects(self):
        c1, chain1, artifact1, _ = three_stage_fixture(chain_id="splice")
        c2 = ContextMarkCompiler.deterministic(["builder", "reviewer", "packager"], seed=20260718, chain_id="splice")
        session = c2.begin_session(make_demo_program(33))
        chain2, artifact2 = session.append(actor="builder", operation="compile", metadata={"issue_id": "other-0"})
        chain2, artifact2 = session.append(actor="reviewer", operation="review", metadata={"issue_id": "other-1"})
        chain2, artifact2 = session.append(actor="packager", operation="package", metadata={"issue_id": "other-2"})
        candidate = [deepcopy(chain1[0]), deepcopy(chain2[1]), deepcopy(chain2[2])]
        self.assertFalse(c1.verify(candidate, artifact2))

    def test_27_reordered_chain_rejects(self):
        compiler, chain, artifact, _ = three_stage_fixture(chain_id="reorder")
        candidate = [chain[1], chain[0], chain[2]]
        self.assertFalse(compiler.verify(candidate, artifact))

    def test_28_wrong_tip_artifact_rejects(self):
        compiler, chain, artifact, artifacts = three_stage_fixture(chain_id="wrong-tip")
        self.assertFalse(compiler.verify(chain, artifacts[0]))

    def test_29_exact_request_retry_returns_identical_output(self):
        compiler = ContextMarkCompiler.deterministic(["builder"], chain_id="retry")
        args = dict(parent_chain=[], program=make_demo_program(4), actor="builder", operation="compile", metadata={"issue_id": "x"})
        first = compiler.issue(**args)
        second = compiler.issue(**args)
        self.assertEqual(first, second)

    def test_30_context_alias_rejects(self):
        report = coarse_binder_alias_witness()
        self.assertTrue(report["same_binder_different_program_rejected"])

    def test_31_unknown_actor_rejects(self):
        compiler = ContextMarkCompiler.deterministic(["builder"], chain_id="actor")
        with self.assertRaises(ContextMarkError):
            compiler.issue([], make_demo_program(4), actor="mallory", operation="compile")

    def test_32_empty_chain_verification_rejects(self):
        compiler = ContextMarkCompiler.deterministic(["builder"], chain_id="empty")
        self.assertFalse(compiler.verify([], make_demo_program(4)))

    def test_33_malformed_signature_encoding_rejects(self):
        compiler, chain, artifact, _ = three_stage_fixture(chain_id="sig-encoding")
        chain[-1]["signature"] = chain[-1]["signature"].upper()
        self.assertFalse(compiler.verify(chain, artifact))

    def test_34_manifest_serialization_is_canonical(self):
        compiler, chain, _artifact, _ = three_stage_fixture(chain_id="manifest")
        self.assertEqual(compiler.serialize_manifest(chain), canonical_bytes(chain))

    def test_35_negative_control(self):
        report = negative_control()
        self.assertTrue(report["accepted_before"])
        self.assertFalse(report["accepted_after_deletion"])
        self.assertTrue(report["binder_equal"])

    def test_36_threshold_backend_compiler_integration(self):
        adapter = ThresholdCarrierAdapter(n=5, t=3)
        compiler = ContextMarkCompiler.deterministic(
            ["builder"], chain_id="threshold-integration", binder=threshold_binder, backend=adapter
        )
        chain, artifact = compiler.issue([], make_demo_program(4), actor="builder", operation="compile", metadata={"issue_id": "t"})
        self.assertTrue(compiler.verify(chain, artifact))

    def test_public_verifier_converts_binder_runtime_error_to_rejection(self):
        compiler = ContextMarkCompiler.deterministic(["builder"], chain_id="binder-runtime")
        chain, artifact = compiler.issue([], make_demo_program(4), actor="builder", operation="compile")
        def failing_binder(_artifact):
            raise RuntimeError("injected binder failure")
        compiler.binder = failing_binder
        result = compiler.verify_detailed(chain, artifact)
        self.assertFalse(result.accepted)
        self.assertIn("injected binder failure", result.reason)

    def test_public_verifier_converts_reader_runtime_error_to_rejection(self):
        compiler = ContextMarkCompiler.deterministic(["builder"], chain_id="reader-runtime")
        chain, artifact = compiler.issue([], make_demo_program(4), actor="builder", operation="compile")
        def failing_reader(_key, _artifact):
            raise RuntimeError("injected reader failure")
        compiler.backend.read = failing_reader
        result = compiler.verify_detailed(chain, artifact)
        self.assertFalse(result.accepted)
        self.assertIn("injected reader failure", result.reason)

    def test_37_record_limit_rejects(self):
        compiler = ContextMarkCompiler.deterministic(["builder"], chain_id="limit", max_records=1)
        chain, artifact = compiler.issue([], make_demo_program(4), actor="builder", operation="compile")
        with self.assertRaises(ContextMarkError):
            compiler.issue(chain, artifact, actor="builder", operation="again")

    def test_38_context_precedes_signature_and_signature_authenticates_context(self):
        compiler = ContextMarkCompiler.deterministic(["builder"], chain_id="context-order")
        chain, artifact = compiler.issue([], make_demo_program(4), actor="builder", operation="compile")
        record = chain[0]
        unsigned = compiler._unsigned(record)
        self.assertEqual(record["context"], compiler._context_digest(unsigned))
        compiler.actor_public_keys["builder"].verify(
            bytes.fromhex(record["signature"]),
            compiler._signature_message(unsigned, record["context"]),
        )
        altered = deepcopy(chain)
        altered[0]["signature"] = ("0" if record["signature"][0] != "0" else "1") + record["signature"][1:]
        self.assertEqual(altered[0]["context"], compiler._context_digest(compiler._unsigned(altered[0])))
        self.assertFalse(compiler.verify(altered, artifact))


class RegistrySessionTests(unittest.TestCase):
    def test_39_private_append_matches_exported_state_and_verifies(self):
        actors = ["builder", "reviewer", "packager"]
        compiler = ContextMarkCompiler.deterministic(actors, chain_id="private-append")
        session = compiler.begin_session(make_demo_program(8))
        for index, actor in enumerate(actors):
            context = session.append_private(
                actor=actor,
                operation=f"stage-{index}",
                metadata={"issue_id": f"p-{index}"},
            )
            self.assertEqual(context, session.current_parent_context)
        chain, artifact = session.snapshot()
        self.assertEqual(len(chain), 3)
        self.assertTrue(compiler.verify(chain, artifact))
        self.assertEqual(chain[-1]["context"], session.current_parent_context)

    def test_40_terminal_failure_audit(self):
        self.assertTrue(terminal_failure_audit()["passed"])

    def test_41_resume_continuity_audit(self):
        self.assertTrue(resume_continuity_audit()["passed"])

    def test_42_snapshot_authentication_rejects_tamper(self):
        compiler = ContextMarkCompiler.deterministic(["builder"], chain_id="snapshot")
        compiler.issue([], make_demo_program(4), actor="builder", operation="compile")
        snapshot = compiler.export_registry_snapshot()
        snapshot["entry_count"] = 0
        restored = ContextMarkCompiler.deterministic(["builder"], chain_id="snapshot")
        with self.assertRaises(ContextMarkError):
            restored.restore_registry_snapshot(snapshot)

    def test_43_snapshot_restore_roundtrip(self):
        compiler = ContextMarkCompiler.deterministic(["builder"], chain_id="restore")
        chain, artifact = compiler.issue([], make_demo_program(4), actor="builder", operation="compile")
        snapshot = compiler.export_registry_snapshot()
        restored = ContextMarkCompiler.deterministic(["builder"], chain_id="restore")
        restored.restore_registry_snapshot(snapshot)
        self.assertTrue(restored.verify(chain, artifact))

    def test_44_nonempty_issue_without_registry_rejects(self):
        source = ContextMarkCompiler.deterministic(["builder"], chain_id="no-reg")
        chain, artifact = source.issue([], make_demo_program(4), actor="builder", operation="compile")
        fresh = ContextMarkCompiler.deterministic(["builder"], chain_id="no-reg")
        with self.assertRaises(ContextMarkError):
            fresh.issue(chain, artifact, actor="builder", operation="package")

    def test_45_nonempty_resume_without_registry_rejects(self):
        source = ContextMarkCompiler.deterministic(["builder"], chain_id="no-resume")
        chain, artifact = source.issue([], make_demo_program(4), actor="builder", operation="compile")
        fresh = ContextMarkCompiler.deterministic(["builder"], chain_id="no-resume")
        with self.assertRaises(ContextMarkError):
            fresh.begin_session(chain=chain, artifact=artifact)

    def test_46_session_stale_parent_rejects(self):
        compiler = ContextMarkCompiler.deterministic(["builder"], chain_id="stale")
        session = compiler.begin_session(make_demo_program(4))
        session.append(actor="builder", operation="compile")
        with self.assertRaises(ContextMarkError):
            session.append(actor="builder", operation="again", expected_parent_context="00" * 32)

    def test_47_session_snapshot_isolation(self):
        compiler = ContextMarkCompiler.deterministic(["builder"], chain_id="isolation")
        session = compiler.begin_session(make_demo_program(4))
        chain, artifact = session.append(actor="builder", operation="compile")
        chain[0]["operation"] = "mutated"
        artifact["module"] = "mutated"
        saved_chain, saved_artifact = session.snapshot()
        self.assertNotEqual(saved_chain[0]["operation"], "mutated")
        self.assertNotEqual(saved_artifact["module"], "mutated")


class BoundCalibrationTests(unittest.TestCase):
    def test_48_theorem_bounds_inside_unit_interval(self):
        rates = PrimitiveRates()
        for game in ("removal", "nontransfer", "unforgeability", "collusion"):
            self.assertTrue(0.0 <= theorem_bound(game, 10, 40, rates) <= 1.0)

    def test_49_theorem_dominates_independent_model(self):
        rates = PrimitiveRates()
        for game in ("removal", "nontransfer", "unforgeability", "collusion"):
            self.assertGreaterEqual(theorem_bound(game, 8, 32, rates), independent_model(game, 8, 32, rates))

    def test_50_first_hit_equals_product(self):
        hazards = [0.1, 0.2, 0.05]
        self.assertAlmostEqual(first_hit_probability(hazards), fixed_schedule_product(hazards))

    def test_51_ledger_dominates_first_hit(self):
        hazards = [0.1, 0.2, 0.05]
        self.assertGreaterEqual(adaptive_ledger_certificate(0.0, hazards), first_hit_probability(hazards))

    def test_52_evidence_conditioned_bound(self):
        self.assertAlmostEqual(evidence_conditioned_bound(0.1, calibration_errors=[0.02, 0.03], key_switch_loss=0.01), 0.16)

    def test_evidence_conditioned_bound_caps_nonprobability_certificate(self):
        self.assertEqual(evidence_conditioned_bound(1.5, calibration_errors=[0.02], key_switch_loss=0.01), 1.0)
        with self.assertRaises(ValueError):
            evidence_conditioned_bound(-0.1)

    def test_53_conditional_kernel_shift(self):
        self.assertAlmostEqual(conditional_kernel_shift(0.1, 1.5, 0.02), 0.17)

    def test_54_exact_union_matches_closed_form(self):
        probabilities = [0.01, 0.02, 0.03, 0.04]
        exact, states, _ = enumerate_union_probability(probabilities)
        self.assertEqual(states, 16)
        self.assertAlmostEqual(exact, closed_form_union(probabilities), places=14)

    def test_55_query_caps(self):
        caps = query_caps(4.0, 0.01, PrimitiveRates())
        self.assertTrue(all(value is None or value >= 0 for value in caps.values()))

    def test_56_clopper_pearson_zero_wins(self):
        upper = clopper_pearson_upper(0, 10, 0.05)
        self.assertAlmostEqual(upper, 1 - 0.05 ** 0.1, places=12)

    def test_57_spending_schedule_telescopes(self):
        total = sum(spending_alpha(t, 0.05) for t in range(1, 100000))
        self.assertLess(total, 0.05)
        self.assertGreater(total, 0.049999)

    def test_58_repeated_look_fixed_inflates(self):
        fixed, anytime = repeated_look_noncoverage(0.5, horizon=64, alpha=0.05)
        self.assertGreater(fixed, 0.1)
        self.assertLessEqual(anytime, 0.05 + 1e-12)

    def test_59_coverage_grid(self):
        rows = coverage_grid([0.1, 0.5, 0.9], horizon=16, alpha=0.05)
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row["anytime_noncoverage"] <= 0.05 + 1e-12 for row in rows))

    def test_60_equal_marginal_counterexample(self):
        row = equal_marginal_history_counterexample()
        self.assertTrue(row["equal_unconditional_challenge_marginal"])
        self.assertEqual(row["deployment_failure_probability"], 1.0)


class FiniteModelCampaignTests(unittest.TestCase):
    def test_61_omission_matrix(self):
        report = validate_omission_matrix(omission_matrix())
        self.assertTrue(report["valid"])
        self.assertEqual(report["row_count"], 42)

    def test_62_safeguard_lattice(self):
        report = validate_safeguard_lattice(safeguard_lattice())
        self.assertTrue(report["valid"])
        self.assertEqual(report["row_count"], 384)

    def test_63_architecture_baseline_counts(self):
        rows = baseline_matrix()
        counts = []
        for name in ("detached_records", "host_bound_owner_mark", "signed_owner_mark", "context_mark_without_parents", "complete"):
            counts.append(sum(row["attack_succeeds"] for row in rows if row["configuration"] == name))
        self.assertEqual(counts, [4, 4, 3, 1, 0])

    def test_64_mutation_campaign_size_and_rejection(self):
        rows = mutation_campaign()
        self.assertEqual(len(rows), 47)
        self.assertTrue(all(row["rejected"] for row in rows))

    def test_65_saturation_boundary(self):
        rates = PrimitiveRates(*(0.5 for _ in range(9)))
        for game in ("removal", "nontransfer", "unforgeability", "collusion"):
            self.assertEqual(theorem_bound(game, 4, 4, rates), 1.0)


if __name__ == "__main__":
    unittest.main()
