"""Owned finite regressions for request recovery and risk-input domains."""
from __future__ import annotations
from copy import deepcopy
from dataclasses import replace
import unittest

from contextmark.bounds import PrimitiveRates, independent_model, query_caps, theorem_bound
from contextmark.canonical import canonical_bytes
from contextmark.compiler import ContextMarkCompiler, ContextMarkError, MarkingError, make_demo_program


class RegistryTranscriptRegression(unittest.TestCase):
    def compiler(self):
        return ContextMarkCompiler.deterministic(["builder"], chain_id="owned-recovery")

    def fixture(self):
        c = self.compiler()
        args = dict(parent_chain=[], program=make_demo_program(2), actor="builder", operation="compile")
        pair = c.issue(**args)
        return c, args, pair

    def authenticate_owned_snapshot(self, c, snapshot):
        # Use the fixture issuer's key to test semantic validation, not MAC
        # forgery. Such snapshots are outside the honest export language.
        snapshot["tag"] = c._registry_tag({k: v for k, v in snapshot.items() if k != "tag"})
        return snapshot

    def reject_atomically(self, c, snapshot):
        target = self.compiler()
        with self.assertRaises(ContextMarkError):
            target.restore_registry_snapshot(self.authenticate_owned_snapshot(c, snapshot))
        self.assertEqual(target.registry_status_counts(), (0, 0, 0))

    def test_restored_exact_retry_matches_immutable_output(self):
        c, args, pair = self.fixture()
        snapshot = c.export_registry_snapshot()
        target = self.compiler()
        target.restore_registry_snapshot(snapshot)
        self.assertEqual(target.issue(**args), pair)
        self.assertEqual(target.export_registry_snapshot(), snapshot)

    def test_inconsistent_request_identifier_rejects(self):
        c, _, _ = self.fixture()
        snapshot = c.export_registry_snapshot()
        snapshot["entries"][0]["request_id"] = "00" * 32
        self.reject_atomically(c, snapshot)

    def test_request_program_encoding_and_binder_are_checked(self):
        c, args, _ = self.fixture()
        changed = deepcopy(args["program"])
        changed["module"] = "different-owned-host"
        for raw in (b" " + canonical_bytes(args["program"]), canonical_bytes(changed)):
            with self.subTest(raw=raw[:12]):
                snapshot = c.export_registry_snapshot()
                snapshot["entries"][0]["request_program_hex"] = raw.hex()
                self.reject_atomically(c, snapshot)

    def test_signed_record_must_match_request(self):
        c, _, _ = self.fixture()
        snapshot = c.export_registry_snapshot()
        other_chain, _ = c.issue([], make_demo_program(2), actor="builder", operation="another-operation")
        snapshot["entries"][0]["record"] = other_chain[0]
        self.reject_atomically(c, snapshot)

    def test_successful_child_requires_retained_successful_parent(self):
        c, _, (chain, artifact) = self.fixture()
        c.issue(chain, artifact, actor="builder", operation="package")
        snapshot = c.export_registry_snapshot()
        snapshot["entries"] = [e for e in snapshot["entries"] if e["unsigned"]["index"] == 1]
        snapshot["attempted_contexts"] = [snapshot["entries"][0]["context"]]
        snapshot["entry_count"] = snapshot["attempted_context_count"] = 1
        self.reject_atomically(c, snapshot)

    def failed_fixture(self):
        c, _, (chain, artifact) = self.fixture()
        def fail(*_args):
            raise RuntimeError("owned synthetic backend failure")
        c.backend.mark = fail
        with self.assertRaises(MarkingError):
            c.issue(chain, artifact, actor="builder", operation="failed-package")
        return c, c.export_registry_snapshot()

    def test_failed_child_requires_retained_successful_parent(self):
        c, snapshot = self.failed_fixture()
        snapshot["entries"] = [e for e in snapshot["entries"] if e["status"] == "failed"]
        snapshot["attempted_contexts"] = [snapshot["entries"][0]["context"]]
        snapshot["entry_count"] = snapshot["attempted_context_count"] = 1
        self.reject_atomically(c, snapshot)

    def test_terminal_failure_language_and_exact_count_types(self):
        c, snapshot = self.failed_fixture()
        failed = next(e for e in snapshot["entries"] if e["status"] == "failed")
        failed["failure_code"] = ""
        self.reject_atomically(c, snapshot)
        c, _, _ = self.fixture()
        snapshot = c.export_registry_snapshot()
        snapshot["entry_count"] = True
        self.reject_atomically(c, snapshot)


class RiskInputRegression(unittest.TestCase):
    def test_budgets_require_nonnegative_exact_integers(self):
        invalid = (-1, True, 0.5, float("nan"), float("inf"))
        for value in invalid:
            for game in ("removal", "nontransfer", "unforgeability", "collusion"):
                for q, n in ((value, 0), (0, value)):
                    with self.subTest(game=game, q=q, n=n):
                        with self.assertRaises(ValueError):
                            theorem_bound(game, q, n, PrimitiveRates())
                        with self.assertRaises(ValueError):
                            independent_model(game, q, n, PrimitiveRates())
            with self.assertRaises(ValueError):
                theorem_bound("collusion", 0, 0, PrimitiveRates(), coalition_groups=value)

    def test_query_caps_validate_every_primitive_rate(self):
        for field in PrimitiveRates().as_dict():
            for value in (-0.1, 1.1, float("nan"), float("inf")):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError):
                        query_caps(4.0, 0.01, replace(PrimitiveRates(), **{field: value}))

    def test_query_caps_reject_nonfinite_record_ratio(self):
        for ratio in (-1.0, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                query_caps(ratio, 0.01, PrimitiveRates())

    def test_default_caps_are_maximal_and_zero_losses_are_uncapped(self):
        rates = PrimitiveRates()
        caps = query_caps(4, 0.01, rates)
        self.assertEqual(caps, dict(removal=333, nontransfer=2497, unforgeability=999, collusion=166))
        for game, count in caps.items():
            self.assertLessEqual(theorem_bound(game, count, 4 * count, rates), 0.01)
            self.assertGreater(theorem_bound(game, count + 1, 4 * (count + 1), rates), 0.01)
        zero = PrimitiveRates(**dict.fromkeys(rates.as_dict(), 0.0))
        self.assertTrue(all(value is None for value in query_caps(4, 0.01, zero).values()))


class ReproductionOutputRegression(unittest.TestCase):
    def test_declared_suite_size_matches_owned_test_sources(self):
        from pathlib import Path
        from suite_contract import EXPECTED_TESTS, source_inventory_valid, source_test_ids, test_output_valid

        root = Path(__file__).resolve().parents[1]
        ids = source_test_ids(root)
        self.assertEqual(len(ids), EXPECTED_TESTS)
        self.assertTrue(source_inventory_valid(root))

        def transcript(selected, ending="OK"):
            lines = [f"{name.rsplit('.', 1)[-1]} ({name}) ... ok" for name in selected]
            return "\n".join(lines) + f"\n\nRan {len(selected)} tests in 0.001s\n\n{ending}\n"

        complete = transcript(ids)
        self.assertTrue(test_output_valid(complete, 0, root))
        self.assertFalse(test_output_valid(complete, 1, root))
        self.assertFalse(test_output_valid(transcript(ids[1:]), 0, root))
        substituted = ids.copy()
        substituted[0] = "test_contextmark.CanonicalTests.test_substituted_fixture"
        self.assertFalse(test_output_valid(transcript(substituted), 0, root))
        self.assertFalse(test_output_valid(transcript(ids, "OK (skipped=1)"), 0, root))
        self.assertFalse(test_output_valid(transcript(ids, "FAILED (failures=1)"), 1, root))

    def test_exact_full_package_shape_bst_control_and_flat_mode(self):
        import hashlib
        import io
        import json
        from contextlib import redirect_stdout
        from pathlib import Path
        import shutil
        import sys
        import tempfile
        from unittest.mock import patch
        import verify_release as verifier

        source_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "packet"
            paper = root / "paper"
            artifact = root / "artifact"
            (artifact / "contextmark").mkdir(parents=True)
            (artifact / "tests").mkdir()
            (artifact / "results" / "raw").mkdir(parents=True)
            (artifact / "literature").mkdir()
            paper.mkdir()
            (artifact / "contextmark" / "__init__.py").write_text("", encoding="utf-8")
            for path in (source_root / "tests").glob("test_*.py"):
                shutil.copyfile(path, artifact / "tests" / path.name)
            text = "\\bstctlcite{authorDisplay}\\cite{real}\\bibliographystyle{IEEEtran}\n"
            (paper / "main.tex").write_text(text, encoding="utf-8")
            (paper / "references.bib").write_text(
                "@IEEEtranBSTCTL{authorDisplay, CTLdash_repeated_names={no}}\n"
                "@article{real, title={Owned fixture}}\n", encoding="utf-8")
            (artifact / "literature" / "reference-verification.csv").write_text(
                "citation_key\nreal\n", encoding="utf-8")
            (artifact / "citation_support.csv").write_text(
                "citation_key\nreal\n", encoding="utf-8")
            manifest = {
                "schema": "contextmark-run-manifest-v2",
                "entry_count": 1,
                "entries": [{
                    "base": "artifact",
                    "path": "contextmark/__init__.py",
                    "sha256": hashlib.sha256(b"").hexdigest(),
                }],
            }
            (artifact / "results" / "raw" / "run-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8")

            # This fixture checks package/citation structure, not PDF parsing.
            with patch.dict(sys.modules, {"fitz": None}):
                self.assertEqual(verifier.verify_full_package(root)["references"], 1)
                (root / "README.md").write_text("Optional navigation\n", encoding="utf-8")
                self.assertEqual(verifier.verify_full_package(root)["references"], 1)
                (root / "unrelated.txt").write_text("not a package root\n", encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "unexpected project-root entries"):
                    verifier.verify_full_package(root)
                (root / "unrelated.txt").unlink()
                (paper / "main.tex").write_text("\\cite{real}\\bibliographystyle{IEEEtran}\n", encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "control not consumed"):
                    verifier.verify_full_package(root)
                (paper / "main.tex").write_text(text.replace("{real}", "{real,authorDisplay}"), encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "control used as an ordinary citation"):
                    verifier.verify_full_package(root)
                (paper / "main.tex").write_text(text, encoding="utf-8")
                (paper / "references.bib").write_text(
                    "@IEEEtranBSTCTL{authorDisplay, CTLdash_repeated_names={no}}\n", encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "citation keys and bibliography differ"):
                    verifier.verify_full_package(root)
                (paper / "references.bib").write_text(
                    "@IEEEtranBSTCTL{authorDisplay, CTLdash_repeated_names={no}}\n"
                    "@article{real, title={Owned fixture}}\n", encoding="utf-8")
                (artifact / "literature" / "reference-verification.csv").write_text(
                    "citation_key\n", encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "reference review ledger mismatch"):
                    verifier.verify_full_package(root)
                (artifact / "literature" / "reference-verification.csv").write_text(
                    "citation_key\nreal\n", encoding="utf-8")
                (artifact / "citation_support.csv").write_text("citation_key\n", encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "local citation support keys mismatch"):
                    verifier.verify_full_package(root)
                (artifact / "citation_support.csv").write_text("citation_key\nreal\n", encoding="utf-8")
                self.assertEqual(verifier.classify_root(artifact)[0], "standalone_artifact")
                with patch.object(sys, "argv", ["verify_release.py", "--root", str(artifact),
                                                "--evidence-dir", str(artifact / "results"), "--skip-tests"]):
                    with redirect_stdout(io.StringIO()) as output:
                        verifier.main()
                self.assertEqual(json.loads(output.getvalue())["mode"], "standalone_artifact")

    def test_prepare_does_not_delete_existing_evidence(self):
        import run_experiments as driver
        from unittest.mock import MagicMock, patch
        output, raw, derived = MagicMock(), MagicMock(), MagicMock()
        output.exists.return_value = True
        output.iterdir.return_value = iter(["owned-existing-evidence"])
        raw.exists.return_value = derived.exists.return_value = False
        with patch.object(driver, "OUTPUT", output, create=True), patch.object(driver, "RAW", raw), patch.object(driver, "DERIVED", derived), patch.object(driver, "environment_record", side_effect=AssertionError("must not start a campaign")) as environment:
            with self.assertRaises(RuntimeError):
                driver.prepare_experiments()
        environment.assert_not_called()
        raw.mkdir.assert_not_called()
        derived.mkdir.assert_not_called()


if __name__ == "__main__":
    unittest.main()
