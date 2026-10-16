"""Exercise independent quality/compliance policy through the public scripts."""
import itertools
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "src/scripts"


class ScanQualityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.out = Path(self.temp.name)
        # Isolate public parameters from the caller's environment.
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("PARAM_")}
        self.env["PARAM_OUTPUT_DIR"] = str(self.out)

    def prepare(self, statuses=("pass",), plan=None):
        benchmark = ET.Element("Benchmark", xmlns="http://checklists.nist.gov/xccdf/1.2")
        result = ET.SubElement(benchmark, "TestResult")
        for index, status in enumerate(statuses):
            rule = ET.SubElement(result, "rule-result", idref=f"rule_{index}")
            ET.SubElement(rule, "result").text = status
        (self.out / "results.xml").write_bytes(ET.tostring(benchmark))
        if plan is not None:
            (self.out / "scan-plan.env").write_text("".join(f"{k}={v}\n" for k, v in plan.items()))

    def run_script(self, name="summarize.sh", **params):
        return subprocess.run(
            ["bash", str(SCRIPTS / name)],
            env={**self.env, **{"PARAM_" + k.upper(): v for k, v in params.items()}},
            capture_output=True, text=True,
        )

    def gates(self):
        return json.loads((self.out / "provenance.json").read_text())["gates"]

    def test_gate_matrix(self):
        # Mixed scans must fail quality even though some checks evaluated.
        for statuses, finding, quality in itertools.product(
            (("pass",), ("fail",), ("pass", "error"), ("pass", "unknown"), ("fail", "error")),
            ("true", "false"), ("true", "false"),
        ):
            with self.subTest(statuses=statuses, finding=finding, quality=quality):
                self.prepare(statuses)
                compliance_failed = finding == "true" and "fail" in statuses
                quality_failed = quality == "true" and any(s in statuses for s in ("error", "unknown"))
                result = self.run_script(fail_on_finding=finding, fail_on_scan_error=quality)
                self.assertEqual(result.returncode, int(compliance_failed or quality_failed), result.stderr)
                gates = self.gates()
                self.assertEqual(gates["compliance"]["failed"], compliance_failed)
                self.assertEqual(gates["scan_quality"]["failed"], quality_failed)
                summary = (self.out / "summary.txt").read_text()
                for name, enabled, failed in (("compliance", finding, compliance_failed),
                                               ("scan-quality", quality, quality_failed)):
                    outcome = "disabled" if enabled == "false" else "failed" if failed else "passed"
                    self.assertIn(f"{name}-gate: {outcome}", summary)

    def test_quality_default_and_circleci_boolean_serialization(self):
        self.prepare(("pass", "error"))
        for value, expected in ((None, 1), ("1", 1), ("0", 0)):
            with self.subTest(value=value):
                params = {} if value is None else {"fail_on_scan_error": value}
                self.assertEqual(self.run_script(**params).returncode, expected)
        self.assertEqual(self.run_script(fail_on_scan_error="yes").returncode, 2)

    def test_ignore_list_only_waives_compliance_failures(self):
        self.prepare(("fail", "error", "unknown"))
        result = self.run_script(fail_on_finding="true", ignore_findings="rule_0,rule_1,rule_2")
        self.assertEqual(result.returncode, 1, result.stderr)
        gates = self.gates()
        self.assertFalse(gates["compliance"]["failed"])
        self.assertTrue(gates["scan_quality"]["failed"])
        self.assertEqual(gates["scan_quality"]["error_results"], 1)
        self.assertEqual(gates["scan_quality"]["unknown_results"], 1)
        summary = (self.out / "summary.txt").read_text()
        self.assertIn("[IGNORED] rule_0", summary)
        self.assertNotIn("[IGNORED] rule_1", summary)
        self.assertNotIn("[IGNORED] rule_2", summary)
        self.assertEqual(self.run_script(fail_on_finding="true", fail_on_scan_error="false",
                                         ignore_findings="rule_0").returncode, 0)

    def test_missing_inventory_fails_even_with_passing_rules(self):
        for family in ("dpkg", "rpm"):
            with self.subTest(family=family):
                self.prepare(plan={family + "_status": "missing", family + "_status_reason": "query failed"})
                result = self.run_script(ignore_findings="rule_0")
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(self.gates()["scan_quality"]["unavailable_inventories"], [family])
                self.assertIn("query failed", (self.out / "summary.txt").read_text())
                self.assertEqual(self.run_script(fail_on_scan_error="false").returncode, 0)
                self.assertFalse(self.gates()["scan_quality"]["enabled"])
                self.assertEqual(self.gates()["scan_quality"]["unavailable_inventories"], [family])

    def test_available_inventory_and_standalone_results_are_supported(self):
        for plan in (None, {"rpm_status": "available", "rpm_status_packages": "12"},
                     {"dpkg_status": "synthesized", "dpkg_status_packages": "12"}):
            with self.subTest(plan=plan):
                self.prepare(plan=plan)
                self.assertEqual(self.run_script().returncode, 0)
                self.assertEqual(self.gates()["scan_quality"]["unavailable_inventories"], [])

    def test_unevaluated_scan_gate_is_independent(self):
        for status in ("notapplicable", "notchecked", "notselected"):
            with self.subTest(status=status):
                self.prepare((status,))
                self.assertEqual(self.run_script(fail_on_scan_error="false").returncode, 1)
                self.assertEqual(self.run_script(require_evaluated_rules="false").returncode, 0)
        self.prepare(("error",))
        self.assertEqual(self.run_script(require_evaluated_rules="false").returncode, 1)
        self.assertEqual(self.run_script(require_evaluated_rules="false", fail_on_scan_error="false").returncode, 0)

    def test_deferred_quality_failure_preserves_evidence_and_is_enforced(self):
        self.prepare(("pass", "error"))
        (self.out / "report.html").write_text("scan report")
        original = (self.out / "results.xml").read_bytes()
        result = self.run_script(defer_gate="true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.gates()["scan_quality"]["failed"])
        self.assertEqual((self.out / "summary.txt.exit-code").read_text(), "1\n")
        self.assertEqual((self.out / "results.xml").read_bytes(), original)
        self.assertEqual((self.out / "report.html").read_text(), "scan report")
        self.assertEqual(self.run_script("enforce-gate.sh").returncode, 1)
        # A retry that opts out writes and enforces its own new decision.
        self.assertEqual(self.run_script(defer_gate="true", fail_on_scan_error="false").returncode, 0)
        self.assertEqual(self.run_script("enforce-gate.sh").returncode, 0)

    def test_checklist_policy_is_not_waived_by_quality_opt_out(self):
        self.prepare()
        self.assertEqual(self.run_script(checklist="require", fail_on_scan_error="false").returncode, 1)
        self.assertTrue(self.gates()["checklist"]["failed"])

    def test_invalid_or_missing_results_cannot_reuse_deferred_success(self):
        self.prepare()
        for invalid in (None, b"<broken", b"<Benchmark><TestResult/></Benchmark>"):
            with self.subTest(invalid=invalid):
                self.assertEqual(self.run_script(defer_gate="true").returncode, 0)
                if invalid is None:
                    (self.out / "results.xml").unlink()
                else:
                    (self.out / "results.xml").write_bytes(invalid)
                self.assertNotEqual(self.run_script(defer_gate="true", fail_on_scan_error="false").returncode, 0)
                self.assertFalse((self.out / "summary.txt.exit-code").exists())
                self.assertEqual(self.run_script("enforce-gate.sh").returncode, 2)
                self.prepare()


if __name__ == "__main__":
    unittest.main()
