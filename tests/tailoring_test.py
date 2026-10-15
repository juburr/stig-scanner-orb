"""Tailoring inheritance, identity, selection evidence and artifact contracts."""

import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import os
import subprocess
import unittest
import xml.etree.ElementTree as ET

import checklist_test as common
from checklist_test import MOD, X, P, H, fixture
from skeleton_test import skeleton

SCAN = common.ROOT / "src/scripts/scan.sh"
CODE = SCAN.read_text().split("<<'PY_TAILORING'\n", 1)[1].split("\nPY_TAILORING\n", 1)[0]
PRE = {"__name__": "tailoring_tests"}
exec(compile(CODE, str(SCAN), "exec"), PRE)
CUSTOM = "xccdf_org.example_profile_custom"
VALUE = "xccdf_org.example_value_minimum"


def tailoring(profile=CUSTOM, base=P):
    root = ET.Element(X + "Tailoring", id="xccdf_org.example_tailoring_test")
    ET.SubElement(root, X + "benchmark", href="ssg-rhel9-ds.xml")
    ET.SubElement(root, X + "version", time="2026-10-14T00:00:00Z").text = "1"
    prof = ET.SubElement(root, X + "Profile", id=profile, extends=base)
    ET.SubElement(prof, X + "title").text = "Test customized STIG"
    ET.SubElement(prof, X + "select", idref="two", selected="false")
    ET.SubElement(prof, X + "set-value", idref=VALUE).text = "18"
    return root


def source():
    root = fixture([("one", 1, "pass", ()), ("two", 2, "pass", ())])
    value = ET.SubElement(root, X + "Value", id=VALUE)
    ET.SubElement(value, X + "value").text = "15"
    ET.SubElement(value, X + "value", selector="long").text = "20"
    rule = next(root.iter(X + "Rule"))
    check = ET.SubElement(rule, X + "check", system="test")
    ET.SubElement(check, X + "check-export", **{"value-id": VALUE, "export-name": "minimum"})
    return root


class TailoringTests(unittest.TestCase):
    setUp = common.ChecklistTests.setUp
    prepare = common.ChecklistTests.prepare
    save_plan = common.ChecklistTests.save_plan
    generate = common.ChecklistTests.generate
    rows = common.ChecklistTests.rows
    summary = common.ChecklistTests.summary

    def preflight(self, tail=None, ds=None):
        self.tail_path = self.out / "tailoring.xml"
        self.ds_path = self.out / "datastream.xml"
        self.tail_path.write_bytes(ET.tostring(tail if tail is not None else tailoring()))
        self.ds_path.write_bytes(ET.tostring(ds if ds is not None else source()))
        return PRE["prepare"](str(self.tail_path), str(self.ds_path), CUSTOM)

    def save_meta(self, meta):
        raw = json.dumps(meta).encode()
        (self.out / "tailoring-meta.json").write_bytes(raw)
        self.plan.update(
            tailoring_file=str(self.tail_path),
            tailoring_sha256=meta["sha256"],
            tailoring_profile=CUSTOM,
            tailoring_meta_sha256=hashlib.sha256(raw).hexdigest(),
        )
        self.save_plan()

    def tailored(self):
        ds = source()
        self.prepare(ds)  # Register the STOCK profile's selection, never the tailored selection.
        meta = self.preflight(ds=ds)
        meta["datastream_sha256"] = H  # Synthetic release-table key, isolated by the shared harness.
        tr = ds.find(X + "TestResult")
        tr.find(X + "profile").set("idref", CUSTOM)
        tr.findall(X + "rule-result")[1].find(X + "result").text = "notselected"
        ET.SubElement(tr, X + "set-value", idref=VALUE).text = "18"
        self.plan["profile"] = CUSTOM
        self.prepare(ds, register=False)
        self.save_meta(meta)
        return ds, meta

    def save_skeleton(self):
        path = self.out / "manual.xml"
        path.write_bytes(ET.tostring(skeleton()))
        return "--stig-xccdf-path=" + str(path)

    def test_parameter_errors_precede_docker_and_output_cleanup(self):
        marker = self.out / "checklist-meta.json"
        marker.write_text("original evidence")
        for file, profile in [
            ("tailoring.xml", ""),
            ("path\nprofile=injected", CUSTOM),
            ("tailoring.xml", CUSTOM + "\nextra=value"),
        ]:
            env = dict(
                os.environ,
                PARAM_IMAGE="unused:test",
                PARAM_OUTPUT_DIR=str(self.out),
                PARAM_TAILORING_FILE=file,
                PARAM_PROFILE_ID=profile,
            )
            result = subprocess.run(["bash", str(SCAN)], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("ERROR:", result.stderr)
            self.assertEqual(marker.read_text(), "original evidence")

    def test_complete_tailored_skeleton_and_exported_evidence(self):
        _, meta = self.tailored()
        self.tail_path.unlink()  # Conversion cannot reopen the caller's input.
        rc, result = self.generate(self.save_skeleton())
        self.assertEqual((rc, result["outcome"]), (0, "generated"), result)
        self.assertEqual(result["tailoring"], meta)
        rows = {v["group_id"]: v for v in self.rows()}
        self.assertEqual(rows["V-1"]["status"], "not_a_finding")
        self.assertIn("'18' (resolved by OpenSCAP)", rows["V-1"]["finding_details"])
        self.assertEqual(rows["V-2"]["status"], "not_reviewed")
        self.assertIn("Deselected by tailoring " + CUSTOM, rows["V-2"]["comments"])
        for row in rows.values():
            self.assertIn(meta["sha256"], row["finding_details"])
        self.assertEqual(self.summary("require").returncode, 0)
        prov = json.loads((self.out / "provenance.json").read_text())
        self.assertEqual(prov["tailoring"]["sha256"], meta["sha256"])
        self.assertEqual(prov["tailoring"]["profile_id"], CUSTOM)
        self.assertIn("tailoring-sha256:", (self.out / "summary.txt").read_text())
        ckl = ET.parse(self.out / "checklist.ckl")
        self.assertIn("Tailored value", ckl.find(".//FINDING_DETAILS").text)

    def test_ssg_only_omits_deselected_row(self):
        self.tailored()
        res = MOD["parse_results"](
            io.BytesIO((self.out / "results.xml").read_bytes()),
            MOD["read_tailoring"](self.plan, str(self.out / "scan-plan.env")),
        )
        _, rows = MOD["build_model"](res, self.plan, "amd64", self.entry[3])
        self.assertEqual(len(rows), 1)
        self.assertIn("Tailored value", rows[0]["finding_details"])
        rc, result = self.generate()
        self.assertEqual((rc, result["outcome"]), (0, "skipped"))
        self.assertIn("bundled DISA data", result["reason"])

    def test_partial_deselection_cannot_certify_the_whole_requirement(self):
        ds, meta = self.tailored()
        rule = list(ds.iter(X + "Rule"))[1]
        for ref in rule.findall(X + "reference"):
            if ref.get("href") == MOD["HREF_RULE"]:
                ref.text = "SV-1r1_rule"
            elif ref.get("href") == MOD["HREF_VULN"]:
                ref.text = "V-1"
        # Source and result references stay identical; only one of two checks ran.
        original = copy.deepcopy(ds)
        original.find(X + "TestResult").find(X + "profile").set("idref", P)
        original.find(X + "TestResult").findall(X + "rule-result")[1].find(X + "result").text = "pass"
        meta = self.preflight(ds=original)
        meta["datastream_sha256"] = H
        self.prepare(ds, register=False)
        self.save_meta(meta)
        rc, result = self.generate(self.save_skeleton())
        self.assertEqual(rc, 0, result)
        row = self.rows()[0]
        self.assertEqual(row["status"], "not_reviewed")
        self.assertIn("one: pass", row["finding_details"])
        self.assertIn("complete requirement", row["finding_details"])
        self.assertEqual(result["not_reviewed_by_reason"]["tailoring_deselected"], 1)

    def test_tailored_cis_cannot_claim_stig(self):
        _, meta = self.tailored()
        meta["base_profile_id"] = "xccdf_org.example_profile_cis"
        self.save_meta(meta)
        rc, result = self.generate(self.save_skeleton())
        self.assertEqual((rc, result["outcome"]), (0, "skipped"))

    def test_original_stock_selection_check_still_applies(self):
        ds = source()
        self.prepare(ds)
        ds.find(X + "TestResult").findall(X + "rule-result")[1].find(X + "result").text = "notselected"
        self.prepare(ds, register=False)
        rc, result = self.generate()
        self.assertEqual((rc, result["outcome"]), (1, "failed"))
        self.assertIn("selects", result["reason"])

    def test_changed_mapping_missing_rule_and_changed_value_fail_closed(self):
        for change in ("mapping", "missing", "duplicate_value"):
            with self.subTest(change=change):
                ds, _ = self.tailored()
                rule = next(ds.iter(X + "Rule"))
                if change == "mapping":
                    rule.find(X + "reference").text = "SV-1r999_rule"
                elif change == "missing":
                    ds.remove(ds.find(X + "Group"))
                else:
                    ET.SubElement(ds.find(X + "TestResult"), X + "set-value", idref=VALUE).text = "15"
                self.prepare(ds, register=False)
                rc, result = self.generate(self.save_skeleton())
                self.assertEqual((rc, result["outcome"]), (1, "failed"), result)
                self.assertFalse((self.out / "checklist.cklb").exists())

    def test_hash_missing_metadata_and_partial_provenance_fail(self):
        for change in ("hash", "missing", "partial", "identity"):
            with self.subTest(change=change):
                _, meta = self.tailored()
                if change == "hash":
                    (self.out / "tailoring-meta.json").write_text("{}")
                elif change == "missing":
                    (self.out / "tailoring-meta.json").unlink()
                elif change == "partial":
                    del self.plan["tailoring_meta_sha256"]
                    self.save_plan()
                else:
                    meta["datastream_sha256"] = "2" * 64
                    self.save_meta(meta)
                rc, result = self.generate()
                self.assertEqual((rc, result["outcome"]), (1, "failed"), result)

    def test_refine_value_and_nested_profile_inheritance(self):
        root = tailoring()
        profile = root.find(X + "Profile")
        profile.set("id", "xccdf_org.example_profile_parent")
        profile.remove(profile.find(X + "set-value"))
        ET.SubElement(profile, X + "refine-value", idref=VALUE, selector="long")
        child = ET.SubElement(root, X + "Profile", id=CUSTOM, extends=profile.get("id"))
        ET.SubElement(child, X + "select", idref="two", selected="true")
        meta = self.preflight(root)
        self.assertEqual(meta["values"][VALUE]["value"], "20")
        self.assertEqual(meta["deselected_rules"], [])
        self.assertEqual(meta["base_profile_id"], P)

    def test_refinement_without_selector_and_coexisting_set_value(self):
        root = tailoring()
        prof = root.find(X + "Profile")
        ET.SubElement(prof, X + "refine-value", idref=VALUE, operator="greater than or equal")
        meta = self.preflight(root)
        self.assertEqual(len(meta["values"][VALUE]["directives"]), 2)
        self.assertIsNone(meta["values"][VALUE]["value"])
        self.assertEqual(meta["values"][VALUE]["operator"], "greater than or equal")

    def test_unknown_profiles_cycles_shadowing_and_duplicate_ids(self):
        for change in ("missing", "cycle", "shadow", "duplicate"):
            root = tailoring()
            profile = root.find(X + "Profile")
            if change == "missing":
                profile.set("extends", "unknown")
            elif change == "cycle":
                profile.set("extends", CUSTOM)
            elif change == "shadow":
                profile.set("id", P)
            else:
                root.append(copy.deepcopy(profile))
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.preflight(root)

    def test_unknown_directives_and_duplicate_values_rejected(self):
        for change in ("unknown_rule", "unknown_value", "selector", "duplicate", "flag"):
            root = tailoring()
            prof = root.find(X + "Profile")
            if change == "unknown_rule":
                prof.find(X + "select").set("idref", "unknown")
            elif change == "unknown_value":
                prof.find(X + "set-value").set("idref", "unknown")
            elif change == "selector":
                prof.remove(prof.find(X + "set-value"))
                ET.SubElement(prof, X + "refine-value", idref=VALUE, selector="unknown")
            elif change == "duplicate":
                ET.SubElement(prof, X + "set-value", idref=VALUE).text = "20"
            else:
                prof.find(X + "select").set("selected", "perhaps")
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.preflight(root)

    def test_group_deselections_expand_to_the_actual_rules(self):
        root = tailoring()
        root.find(X + "Profile").find(X + "select").set("idref", "g-two")
        self.assertEqual(self.preflight(root)["deselected_rules"], ["two"])

    def test_group_and_child_flags_preserve_ancestor_selection_semantics(self):
        root = tailoring()
        profile = root.find(X + "Profile")
        profile.find(X + "select").set("idref", "g-two")
        ET.SubElement(profile, X + "select", idref="two", selected="true")
        self.assertEqual(self.preflight(root)["deselected_rules"], ["two"])
        root = tailoring()
        profile = root.find(X + "Profile")
        ET.SubElement(profile, X + "select", idref="g-two", selected="true")
        self.assertEqual(self.preflight(root)["deselected_rules"], ["two"])

    def test_wrong_benchmark_and_multiple_benchmarks_rejected(self):
        root = tailoring()
        root.find(X + "benchmark").set("id", "different")
        with self.assertRaises(ValueError):
            self.preflight(root)
        ds = ET.Element("collection")
        ds.extend([source(), source()])
        with self.assertRaises(ValueError):
            self.preflight(ds=ds)

    def test_dtd_encoding_and_size_bound_before_parse(self):
        self.preflight()
        for data in (
            b'<!DOCTYPE Tailoring [<!ENTITY a "test">]><Tailoring/>',
            "<Tailoring/>".encode("utf-16"),
            b"x" * ((16 << 20) + 1),
        ):
            self.tail_path.write_bytes(data)
            with self.assertRaises((ValueError, UnicodeError)):
                PRE["prepare"](str(self.tail_path), str(self.ds_path), CUSTOM)


if __name__ == "__main__":
    unittest.main(verbosity=2)
