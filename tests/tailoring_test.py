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
            tailoring_profile=meta["profile_id"],
            tailoring_evaluated_sha256=meta["evaluated_sha256"],
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
        self.assertEqual(result["tailoring"]["sha256"], meta["sha256"])
        self.assertEqual(result["tailoring"]["metadata_sha256"], self.plan["tailoring_meta_sha256"])
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
        self.assertEqual(prov["profile"]["title"], meta["profile_title"])
        self.assertEqual(prov["tailoring"]["profile_title"], meta["profile_title"])
        self.assertIn("tailoring-sha256:", (self.out / "summary.txt").read_text())
        ckl = ET.parse(self.out / "checklist.ckl")
        self.assertIn("Tailored value", ckl.find(".//FINDING_DETAILS").text)

    def test_value_evidence_uses_recorded_checks_and_labels_uncertain_associations(self):
        for case in ("selected", "alternative", "ambiguous", "missing", "multiple"):
            with self.subTest(case=case):
                ds, meta = self.tailored()
                rule = next(ds.iter(X + "Rule"))
                selected = rule.find(X + "check")
                ET.SubElement(selected, X + "check-content-ref", href="checks.xml", name="selected")
                selected.set("selector", "chosen")
                other = ET.SubElement(rule, X + "check", system="test", selector="other")
                ET.SubElement(other, X + "check-content-ref", href="checks.xml", name="other")
                if case in ("alternative", "multiple", "ambiguous"):
                    export = selected.find(X + "check-export")
                    selected.remove(export)
                    other.append(export)
                if case == "ambiguous":
                    other.find(X + "check-content-ref").set("name", "selected")
                rr = ds.find(X + "TestResult").find(X + "rule-result")
                if case != "missing":
                    check = ET.SubElement(rr, X + "check", system="test")
                    ET.SubElement(check, X + "check-content-ref", href="checks.xml", name="selected")
                if case == "multiple":
                    rr = ET.SubElement(ds.find(X + "TestResult"), X + "rule-result", idref="one")
                    ET.SubElement(rr, X + "result").text = "pass"
                    check = ET.SubElement(rr, X + "check", system="test")
                    ET.SubElement(check, X + "check-content-ref", href="checks.xml", name="other")
                self.prepare(ds, register=False)
                rc, result = self.generate(self.save_skeleton())
                self.assertEqual((rc, result["outcome"]), (0, "generated"), result)
                details = self.rows()[0]["finding_details"]
                if case == "alternative":
                    self.assertNotIn("Tailored value " + VALUE, details)
                else:
                    self.assertIn("Tailored value " + VALUE, details)
                    self.assertIn("global TestResult evidence", details)
                    if case in ("missing", "ambiguous"):
                        self.assertIn("association with an executed check is not established", details)
                        self.assertNotIn("Export declared by recorded check", details)
                    else:
                        self.assertIn("Export declared by recorded check(s): one", details)

    def test_rule_refinement_requests_and_actual_result_properties_are_retained(self):
        ds, _ = self.tailored()
        root = tailoring()
        prof = root.find(X + "Profile")
        request = ET.SubElement(prof, X + "refine-rule", idref="one", role="unchecked", selector="alternate")
        ET.SubElement(request, X + "remark").text = "Site decision"
        ET.SubElement(prof, X + "refine-rule", idref="one", severity="low", weight="2.5")
        meta = self.preflight(root, ds)
        self.assertEqual(len(meta["rule_refinements"]["one"]["directives"]), 2)
        self.assertEqual(meta["rule_refinements"]["one"]["directives"][0]["remarks"], ["Site decision"])
        meta["datastream_sha256"] = H
        rr = ds.find(X + "TestResult/" + X + "rule-result")
        rr.set("role", "unchecked")
        rr.set("severity", "low")
        rr.set("weight", "2.5")
        rr.find(X + "result").text = "notchecked"
        check = ET.SubElement(rr, X + "check", system="test", selector="alternate")
        ET.SubElement(check, X + "check-content-ref", href="checks.xml", name="alternate")
        self.prepare(ds, register=False)
        self.save_meta(meta)
        rc, result = self.generate(self.save_skeleton())
        self.assertEqual((rc, result["outcome"]), (0, "generated"), result)
        row = self.rows()[0]
        self.assertEqual(row["status"], "not_reviewed")
        self.assertEqual(row["severity"], "high")  # Official DISA metadata is preserved.
        for evidence in (
            "Requested refine-rule",
            '"role": "unchecked"',
            '"severity": "low"',
            '"weight": "2.5"',
            '"selector": "alternate"',
            "Recorded TestResult properties",
        ):
            self.assertIn(evidence, row["finding_details"])

    def test_refinements_on_stock_unselected_rules_remain_in_complete_checklists(self):
        ds, _ = self.tailored()
        ET.SubElement(ds.find(X + "Profile"), X + "select", idref="two", selected="false")
        root = tailoring()
        prof = root.find(X + "Profile")
        prof.remove(prof.find(X + "select"))
        ET.SubElement(prof, X + "refine-rule", idref="two", severity="low")
        meta = self.preflight(root, ds)
        self.assertEqual(meta["deselected_rules"], [])
        meta["datastream_sha256"] = H
        self.prepare(ds, register=False)
        self.save_meta(meta)
        rc, result = self.generate(self.save_skeleton())
        self.assertEqual((rc, result["outcome"]), (0, "generated"), result)
        row = self.rows()[1]
        self.assertEqual(row["status"], "not_reviewed")
        self.assertIn("Requested refine-rule", row["finding_details"])
        self.assertIn("checks were not evaluated", row["finding_details"])

    def test_group_cluster_refinements_are_bound_to_each_descendant_rule(self):
        ds = source()
        for group in ds.findall(X + "Group"):
            group.set("cluster-id", "all_groups")
        root = tailoring()
        ET.SubElement(root.find(X + "Profile"), X + "refine-rule", idref="all_groups", weight="2")
        meta = self.preflight(root, ds)
        self.assertEqual(set(meta["rule_refinements"]), {"one", "two"})
        for rid in ("one", "two"):
            directive = meta["rule_refinements"][rid]["directives"][0]
            self.assertEqual(directive["target_id"], "g-" + rid)
            self.assertEqual(directive["target_type"], "Group")
            self.assertEqual(directive["attributes"], {"weight": "2"})

    def test_summary_rejects_unverified_tailoring_identity_even_without_checklists(self):
        self.tailored()
        (self.out / "tailoring-meta.json").write_text('{"profile_title":"incorrect"}')
        result = self.summary("none")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tailoring metadata hash/size", result.stderr)

    def test_every_unused_profile_base_and_ancestry_is_validated(self):
        for change in ("missing", "unknown", "cycle", "unresolved"):
            with self.subTest(change=change):
                root = tailoring()
                ds = source()
                other = ET.SubElement(root, X + "Profile", id="xccdf_org.example_profile_unused")
                if change == "unknown":
                    other.set("extends", "unknown")
                elif change in ("cycle", "unresolved"):
                    base = "xccdf_org.example_profile_other_base"
                    other.set("extends", base)
                    ET.SubElement(ds, X + "Profile", id=base, extends=base if change == "cycle" else "unknown")
                with self.assertRaises(ValueError):
                    self.preflight(root, ds)
        root = tailoring()
        ET.SubElement(root, X + "Profile", id="xccdf_org.example_profile_unused", extends=P)
        self.assertEqual(self.preflight(root)["base_profile_id"], P)

    def test_inherited_rule_checks_associate_values_and_preserve_replacement_semantics(self):
        for case in ("inherited", "replaced", "complex", "cycle", "missing"):
            with self.subTest(case=case):
                ds, _ = self.tailored()
                child, parent = list(ds.iter(X + "Rule"))
                inherited = child.find(X + "check")
                child.remove(inherited)
                ET.SubElement(inherited, X + "check-content-ref", href="checks.xml", name="inherited")
                parent.append(inherited)
                child.set("extends", parent.get("id"))
                if case == "cycle":
                    parent.set("extends", child.get("id"))
                elif case == "missing":
                    child.set("extends", "unknown")
                elif case == "replaced":
                    check = ET.SubElement(child, X + "check", system="test")
                    ET.SubElement(check, X + "check-content-ref", href="checks.xml", name="replacement")
                elif case == "complex":
                    parent.remove(inherited)
                    complex_check = ET.SubElement(parent, X + "complex-check", operator="AND")
                    complex_check.append(inherited)
                rr = ds.find(X + "TestResult/" + X + "rule-result")
                check = ET.SubElement(rr, X + "check", system="test")
                ET.SubElement(
                    check,
                    X + "check-content-ref",
                    href="checks.xml",
                    name="replacement" if case == "replaced" else "inherited",
                )
                if case not in ("cycle", "missing"):
                    meta = self.preflight(ds=ds)
                    meta["datastream_sha256"] = H
                    self.save_meta(meta)
                self.prepare(ds, register=False)
                rc, result = self.generate(self.save_skeleton())
                if case in ("cycle", "missing"):
                    self.assertEqual((rc, result["outcome"]), (1, "failed"), result)
                    self.assertIn("Rule inheritance", result["reason"])
                    continue
                self.assertEqual((rc, result["outcome"]), (0, "generated"), result)
                details = self.rows()[0]["finding_details"]
                if case == "replaced":
                    self.assertNotIn("Tailored value " + VALUE, details)
                else:
                    self.assertIn("Tailored value " + VALUE, details)
                    self.assertIn("Export declared by recorded check(s): one", details)

    def test_fully_deselected_tailoring_generates_complete_not_reviewed_checklists(self):
        ds, _ = self.tailored()
        ET.SubElement(ds, X + "platform", idref="not-evaluated")
        root = tailoring()
        ET.SubElement(root.find(X + "Profile"), X + "select", idref="one", selected="false")
        meta = self.preflight(root, ds)
        self.assertEqual(meta["deselected_rules"], ["one", "two"])
        meta["datastream_sha256"] = H
        for rr in ds.find(X + "TestResult").findall(X + "rule-result"):
            rr.find(X + "result").text = "notselected"
        self.prepare(ds, register=False)
        self.save_meta(meta)
        rc, result = self.generate(self.save_skeleton())
        self.assertEqual((rc, result["outcome"]), (0, "generated"), result)
        self.assertEqual(len(self.rows()), 2)
        self.assertTrue(all(row["status"] == "not_reviewed" for row in self.rows()))
        self.assertIn("benchmark applicability was not established", self.rows()[0]["finding_details"])
        self.assertEqual(result["not_reviewed_by_reason"]["tailoring_deselected"], 2)
        # Checklist conversion succeeds, while the default hollow-scan gate
        # remains independent and still rejects zero evaluated Rules.
        self.assertNotEqual(self.summary("require").returncode, 0)
        env = dict(
            os.environ,
            PARAM_OUTPUT_DIR=str(self.out),
            PARAM_CHECKLIST="require",
            PARAM_FAIL_ON_FINDING="false",
            PARAM_REQUIRE_EVALUATED_RULES="false",
        )
        summary = subprocess.run(
            ["bash", str(common.ROOT / "src/scripts/summarize.sh")], env=env, capture_output=True, text=True
        )
        self.assertEqual(summary.returncode, 0, summary.stderr)

    def test_unused_profile_directives_are_validated_without_affecting_selected_metadata(self):
        for change in ("rule", "value", "flag", "complex", "complex_selector", "scalar_child"):
            with self.subTest(change=change):
                ds = source()
                root = tailoring()
                other = ET.SubElement(root, X + "Profile", id="xccdf_org.example_profile_unused", extends=P)
                ET.SubElement(other, X + "title").text = "Unused"
                if change == "rule":
                    ET.SubElement(other, X + "select", idref="unknown", selected="true")
                elif change == "value":
                    ET.SubElement(other, X + "set-value", idref="unknown").text = "20"
                elif change == "flag":
                    ET.SubElement(other, X + "select", idref="one", selected="invalid")
                elif change == "complex":
                    ET.SubElement(other, X + "set-complex-value", idref=VALUE)
                elif change == "complex_selector":
                    ET.SubElement(ds.find(X + "Value"), X + "complex-value", selector="vector")
                    ET.SubElement(other, X + "refine-value", idref=VALUE, selector="vector")
                else:
                    ET.SubElement(ET.SubElement(other, X + "set-value", idref=VALUE), X + "remark")
                with self.assertRaises(ValueError):
                    self.preflight(root, ds)
        root = tailoring()
        other = ET.SubElement(root, X + "Profile", id="xccdf_org.example_profile_unused", extends=P)
        ET.SubElement(other, X + "title").text = "Unused"
        ET.SubElement(other, X + "select", idref="one", selected="false")
        ET.SubElement(other, X + "set-value", idref=VALUE).text = "99"
        meta = self.preflight(root)
        self.assertEqual(meta["deselected_rules"], ["two"])
        self.assertEqual(meta["values"][VALUE]["value"], "18")
        self.assertTrue(all(d["profile_id"] == CUSTOM for d in meta["values"][VALUE]["directives"]))

    def test_inherited_directives_precede_trailing_profile_metadata(self):
        ds = source()
        mid = "xccdf_org.example_profile_intermediary"
        parent = ET.SubElement(ds, X + "Profile", id=mid, extends=P)
        ET.SubElement(parent, X + "set-value", idref=VALUE).text = "20"
        root = tailoring(base=mid)
        prof = root.find(X + "Profile")
        prof.remove(prof.find(X + "select"))
        prof.remove(prof.find(X + "set-value"))
        ET.SubElement(ET.SubElement(prof, X + "metadata"), "{urn:stig:compat}note").text = "Retained metadata"
        self.preflight(root, ds)
        evaluated = self.out / "evaluated.xml"
        PRE["prepare"](str(self.tail_path), str(self.ds_path), CUSTOM, str(evaluated))
        children = [e.tag for e in ET.parse(evaluated).find(X + "Profile")]
        self.assertLess(children.index(X + "set-value"), children.index(X + "metadata"))

    def test_tailored_selected_mapping_missing_from_disa_cannot_disappear(self):
        ds, _ = self.tailored()
        child = copy.deepcopy(next(ds.iter(X + "Rule")))
        child.set("id", "added")
        for ref in child.findall(X + "reference"):
            ref.text = "SV-99r1_rule" if ref.get("href") == MOD["HREF_RULE"] else "V-99"
        ds.find(X + "Group").append(child)
        rr = ET.SubElement(ds.find(X + "TestResult"), X + "rule-result", idref="added")
        ET.SubElement(rr, X + "result").text = "fail"
        meta = self.preflight(ds=ds)
        meta["datastream_sha256"] = H
        self.prepare(ds, register=False)
        self.save_meta(meta)
        rc, result = self.generate(self.save_skeleton())
        self.assertEqual((rc, result["outcome"]), (1, "failed"), result)
        self.assertIn("V-99", result["reason"])
        self.assertFalse((self.out / "checklist.ckl").exists())
        self.assertFalse((self.out / "checklist.cklb").exists())

    def test_fully_indirect_deselection_counts_real_result_mappings(self):
        ds, _ = self.tailored()
        group = ET.SubElement(ds, X + "Group", id="g-dependency")
        ET.SubElement(group, X + "Rule", id="dependency")
        for rule in ds.iter(X + "Rule"):
            if rule.get("id") != "dependency":
                ET.SubElement(rule, X + "requires", idref="dependency")
        rr = ET.SubElement(ds.find(X + "TestResult"), X + "rule-result", idref="dependency")
        ET.SubElement(rr, X + "result").text = "notselected"
        for rr in ds.find(X + "TestResult").findall(X + "rule-result"):
            rr.find(X + "result").text = "notselected"
        root = tailoring()
        root.find(X + "Profile").find(X + "select").set("idref", "dependency")
        meta = self.preflight(root, ds)
        self.assertEqual(meta["deselected_rules"], ["dependency"])
        meta["datastream_sha256"] = H
        self.prepare(ds, register=False)
        self.save_meta(meta)
        rc, result = self.generate(self.save_skeleton())
        self.assertEqual((rc, result["outcome"]), (0, "generated"), result)
        self.assertTrue(all(row["status"] == "not_reviewed" for row in self.rows()))
        self.assertNotIn("Deselected by tailoring", self.rows()[0]["comments"])

    def test_inherited_disa_references_keep_derived_failures_visible(self):
        for mode in ("inherit", "append", "override"):
            with self.subTest(mode=mode):
                ds, _ = self.tailored()
                derived = ET.SubElement(
                    ds.find(X + "Group"), X + "Rule", id="derived", extends="one", severity="medium"
                )
                ET.SubElement(derived, X + "title").text = "Derived check"
                check = ET.SubElement(derived, X + "check", system="test")
                ET.SubElement(check, X + "check-content-ref", href="checks.xml", name="failing-derived")
                if mode != "inherit":
                    ref = ET.SubElement(derived, X + "reference", href=MOD["HREF_RULE"])
                    ref.text = "SV-2r1_rule"
                    if mode == "override":
                        ref.set("override", "true")
                    ET.SubElement(derived, X + "reference", href=MOD["HREF_VULN"]).text = "V-2"
                rr = ET.SubElement(ds.find(X + "TestResult"), X + "rule-result", idref="derived")
                ET.SubElement(rr, X + "result").text = "fail"
                meta = self.preflight(ds=ds)
                meta["datastream_sha256"] = H
                self.prepare(ds, register=False)
                self.save_meta(meta)
                rc, result = self.generate(self.save_skeleton())
                self.assertEqual((rc, result["outcome"]), (0, "generated"), result)
                parsed = MOD["parse_results"](str(self.out / "results.xml"), meta)
                expected = {"1"} if mode == "inherit" else {"2"} if mode == "override" else {"1", "2"}
                self.assertEqual(set(parsed["rules"]["derived"]["svs"]), expected)
                rows = {row["group_id"]: row for row in self.rows()}
                if mode != "override":
                    self.assertEqual(rows["V-1"]["status"], "open")
                    self.assertIn("derived: fail", rows["V-1"]["finding_details"])
                else:
                    self.assertEqual(rows["V-1"]["status"], "not_a_finding")
                    self.assertIn("derived: fail", rows["V-2"]["finding_details"])

    def test_tailoring_output_collisions_preserve_input_and_existing_evidence(self):
        bindir = self.out / "bin"
        bindir.mkdir()
        fake = bindir / "docker"
        fake.write_text('#!/bin/sh\nprintf called > "$DOCKER_CALLED"\nexit 99\n')
        fake.chmod(0o755)
        called = self.out / "docker-called"
        raw = ET.tostring(tailoring())
        for case in ("direct", "dot", "directory_alias", "file_alias", "hardlink", "later_output", "datastream"):
            with self.subTest(case=case):
                directory = self.out / case
                directory.mkdir()
                output = directory / "out"
                output.mkdir()
                artifact = output / (
                    "results.xml" if case in ("later_output", "datastream") else "tailoring-meta.json"
                )
                artifact.write_bytes(raw)
                evidence = output / "checklist-meta.json"
                evidence.write_text("prior evidence")
                source = artifact
                output_param = str(output)
                cwd = self.out
                if case == "dot":
                    cwd, source, output_param = output, Path("tailoring-meta.json"), "."
                elif case == "directory_alias":
                    alias = directory / "output-alias"
                    alias.symlink_to(output, target_is_directory=True)
                    output_param = str(alias)
                elif case == "file_alias":
                    source = directory / "source.xml"
                    source.symlink_to(artifact)
                elif case == "hardlink":
                    source = directory / "source.xml"
                    os.link(artifact, source)
                env = dict(
                    os.environ,
                    PATH=str(bindir) + os.pathsep + os.environ["PATH"],
                    DOCKER_CALLED=str(called),
                    PARAM_IMAGE="unused:test",
                    PARAM_OUTPUT_DIR=output_param,
                    PARAM_PROFILE_ID=CUSTOM,
                    PARAM_TAILORING_FILE=str(source),
                )
                if case == "datastream":
                    source = directory / "tailoring.xml"
                    source.write_bytes(raw)
                    env["PARAM_TAILORING_FILE"] = str(source)
                    env["PARAM_DATASTREAM_PATH"] = str(artifact)
                run = subprocess.run(["bash", str(SCAN)], env=env, cwd=str(cwd), capture_output=True, text=True)
                self.assertEqual(run.returncode, 2, run.stderr)
                self.assertIn("collides with generated output", run.stderr)
                self.assertEqual(artifact.read_bytes(), raw)
                self.assertEqual(evidence.read_text(), "prior evidence")
                self.assertFalse(called.exists())

    def test_positive_group_requests_do_not_claim_stock_deselections(self):
        ds, _ = self.tailored()
        for rule in ds.iter(X + "Rule"):
            rule.set("selected", "false")
        for rr in ds.find(X + "TestResult").findall(X + "rule-result"):
            rr.find(X + "result").text = "notselected"
        ET.SubElement(ds, X + "platform", idref="not-evaluated")
        root = tailoring()
        prof = root.find(X + "Profile")
        prof.remove(prof.find(X + "select"))
        ET.SubElement(prof, X + "select", idref="g-one", selected="true")
        meta = self.preflight(root, ds)
        self.assertEqual(meta["deselected_rules"], [])
        meta["datastream_sha256"] = H
        self.prepare(ds, register=False)
        self.save_meta(meta)
        rc, result = self.generate(self.save_skeleton())
        self.assertEqual((rc, result["outcome"]), (0, "skipped"), result)
        self.assertIn("none of the Benchmark's platforms", result["reason"])
        # An actual negative Group selector is recorded as such.
        prof.find(X + "select").set("selected", "false")
        self.assertEqual(self.preflight(root, ds)["deselected_rules"], ["one"])

    def test_preflight_failure_cannot_republish_prior_scan_outputs(self):
        self.preflight()
        self.tail_path.write_text("not valid tailoring XML")
        artifacts = (
            "results.xml",
            "report.html",
            "scan-plan.env",
            "summary.txt",
            "provenance.json",
            "tailoring-meta.json",
        )
        for filename in artifacts:
            (self.out / filename).write_text("old invocation evidence")
        # Load the exact production safety/cleanup prefix and preflight;
        # omit only Docker provisioning, which test-scripts does not require.
        prefix = SCAN.read_text().split("# --- image helpers", 1)[0]
        harness = self.out / "preflight-harness.sh"
        harness.write_text(
            prefix + '\npython3 - "$TAILORING_FILE" "$TEST_DATASTREAM" "$PROFILE_ID_OVERRIDE" '
            '"$OUTPUT_DIR/test-meta.json" "$OUTPUT_DIR/evaluated.xml" <<\'PY_TAILORING\'\n' + CODE + "\nPY_TAILORING\n"
        )
        env = dict(
            os.environ,
            PARAM_IMAGE="unused:test",
            PARAM_OUTPUT_DIR=str(self.out),
            PARAM_PROFILE_ID=CUSTOM,
            PARAM_TAILORING_FILE=str(self.tail_path),
            TEST_DATASTREAM=str(self.ds_path),
        )
        result = subprocess.run(["bash", str(harness)], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("invalid tailoring", result.stderr)
        self.assertEqual(self.tail_path.read_text(), "not valid tailoring XML")
        for filename in artifacts:
            self.assertFalse((self.out / filename).exists(), filename)

    def test_standalone_summary_binds_results_and_complete_unambiguous_plan(self):
        for change in ("results", "missing_hash", "partial", "duplicate"):
            with self.subTest(change=change):
                ds, _ = self.tailored()
                if change == "results":
                    ds.find(X + "TestResult/" + X + "rule-result/" + X + "result").text = "fail"
                    (self.out / "results.xml").write_bytes(ET.tostring(ds))
                elif change == "missing_hash":
                    del self.plan["results_sha256"]
                    self.save_plan()
                elif change == "partial":
                    del self.plan["tailoring_file"]
                    self.save_plan()
                else:
                    with (self.out / "scan-plan.env").open("a") as f:
                        f.write("results_sha256=" + self.plan["results_sha256"] + "\n")
                result = self.summary("none")
                self.assertNotEqual(result.returncode, 0)
                expected = (
                    "incomplete tailoring provenance"
                    if change == "partial"
                    else "repeats results_sha256" if change == "duplicate" else "results hash differs"
                )
                self.assertIn(expected, result.stderr)
                self.assertFalse((self.out / "provenance.json").exists())
                self.assertFalse((self.out / "summary.txt").exists())
        self.tailored()
        result = self.summary("none")
        self.assertEqual(result.returncode, 0, result.stderr)
        provenance = json.loads((self.out / "provenance.json").read_text())
        self.assertEqual(provenance["profile"]["id"], CUSTOM)
        self.assertEqual(provenance["tailoring"]["metadata_sha256"], self.plan["tailoring_meta_sha256"])

    def test_signed_tailoring_is_never_rewritten(self):
        for location in ("Tailoring", "Profile"):
            for reason in ("cluster", "repeat", "inherited", "fallback"):
                with self.subTest(location=location, reason=reason):
                    ds, root = source(), tailoring()
                    prof = root.find(X + "Profile")
                    ET.SubElement(root if location == "Tailoring" else prof, X + "signature")
                    if reason == "cluster":
                        ds.find(X + "Value").set("cluster-id", "settings")
                        prof.find(X + "set-value").set("idref", "settings")
                    elif reason == "repeat":
                        ET.SubElement(prof, X + "select", idref="two", selected="true")
                    elif reason == "inherited":
                        mid = "xccdf_org.example_profile_intermediary"
                        inherited = ET.SubElement(ds, X + "Profile", id=mid, extends=P)
                        ET.SubElement(inherited, X + "set-value", idref=VALUE).text = "25"
                        prof.set("extends", mid)
                    else:
                        prof.remove(prof.find(X + "set-value"))
                        ET.SubElement(prof, X + "refine-value", idref=VALUE, selector="unmatched")
                    input_path, ds_path = self.out / "signed.xml", self.out / "source.xml"
                    original = ET.tostring(root)
                    input_path.write_bytes(original)
                    ds_path.write_bytes(ET.tostring(ds))
                    evaluated = self.out / (location + "-" + reason + ".xml")
                    with self.assertRaisesRegex(ValueError, "signed tailoring cannot be normalized"):
                        PRE["prepare"](str(input_path), str(ds_path), CUSTOM, str(evaluated))
                    self.assertEqual(input_path.read_bytes(), original)
                    self.assertFalse(evaluated.exists())
        # Exercise only byte preservation/detection, without claiming that a
        # placeholder signature has passed native schema or crypto validation.
        root = tailoring()
        ET.SubElement(root, X + "signature")
        meta = self.preflight(root)
        evaluated = self.out / "signed-pass-through.xml"
        meta = PRE["prepare"](str(self.tail_path), str(self.ds_path), CUSTOM, str(evaluated))
        self.assertEqual(evaluated.read_bytes(), self.tail_path.read_bytes())
        self.assertTrue(meta["signature_present"])
        self.assertEqual(meta["signature_verification"], "not-performed")

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
        meta["base_profile_ancestry"] = [meta["base_profile_id"]]
        self.save_meta(meta)
        rc, result = self.generate(self.save_skeleton())
        self.assertEqual((rc, result["outcome"]), (0, "skipped"))

    def test_unapplied_deselections_cannot_publish_a_checklist(self):
        ds, _ = self.tailored()
        ds.find(X + "TestResult").findall(X + "rule-result")[1].find(X + "result").text = "pass"
        self.prepare(ds, register=False)
        rc, result = self.generate(self.save_skeleton())
        self.assertEqual((rc, result["outcome"]), (1, "failed"))
        self.assertIn("did not apply requested tailoring deselections", result["reason"])
        self.assertFalse((self.out / "checklist.cklb").exists())

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

    def test_refine_value_and_nested_benchmark_profile_inheritance(self):
        ds = source()
        root = tailoring()
        profile = root.find(X + "Profile")
        profile.set("id", "xccdf_org.example_profile_parent")
        profile.remove(profile.find(X + "set-value"))
        ET.SubElement(profile, X + "refine-value", idref=VALUE, selector="long")
        child = ET.SubElement(root, X + "Profile", id=CUSTOM, extends=profile.get("id"))
        ET.SubElement(child, X + "select", idref="two", selected="true")
        root.remove(profile)
        ds.append(profile)
        meta = self.preflight(root, ds)
        self.assertEqual(meta["values"][VALUE]["value"], "20")
        self.assertEqual(meta["deselected_rules"], [])
        self.assertEqual(meta["base_profile_id"], profile.get("id"))

    def test_refinement_without_selector_and_coexisting_set_value(self):
        root = tailoring()
        prof = root.find(X + "Profile")
        ET.SubElement(prof, X + "refine-value", idref=VALUE, operator="greater than or equal")
        meta = self.preflight(root)
        self.assertEqual(len(meta["values"][VALUE]["directives"]), 2)
        self.assertIsNone(meta["values"][VALUE]["value"])
        self.assertEqual(meta["values"][VALUE]["operator"], "greater than or equal")

    def test_selector_without_matching_value_uses_scalar_default(self):
        ds = source()
        ET.SubElement(ds.find(X + "Value"), X + "lower-bound", selector="bounded").text = "10"
        root = tailoring()
        prof = root.find(X + "Profile")
        prof.remove(prof.find(X + "set-value"))
        setting = ET.SubElement(prof, X + "refine-value", idref=VALUE, selector="bounded")
        for selector in ("bounded", "unknown", ""):
            setting.set("selector", selector)
            meta = self.preflight(root, ds)
            self.assertEqual(meta["values"][VALUE]["value"], "15")
            self.assertEqual(meta["values"][VALUE]["selector"], selector)
        value = ds.find(X + "Value")
        value.remove(value.find(X + "value"))
        variant = ET.SubElement(value, X + "complex-value")
        ET.SubElement(variant, X + "item").text = "vector"
        with self.assertRaisesRegex(ValueError, "complex-value refinements are not supported"):
            self.preflight(root, ds)

    def test_default_fallback_materializes_without_overriding_explicit_values(self):
        root = tailoring()
        prof = root.find(X + "Profile")
        prof.remove(prof.find(X + "set-value"))
        ET.SubElement(prof, X + "refine-value", idref=VALUE, selector="bounded")
        self.preflight(root)
        evaluated = self.out / "evaluated.xml"
        meta = PRE["prepare"](str(self.tail_path), str(self.ds_path), CUSTOM, str(evaluated))
        self.assertEqual(meta["value_fallbacks_materialized"], [VALUE])
        self.assertEqual(ET.parse(evaluated).find(".//" + X + "set-value").text, "15")
        self.assertNotEqual(meta["sha256"], meta["evaluated_sha256"])
        for layer in ("local", "base"):
            ds = source()
            target = prof if layer == "local" else ds.find(X + "Profile")
            setting = ET.SubElement(target, X + "set-value", idref=VALUE)
            setting.text = "25"
            expected = [] if layer == "local" else [VALUE]
            self.assertEqual(self.preflight(root, ds)["value_fallbacks_materialized"], expected)
            target.remove(setting)

    def test_cross_type_value_selector_order_controls_materialized_values(self):
        for case, selector, expected in (
            ("base-set-first", "missing", "15"),
            ("local-set-first", "missing", "15"),
            ("local-set-first", "long", "20"),
            ("local-set-last", "missing", "25"),
            ("partial-refine-last", "long", "25"),
        ):
            with self.subTest(case=case, selector=selector):
                ds = source()
                root = tailoring()
                prof = root.find(X + "Profile")
                prof.remove(prof.find(X + "set-value"))
                first = ds.find(X + "Profile") if case == "base-set-first" else prof
                if case not in ("local-set-last", "partial-refine-last"):
                    ET.SubElement(first, X + "set-value", idref=VALUE).text = "25"
                ET.SubElement(prof, X + "refine-value", idref=VALUE, selector=selector)
                if case in ("local-set-last", "partial-refine-last"):
                    ET.SubElement(prof, X + "set-value", idref=VALUE).text = "25"
                if case == "partial-refine-last":
                    ET.SubElement(prof, X + "refine-value", idref=VALUE, operator="greater than")
                self.preflight(root, ds)
                evaluated = self.out / "evaluated.xml"
                if evaluated.exists():
                    evaluated.unlink()
                meta = PRE["prepare"](str(self.tail_path), str(self.ds_path), CUSTOM, str(evaluated))
                result = ET.parse(evaluated).find(".//" + X + "Profile")
                self.assertEqual(result.find(X + "set-value").text, expected)
                self.assertEqual(meta["value_overrides_materialized"], [VALUE])
                self.assertEqual(
                    meta["value_fallbacks_materialized"],
                    [VALUE] if selector == "missing" and case != "local-set-last" else [],
                )

    def test_local_profile_inheritance_is_rejected_before_evaluation(self):
        root = tailoring()
        parent = root.find(X + "Profile")
        parent.set("id", "xccdf_org.example_profile_parent")
        child = ET.SubElement(root, X + "Profile", id=CUSTOM, extends=parent.get("id"))
        with self.assertRaisesRegex(ValueError, "cannot extend other tailoring profiles"):
            self.preflight(root)
        child.set("extends", P)
        self.assertEqual(self.preflight(root)["base_profile_id"], P)

    def test_scalar_set_value_children_are_invalid_not_requested_text(self):
        root = tailoring()
        ET.SubElement(root.find(".//" + X + "set-value"), X + "remark").text = "site minimum"
        with self.assertRaisesRegex(ValueError, "scalar text only"):
            self.preflight(root)
        ds, _ = self.tailored()
        ET.SubElement(ds.find(".//" + X + "TestResult/" + X + "set-value"), X + "remark").text = "not a scalar"
        self.prepare(ds, register=False)
        rc, result = self.generate(self.save_skeleton())
        self.assertEqual((rc, result["outcome"]), (1, "failed"), result)
        self.assertIn("scalar text only", result["reason"])

    def test_large_tailoring_manifest_keeps_summary_metadata_compact(self):
        _, meta = self.tailored()
        # A large, valid directive history must stay in the separate manifest.
        meta["values"][VALUE]["directives"][0]["value"] = "1" * (1 << 20)
        self.save_meta(meta)
        rc, result = self.generate(self.save_skeleton())
        self.assertEqual((rc, result["outcome"]), (0, "generated"), result)
        self.assertLess((self.out / "checklist-meta.json").stat().st_size, 1 << 20)
        self.assertNotIn("values", result["tailoring"])
        self.assertEqual(self.summary("require").returncode, 0)
        # The real artifact guard must retain the valid generated files too.
        env = dict(os.environ, PARAM_OUTPUT_DIR=str(self.out), PARAM_CHECKLIST_GUARD="true")
        subprocess.run(["bash", str(common.ROOT / "src/scripts/checklist.sh")], env=env, check=True)
        self.assertTrue((self.out / "checklist.cklb").exists())

    def test_base_profile_and_item_group_defaults_constrain_requested_selections(self):
        for layer in ("base", "ancestor", "item"):
            with self.subTest(layer=layer):
                ds, meta = self.tailored()
                for ref in list(ds.iter(X + "Rule"))[1].findall(X + "reference"):
                    ref.text = "SV-1r1_rule" if ref.get("href") == MOD["HREF_RULE"] else "V-1"
                if layer == "item":
                    ds.findall(X + "Group")[1].set("selected", "false")
                else:
                    base = ds.find(X + "Profile")
                    if layer == "ancestor":
                        ancestor = "xccdf_org.example_profile_baseline"
                        base.set("extends", ancestor)
                        base = ET.SubElement(ds, X + "Profile", id=ancestor)
                    ET.SubElement(base, X + "select", idref="g-two", selected="false")
                root = tailoring()
                root.find(X + "Profile").find(X + "select").set("selected", "true")
                meta = self.preflight(root, ds)
                self.assertEqual(meta["deselected_rules"], [])
                meta["datastream_sha256"] = H
                self.prepare(ds, register=False)
                self.save_meta(meta)
                rc, result = self.generate(self.save_skeleton())
                self.assertEqual((rc, result["outcome"]), (0, "generated"), result)
                self.assertEqual(self.rows()[0]["status"], "not_reviewed")
                self.assertIn("Not selected under tailored profile", self.rows()[0]["comments"])
                self.assertIn("one: pass", self.rows()[0]["finding_details"])
                # An explicit group override can enable the requested child.
                ET.SubElement(root.find(X + "Profile"), X + "select", idref="g-two", selected="true")
                self.assertEqual(self.preflight(root, ds)["deselected_rules"], [])

    def test_untouched_stock_deselections_are_not_tailoring_overrides(self):
        ds = source()
        ET.SubElement(ds.find(X + "Profile"), X + "select", idref="g-one", selected="false")
        self.assertEqual(self.preflight(ds=ds)["deselected_rules"], ["two"])

    def test_value_inheritance_resolves_selectors_defaults_and_invalid_chains(self):
        ds = source()
        child = ds.find(X + "Value")
        child.set("extends", VALUE + "_base")
        child.remove(child.findall(X + "value")[1])
        base = ET.SubElement(ds, X + "Value", id=VALUE + "_base")
        ET.SubElement(base, X + "value", selector="high").text = "20"
        root = tailoring()
        prof = root.find(X + "Profile")
        prof.remove(prof.find(X + "set-value"))
        setting = ET.SubElement(prof, X + "refine-value", idref=VALUE, selector="high")
        meta = self.preflight(root, ds)
        self.assertEqual(meta["values"][VALUE]["value"], "20")
        self.assertEqual(meta["value_fallbacks_materialized"], [])
        setting.set("selector", "unmatched")
        self.assertEqual(self.preflight(root, ds)["values"][VALUE]["value"], "15")
        child.remove(child.find(X + "value"))
        self.assertEqual(self.preflight(root, ds)["values"][VALUE]["value"], "20")
        for parent in (VALUE, "unknown"):
            base.set("extends", parent)
            with self.assertRaisesRegex(ValueError, "Value inheritance"):
                self.preflight(root, ds)
        base.attrib.pop("extends")
        scalar = base.find(X + "value")
        base.remove(scalar)
        ET.SubElement(ET.SubElement(base, X + "complex-value", selector="high"), X + "item").text = "20"
        setting.set("selector", "high")
        with self.assertRaisesRegex(ValueError, "complex-value refinements"):
            self.preflight(root, ds)

    def test_repeated_selectors_follow_document_order(self):
        root = tailoring()
        prof = root.find(X + "Profile")
        ET.SubElement(prof, X + "select", idref="two", selected="true")
        ET.SubElement(prof, X + "set-value", idref=VALUE).text = "25"
        ET.SubElement(prof, X + "refine-value", idref=VALUE, selector="long")
        ET.SubElement(prof, X + "refine-value", idref=VALUE, operator="greater than")
        meta = self.preflight(root)
        self.assertEqual(meta["deselected_rules"], [])
        self.assertTrue(meta["repeated_selectors_normalized"])
        self.assertEqual([d["value"] for d in meta["values"][VALUE]["directives"][:2]], ["18", "25"])
        evaluated = self.out / "evaluated.xml"
        PRE["prepare"](str(self.tail_path), str(self.ds_path), CUSTOM, str(evaluated))
        result = ET.parse(evaluated).find(".//" + X + "Profile")
        self.assertEqual(len(result.findall(X + "select")), 1)
        self.assertEqual(result.find(X + "select").get("selected"), "true")
        self.assertEqual(result.find(X + "set-value").text, "20")
        self.assertEqual(result.find(X + "refine-value").get("selector"), "long")
        self.assertEqual(result.find(X + "refine-value").get("operator"), "greater than")

    def test_shadowing_transitions_to_the_same_named_benchmark_profile(self):
        ds, _ = self.tailored()
        root = tailoring(profile=P)
        self.preflight()  # Create the helper paths without assuming the selected id.
        self.tail_path.write_bytes(ET.tostring(root))
        self.ds_path.write_bytes(ET.tostring(ds))
        meta = PRE["prepare"](str(self.tail_path), str(self.ds_path), P)
        self.assertEqual(meta["base_profile_ancestry"], [P])
        self.assertEqual(meta["deselected_rules"], ["two"])
        meta["datastream_sha256"] = H
        ds.find(X + "TestResult").find(X + "profile").set("idref", P)
        self.plan["profile"] = P
        self.prepare(ds, register=False)
        self.save_meta(meta)
        rc, result = self.generate(self.save_skeleton())
        self.assertEqual((rc, result["outcome"]), (0, "generated"), result)
        self.assertEqual(self.summary("require").returncode, 0)
        provenance = json.loads((self.out / "provenance.json").read_text())
        self.assertEqual(provenance["profile"]["title"], meta["profile_title"])
        self.assertNotEqual(provenance["profile"]["title"], ds.find(X + "Profile/" + X + "title").text)
        child = ET.SubElement(root, X + "Profile", id=CUSTOM, extends=P)
        ET.SubElement(child, X + "select", idref="two", selected="true")
        with self.assertRaisesRegex(ValueError, "cannot extend other tailoring profiles"):
            self.preflight(root)

    def test_indirect_or_stock_partial_selection_withholds_shared_requirement(self):
        for cause in ("requires", "conflicts", "stock"):
            with self.subTest(cause=cause):
                ds, _ = self.tailored()
                group = ET.SubElement(ds, X + "Group", id="g-indirect")
                rule = copy.deepcopy(next(ds.iter(X + "Rule")))
                rule.set("id", "indirect")
                group.append(rule)
                if cause != "stock":
                    ET.SubElement(rule, X + cause, idref="two")
                rr = ET.SubElement(ds.find(X + "TestResult"), X + "rule-result", idref="indirect")
                ET.SubElement(rr, X + "result").text = "notselected"
                meta = self.preflight(ds=ds)
                self.assertEqual(meta["deselected_rules"], ["two"])
                meta["datastream_sha256"] = H
                self.prepare(ds, register=False)
                self.save_meta(meta)
                rc, result = self.generate(self.save_skeleton())
                self.assertEqual((rc, result["outcome"]), (0, "generated"), result)
                row = self.rows()[0]
                self.assertEqual(row["status"], "not_reviewed")
                self.assertIn("one: pass", row["finding_details"])
                self.assertIn("Not selected under tailored profile", row["comments"])
                self.assertEqual(result["not_reviewed_by_reason"]["tailored_partial_selection"], 1)

    def test_unknown_profiles_cycles_shadowing_and_duplicate_ids(self):
        for change in ("missing", "cycle", "invalid_shadow", "duplicate"):
            root = tailoring()
            profile = root.find(X + "Profile")
            if change == "missing":
                profile.set("extends", "unknown")
            elif change == "cycle":
                profile.set("extends", CUSTOM)
            elif change == "invalid_shadow":
                profile.set("id", P)
                profile.set("extends", "unknown")
            else:
                root.append(copy.deepcopy(profile))
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.preflight(root)

    def test_unknown_directives_and_invalid_flags_rejected(self):
        for change in ("unknown_rule", "unknown_value", "flag"):
            root = tailoring()
            prof = root.find(X + "Profile")
            if change == "unknown_rule":
                prof.find(X + "select").set("idref", "unknown")
            elif change == "unknown_value":
                prof.find(X + "set-value").set("idref", "unknown")
            elif change == "selector":
                prof.remove(prof.find(X + "set-value"))
                ET.SubElement(prof, X + "refine-value", idref=VALUE, selector="unknown")
            else:
                prof.find(X + "select").set("selected", "perhaps")
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.preflight(root)

    def test_group_deselections_expand_to_the_actual_rules(self):
        root = tailoring()
        root.find(X + "Profile").find(X + "select").set("idref", "g-two")
        self.assertEqual(self.preflight(root)["deselected_rules"], ["two"])

    def test_cluster_select_and_rule_refinements_expand_concrete_targets(self):
        ds = source()
        for rule in ds.iter(X + "Rule"):
            rule.set("cluster-id", "test_rules")
        root = tailoring()
        profile = root.find(X + "Profile")
        profile.find(X + "select").set("idref", "test_rules")
        ET.SubElement(profile, X + "refine-rule", idref="test_rules", role="unchecked")
        self.assertEqual(self.preflight(root, ds)["deselected_rules"], ["one", "two"])
        # Clusters can also contain Groups: selecting a child still cannot
        # override an unselected ancestor reached through a cluster reference.
        ds.find(X + "Group").set("cluster-id", "test_groups")
        profile.find(X + "select").set("idref", "test_groups")
        ET.SubElement(profile, X + "select", idref="one", selected="true")
        self.assertEqual(self.preflight(root, ds)["deselected_rules"], ["one"])

    def test_value_clusters_resolve_selectors_for_each_value(self):
        ds = source()
        ds.find(X + "Value").set("cluster-id", "test_values")
        other = ET.SubElement(ds, X + "Value", id=VALUE + "_other", **{"cluster-id": "test_values"})
        ET.SubElement(other, X + "value", selector="long").text = "30"
        root = tailoring()
        profile = root.find(X + "Profile")
        profile.find(X + "set-value").set("idref", "test_values")
        meta = self.preflight(root, ds)
        self.assertEqual({v["value"] for v in meta["values"].values()}, {"18"})
        profile.remove(profile.find(X + "set-value"))
        ET.SubElement(profile, X + "refine-value", idref="test_values", selector="long")
        meta = self.preflight(root, ds)
        self.assertEqual(meta["values"][VALUE]["value"], "20")
        self.assertEqual(meta["values"][VALUE + "_other"]["value"], "30")
        self.assertEqual(meta["values"][VALUE]["directives"][0]["idref"], "test_values")

    def test_benchmark_intermediary_overrides_are_in_tailoring_evidence(self):
        ds, _ = self.tailored()
        mid = "xccdf_org.example_profile_intermediary"
        profile = ET.SubElement(ds, X + "Profile", id=mid, extends=P)
        ET.SubElement(profile, X + "select", idref="two", selected="false")
        ET.SubElement(profile, X + "set-value", idref=VALUE).text = "18"
        root = tailoring(base=mid)
        custom = root.find(X + "Profile")
        custom.remove(custom.find(X + "select"))
        custom.remove(custom.find(X + "set-value"))
        meta = self.preflight(root, ds)
        meta["datastream_sha256"] = H
        self.assertEqual(meta["deselected_rules"], ["two"])
        self.assertTrue(meta["benchmark_overrides_materialized"])
        self.assertEqual(meta["values"][VALUE]["directives"][0]["profile_id"], mid)
        self.prepare(ds, register=False)
        self.save_meta(meta)
        rc, result = self.generate(self.save_skeleton())
        self.assertEqual(rc, 0, result)
        self.assertEqual(result["not_reviewed_by_reason"]["tailoring_deselected"], 1)
        self.assertIn("Tailored value", self.rows()[0]["finding_details"])

    def test_cluster_expansion_binds_original_and_evaluated_bytes(self):
        ds = source()
        ds.find(X + "Value").set("cluster-id", "settings")
        root = tailoring()
        root.find(X + "Profile").find(X + "set-value").set("idref", "settings")
        self.preflight(root, ds)
        evaluated = self.out / "evaluated.xml"
        original = self.tail_path.read_bytes()
        meta = PRE["prepare"](str(self.tail_path), str(self.ds_path), CUSTOM, str(evaluated))
        parsed = ET.parse(evaluated)
        self.assertEqual(parsed.find(".//" + X + "set-value").get("idref"), VALUE)
        self.assertEqual(meta["sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(meta["evaluated_sha256"], hashlib.sha256(evaluated.read_bytes()).hexdigest())
        self.assertNotEqual(meta["sha256"], meta["evaluated_sha256"])
        self.assertTrue(meta["clusters_expanded"])
        self.assertEqual(self.tail_path.read_bytes(), original)
        _, basic = self.tailored()
        self.assertEqual(basic["sha256"], basic["evaluated_sha256"])

    def test_complex_value_requests_are_rejected_before_scanning(self):
        root = tailoring()
        profile = root.find(X + "Profile")
        setting = ET.SubElement(profile, X + "set-complex-value", idref=VALUE)
        for value in ("one<&>", "two"):
            ET.SubElement(setting, X + "item").text = value
        with self.assertRaisesRegex(ValueError, "set-complex-value is not supported"):
            self.preflight(root)

    def test_complex_value_selectors_are_rejected_including_clusters(self):
        ds = source()
        value = ds.find(X + "Value")
        value.set("cluster-id", "vector_values")
        variant = ET.SubElement(value, X + "complex-value", selector="vector")
        for item in ("10", "20"):
            ET.SubElement(variant, X + "item").text = item
        root = tailoring()
        profile = root.find(X + "Profile")
        profile.remove(profile.find(X + "set-value"))
        refinement = ET.SubElement(profile, X + "refine-value", idref="vector_values", selector="vector")
        with self.assertRaisesRegex(ValueError, "complex-value refinements are not supported"):
            self.preflight(root, ds)
        for el in list(value):
            if el.tag == X + "value":
                value.remove(el)
        refinement.attrib.pop("selector")
        with self.assertRaisesRegex(ValueError, "complex-value refinements are not supported"):
            self.preflight(root, ds)

    def test_duplicate_scalar_and_complex_results_are_rejected(self):
        ds, _ = self.tailored()
        setting = ET.SubElement(ds.find(X + "TestResult"), X + "set-complex-value", idref=VALUE)
        ET.SubElement(setting, X + "item").text = "18"
        self.prepare(ds, register=False)
        rc, result = self.generate(self.save_skeleton())
        self.assertEqual((rc, result["outcome"]), (1, "failed"))
        self.assertIn("repeated set-value", result["reason"])

    def test_benchmark_intermediary_profiles_retain_the_stig_base(self):
        ds, _ = self.tailored()
        mid = "xccdf_org.example_profile_intermediary"
        ET.SubElement(ds, X + "Profile", id=mid, extends=P)
        root = tailoring(base=mid)
        meta = self.preflight(root, ds)
        self.assertEqual(meta["base_profile_ancestry"], [mid, P])
        meta["datastream_sha256"] = H
        self.prepare(ds, register=False)
        self.save_meta(meta)
        rc, result = self.generate(self.save_skeleton())
        self.assertEqual((rc, result["outcome"]), (0, "generated"), result)
        self.plan["datastream_sha256"] = meta["datastream_sha256"] = "a" * 64
        self.save_meta(meta)
        rc, result = self.generate(self.save_skeleton(), register=False)
        self.assertEqual((rc, result["outcome"]), (0, "generated"), result)

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
