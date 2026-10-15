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
            self.assertEqual(self.preflight(root, ds)["value_fallbacks_materialized"], [])
            target.remove(setting)

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
                self.assertEqual(meta["deselected_rules"], ["two"])
                meta["datastream_sha256"] = H
                self.prepare(ds, register=False)
                self.save_meta(meta)
                rc, result = self.generate(self.save_skeleton())
                self.assertEqual((rc, result["outcome"]), (0, "generated"), result)
                self.assertEqual(self.rows()[0]["status"], "not_reviewed")
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
        self.assertEqual(result.find(X + "set-value").text, "25")
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
        child = ET.SubElement(root, X + "Profile", id=CUSTOM, extends=P)
        ET.SubElement(child, X + "select", idref="two", selected="true")
        self.assertEqual(self.preflight(root)["deselected_rules"], [])

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
