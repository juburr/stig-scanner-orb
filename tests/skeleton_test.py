"""Skeleton contracts: official metadata, drift safety, bounded inputs and policy."""

import copy
import hashlib
import io
import json
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import zipfile

import checklist_test as common
from checklist_test import MOD, fixture, P

X = MOD["X11"]


def skeleton(nums=(1, 2), revision=1, version="99", release="Release: 1 Benchmark Date: 01 Oct 2026"):
    root = ET.Element(X + "Benchmark", id="RHEL_9_STIG")
    for tag, value in [
        ("title", "Official test STIG"),
        ("description", "Test benchmark"),
        ("version", version),
    ]:
        ET.SubElement(root, X + tag).text = value
    ET.SubElement(root, X + "plain-text", id="release-info").text = release
    profile = ET.SubElement(root, X + "Profile", id="MAC-1_Classified")
    for n in nums:
        ET.SubElement(profile, X + "select", idref=f"V-{n}", selected="true")
        group = ET.SubElement(root, X + "Group", id=f"V-{n}")
        ET.SubElement(group, X + "title").text = "SRG-TEST"
        rule = ET.SubElement(group, X + "Rule", id=f"SV-{n}r{revision}_rule", severity="high", weight="10.0")
        for tag, value in [
            ("version", f"RHEL-09-{n}"),
            ("title", f"Official rule {n} < & >"),
            (
                "description",
                "<VulnDiscussion>Official discussion &amp; evidence</VulnDiscussion><Documentable>false</Documentable>",
            ),
            ("fixtext", "Official fix\nSecond line"),
        ]:
            ET.SubElement(rule, X + tag).text = value
        ET.SubElement(rule, X + "ident", system="https://cyber.mil/cci").text = "CCI-000001"
        ET.SubElement(rule, X + "ident", system="legacy").text = "V-OLD"
        check = ET.SubElement(rule, X + "check", system="test")
        ET.SubElement(check, X + "check-content").text = "Official check\nSecond line"
        ET.SubElement(check, X + "check-content-ref", name="M")
    return root


class SkeletonTests(unittest.TestCase):
    setUp = common.ChecklistTests.setUp
    prepare = common.ChecklistTests.prepare
    save_plan = common.ChecklistTests.save_plan
    generate = common.ChecklistTests.generate
    rows = common.ChecklistTests.rows
    summary = common.ChecklistTests.summary
    guard = common.ChecklistTests.guard
    wrapper = common.ChecklistTests.wrapper

    def save(self, root=None, zipped=False, member="nested/Manual-xccdf.xml"):
        data = ET.tostring(root if root is not None else skeleton())
        path = self.out / ("manual.zip" if zipped else "manual.xml")
        if zipped:
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr(member, data)
        else:
            path.write_bytes(data)
        self.path = path
        return data

    def run_skeleton(self, **kwargs):
        return self.generate("--stig-xccdf-path=" + str(self.path), **kwargs)

    def assert_invalid(self, root, reason):
        self.save(root)
        rc, meta = self.run_skeleton()
        self.assertEqual((rc, meta["outcome"]), (1, "failed"), meta)
        self.assertIn(reason, meta["reason"])
        self.assertFalse((self.out / "checklist.ckl").exists())
        self.assertFalse((self.out / "checklist.cklb").exists())
        self.assertEqual(self.summary("require").returncode, 1)

    def test_official_rows_metadata_and_provenance_in_both_formats(self):
        data = self.save()
        rc, meta = self.run_skeleton()
        self.assertEqual(rc, 0)
        self.assertEqual(meta["release_source"], "skeleton")
        self.assertEqual(meta["skeleton_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(meta["skeleton_source_sha256"], meta["skeleton_sha256"])
        self.assertEqual(meta["skeleton_completeness"], "internal")
        self.assertEqual(meta["status"], {"NotAFinding": 1, "Not_Reviewed": 1})
        self.assertEqual(meta["not_reviewed_by_reason"], {"no_scanner_rule": 1})
        rows = self.rows()
        self.assertEqual(rows[0]["rule_title"], "Official rule 1 < & >")
        self.assertEqual(rows[0]["severity"], "high")
        self.assertEqual(rows[0]["ccis"], ["CCI-000001"])
        self.assertEqual(rows[0]["legacy_ids"], ["V-OLD"])
        self.assertEqual(rows[0]["check_content"], "Official check\nSecond line")
        for row in rows:
            self.assertIn(meta["skeleton_sha256"], row["finding_details"])
            self.assertIn("Scanner:", row["finding_details"])
            self.assertIn("Target:", row["finding_details"])
        ckl = ET.parse(self.out / "checklist.ckl")
        self.assertEqual(
            [
                x.findtext("ATTRIBUTE_DATA")
                for x in ckl.findall(".//STIG_DATA")
                if x.findtext("VULN_ATTRIBUTE") == "CCI_REF"
            ],
            ["CCI-000001", "CCI-000001"],
        )
        self.assertEqual(self.guard(), 0)
        summary = self.summary("require")
        self.assertEqual(summary.returncode, 0, summary.stdout + summary.stderr)
        self.assertIn("self-consistency", summary.stdout)
        self.assertEqual(
            json.loads((self.out / "provenance.json").read_text())["checklist"]["skeleton_sha256"],
            meta["skeleton_sha256"],
        )

    def test_zip_snapshot_hashes_and_no_extraction(self):
        data = self.save(zipped=True, member="../../outside/Manual-xccdf.xml")
        before = set(self.out.iterdir())
        rc, meta = self.run_skeleton()
        self.assertEqual(rc, 0)
        self.assertEqual(meta["skeleton_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(meta["skeleton_source_sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(meta["skeleton_member"], "../../outside/Manual-xccdf.xml")
        self.assertEqual(
            set(self.out.iterdir()) - before,
            {self.out / name for name in ("checklist.ckl", "checklist.cklb", "checklist-meta.json")},
        )

    def test_revision_mismatches_withhold_every_automated_verdict(self):
        for result, gates in [("pass", ()), ("fail", ()), ("notapplicable", ("#system_with_kernel",))]:
            with self.subTest(result=result):
                self.prepare(fixture([("one", 1, result, gates)]))
                self.save(skeleton(revision=2))
                rc, meta = self.run_skeleton()
                self.assertEqual(rc, 0)
                self.assertEqual(meta["status"], {"Not_Reviewed": 2})
                self.assertEqual(meta["not_reviewed_by_reason"]["revision_mismatch"], 1)
                row = self.rows()[0]
                self.assertEqual(row["rule_id_src"], "SV-1r2_rule")
                self.assertIn("one: " + result, row["finding_details"])
                self.assertIn("SV-1r1_rule", row["finding_details"])
                self.assertIn("different revision", row["comments"])
                self.assertEqual(meta["na_by_reason"], {})

    def test_all_contributors_must_match_even_if_one_does(self):
        self.prepare(
            fixture([("one", 1, "pass", ()), ("two", 1, "fail", (), [("sv", "SV-1r2_rule"), ("v", "V-1")])])
        )
        self.save(skeleton(revision=2))
        rc, meta = self.run_skeleton()
        self.assertEqual(rc, 0)
        self.assertEqual(meta["not_reviewed_by_reason"]["revision_mismatch"], 1)
        self.assertIn(
            "Automated result across the content's revisions: Open", self.rows()[0]["finding_details"]
        )
        self.assertIn("SV-1r1_rule", self.rows()[0]["finding_details"])

    def test_older_skeleton_also_withholds_revision_mismatch(self):
        self.prepare(fixture([("one", 1, "pass", (), [("sv", "SV-1r2_rule"), ("v", "V-1")])]))
        self.save(skeleton(revision=1))
        rc, meta = self.run_skeleton()
        self.assertEqual(rc, 0)
        self.assertEqual(meta["not_reviewed_by_reason"]["revision_mismatch"], 1)
        self.assertIn("SV-1r2_rule", self.rows()[0]["finding_details"])
        self.assertIn("different revision", self.rows()[0]["comments"])

    def test_xccdf12_and_snapshot_not_reopened_during_parse(self):
        root = skeleton()
        for el in root.iter():
            el.tag = el.tag.replace(X, MOD["X12"])
        data = self.save(root)
        original_parse = MOD["parse_disa"]
        def replace_source(source):
            self.path.write_bytes(b"edited after the input snapshot")
            return original_parse(source)
        with patch.dict(MOD, {"parse_disa": replace_source}):
            rc, meta = self.run_skeleton()
        self.assertEqual(rc, 0)
        self.assertEqual(meta["skeleton_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(meta["skeleton_source_sha256"], meta["skeleton_sha256"])

    def test_skeleton_does_not_waive_known_selection_fingerprint(self):
        self.save()
        changed = fixture([("one", 1, "pass", (), [("sv", "SV-1r2_rule"), ("v", "V-1")])])
        self.prepare(changed, register=False)
        rc, meta = self.run_skeleton()
        self.assertEqual(rc, 1)
        self.assertIn("references differ", meta["reason"])

    def test_deselected_and_manual_only_are_distinct(self):
        self.prepare(fixture([("one", 1, "pass", ()), ("two", 2, "notselected", ())]))
        self.save(skeleton((1, 2, 3)))
        rc, meta = self.run_skeleton()
        self.assertEqual(rc, 0)
        self.assertEqual(meta["not_reviewed_by_reason"], {"deselected": 1, "no_scanner_rule": 1})
        self.assertIn("two", self.rows()[1]["finding_details"])
        self.assertIn("evaluated profile did not select", self.rows()[1]["comments"])

    def test_unknown_datastream_and_benchmark_target_fallback(self):
        self.plan["datastream_sha256"] = "unknown"
        self.save_plan()
        self.save()
        self.assertEqual(self.run_skeleton()[0], 0)
        self.plan["target_base"] = "rhel9"
        self.prepare(fixture(benchmark="custom-benchmark"), register=False)
        self.assertEqual(self.run_skeleton()[0], 0)
        del self.plan["target_base"]
        self.save_plan()
        rc, meta = self.run_skeleton()
        self.assertEqual(rc, 1)
        self.assertIn("can't tell", meta["reason"])

    def test_skeleton_does_not_bypass_scan_contracts(self):
        self.save()
        self.prepare(fixture(profile=P.replace("stig", "cis_level1_server")))
        self.assertEqual(self.run_skeleton()[1]["outcome"], "skipped")
        self.prepare(fixture())
        self.plan["results_sha256"] = "wrong"
        self.save_plan()
        self.assertEqual(self.run_skeleton()[1]["outcome"], "failed")
        self.prepare(fixture())
        self.plan["rpm_status"] = "missing"
        self.save_plan()
        self.assertEqual(self.run_skeleton()[1]["outcome"], "skipped")
        self.prepare(fixture(benchmark="wrong-benchmark"), register=False)
        self.assertIn("different scans", self.run_skeleton()[1]["reason"])

    def test_known_inventory_catches_rewritten_profiles_and_release_date(self):
        self.save()
        parsed = MOD["parse_disa"](io.BytesIO(self.path.read_bytes()))
        pairs = sorted(f"{g['vid']} {g['rule_id']}" for g in parsed["groups"])
        inv = (len(pairs), hashlib.sha256("\n".join(pairs).encode()).hexdigest(), parsed["releaseinfo"])
        with patch.dict(MOD["STIG_INVENTORY"], {("RHEL_9_STIG", "99", "1"): inv}):
            self.assertEqual(self.run_skeleton()[1]["skeleton_completeness"], "inventory")
            root = skeleton((1,))
            self.assert_invalid(root, "don't match")
            root = skeleton(release="Release: 1 Benchmark Date: 02 Oct 2026")
            self.assert_invalid(root, "release info")
            self.assert_invalid(skeleton(revision=2), "don't match")

    def test_bad_identity_and_rule_structure(self):
        root = skeleton()
        root.set("id", "RHEL_8_STIG")
        self.assert_invalid(root, "implements RHEL_9_STIG")
        for mutation, reason in [
            (lambda r: r.find(X + "Group").remove(r.find(".//" + X + "Rule")), "exactly one"),
            (lambda r: r.find(X + "Group").append(copy.deepcopy(r.find(".//" + X + "Rule"))), "exactly one"),
            (lambda r: r.find(".//" + X + "Rule").set("id", "SV-2r1_rule"), "repeated Rule IDs"),
            (lambda r: r.find(".//" + X + "Rule").set("id", "SV-999r1_rule"), "other numbers"),
            (lambda r: r.find(".//" + X + "Rule").set("id", "SV-1garbage"), "malformed"),
            (lambda r: r.find(X + "Group").set("id", "XX1"), "malformed"),
            (lambda r: r.find(".//" + X + "Rule").set("severity", "unknown"), "severity"),
            (lambda r: r.find(X + "Profile").remove(r.find(".//" + X + "select")), "profiles don't select"),
        ]:
            with self.subTest(reason=reason):
                root = skeleton()
                mutation(root)
                self.assert_invalid(root, reason)
        for tag in ["title", "description", "check", "fixtext"]:
            root = skeleton()
            rule = root.find(".//" + X + "Rule")
            rule.remove(rule.find(X + tag))
            self.assert_invalid(root, "without a title")

    def test_canonical_release_and_calendar(self):
        for version in ["", "02", "２"]:
            self.assert_invalid(skeleton(version=version), "names no release")
        for release in [
            "",
            "Release: 1",
            "Release: 01 Benchmark Date: 01 Oct 2026",
            "Release: １ Benchmark Date: 01 Oct 2026",
            "Release: 1 Benchmark Date: 31 Feb 2026",
            "Release: 1 Benchmark Date: 01 Foo 2026",
            "Release: 1 Benchmark Date: 01 Oct 2026 trailing",
        ]:
            with self.subTest(release=release):
                self.assert_invalid(skeleton(release=release), "names no release")

    def test_duplicate_scalars_and_stray_rules_are_rejected(self):
        root = skeleton()
        root.append(copy.deepcopy(root.find(X + "version")))
        self.assert_invalid(root, "repeats version")
        root = skeleton()
        root.append(copy.deepcopy(root.find(".//" + X + "Rule")))
        self.assert_invalid(root, "outside its Groups")
        root = skeleton()
        root.append(copy.deepcopy(root.find(X + "plain-text")))
        self.assert_invalid(root, "exactly one release-info")
        root = skeleton()
        profile = root.find(X + "Profile")
        profile.append(copy.deepcopy(profile.find(X + "select")))
        self.assert_invalid(root, "repeated or disabled")
        root = skeleton()
        root.find(".//" + X + "select").set("selected", "false")
        self.assert_invalid(root, "repeated or disabled")

    def test_excessively_missing_and_zero_overlap_fail(self):
        self.prepare(fixture([(f"r{n}", n, "pass", ()) for n in range(1, 22)]))
        self.save(skeleton((1,)))
        rc, meta = self.run_skeleton()
        self.assertEqual(rc, 1)
        self.assertIn("lacks 20", meta["reason"])
        self.save(skeleton((99,)))
        rc, meta = self.run_skeleton()
        self.assertEqual(rc, 1)
        self.assertIn("shares no V-ID", meta["reason"])

    def test_small_removed_vid_set_is_reported(self):
        self.prepare(fixture([("one", 1, "pass", ()), ("two", 2, "fail", ())]))
        self.save(skeleton((1, 3)))
        rc, meta = self.run_skeleton()
        self.assertEqual(rc, 0)
        self.assertEqual(meta["unmatched_ssg_vids"], ["V-2"])
        self.assertIn("V-2", self.summary("require").stdout)

    def test_zip_ambiguity_corruption_and_size_caps(self):
        self.save(zipped=True)
        with zipfile.ZipFile(self.path, "a") as z:
            z.writestr("another/Manual-xccdf.xml", ET.tostring(skeleton()))
        self.assertIn("2 manual XCCDF", self.run_skeleton()[1]["reason"])
        with zipfile.ZipFile(self.path, "w") as z:
            z.writestr("readme.txt", "nothing")
        self.assertIn("0 manual XCCDF", self.run_skeleton()[1]["reason"])
        self.save()
        with patch.dict(MOD, {"MAX_DISA_BYTES": 100}):
            self.assertEqual(self.run_skeleton()[1]["outcome"], "failed")
        self.save(zipped=True)
        with zipfile.ZipFile(self.path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("Manual-xccdf.xml", b"x" * ((16 << 20) + 1))
        self.assertIn("member is larger", self.run_skeleton()[1]["reason"])
        self.path.write_bytes(b"not XML or ZIP")
        self.assertEqual(self.run_skeleton()[1]["outcome"], "failed")

    def test_shell_parameter_and_input_read_failure_cleanup(self):
        self.save()
        result = self.wrapper(PARAM_STIG_XCCDF_PATH=str(self.path))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            json.loads((self.out / "checklist-meta.json").read_text())["release_source"], "skeleton"
        )
        self.path.unlink()
        self.assertEqual(self.run_skeleton()[1]["outcome"], "failed")
        self.assertFalse((self.out / "checklist.ckl").exists())
        self.assertFalse((self.out / "checklist.cklb").exists())
        self.assertEqual(self.summary("auto").returncode, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
