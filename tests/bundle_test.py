"""Offline bundle integrity, packaging, refresh and revision-equivalence contracts."""

import base64
import copy
import lzma
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import checklist_test as common
from checklist_test import MOD, fixture, H
from skeleton_test import skeleton

ROOT = common.ROOT
spec = importlib.util.spec_from_file_location("refresh", ROOT / "tools/refresh-stig-data.py")
refresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refresh)


class BundleTests(unittest.TestCase):
    setUp = common.ChecklistTests.setUp
    prepare = common.ChecklistTests.prepare
    save_plan = common.ChecklistTests.save_plan
    generate = common.ChecklistTests.generate
    rows = common.ChecklistTests.rows
    summary = common.ChecklistTests.summary
    guard = common.ChecklistTests.guard

    def bundle(self, root=None):
        root = root if root is not None else skeleton()
        xml = common.ET.tostring(root)
        disa = MOD["parse_disa"](io.BytesIO(xml))
        release = (disa["version"], disa["releaseinfo"])
        self.entry = (*self.entry[:3], release)
        disa["profiles"] = [sorted(p) for p in disa["profiles"]]
        source = {
            "url": "https://dl.dod.cyber.mil/test.zip",
            "sha256": "a" * 64,
            "xccdf_sha256": hashlib.sha256(xml).hexdigest(),
            "member": "Manual-xccdf.xml",
            "credits": "DISA",
        }
        data = json.dumps(
            {
                "schema": "stig-scanner-orb/stig-data/v1",
                "datastream_sha256": H,
                "stig": disa,
                "source": source,
            },
            sort_keys=True,
        ).encode()
        self.descriptor = {
            "alias": "test",
            "json_sha256": hashlib.sha256(data).hexdigest(),
            "source_sha256": source["sha256"],
            "xccdf_sha256": source["xccdf_sha256"],
        }
        self.encoded = base64.b64encode(lzma.compress(data)).decode()
        self.bundle_path = self.out / "test.sh"
        self.bundle_path.write_text(refresh.render_script("test", self.encoded))
        pairs = sorted(f"{g['vid']} {g['rule_id']}" for g in disa["groups"])
        self.inventory_key = (disa["benchmark_id"], disa["version"], disa["releaseinfo"].split()[1])
        self.inventory = (
            len(pairs),
            hashlib.sha256("\n".join(pairs).encode()).hexdigest(),
            disa["releaseinfo"],
        )

    def run_bundle(self, extra=()):
        with patch.dict(MOD["BUNDLE_TABLE"], {H: self.descriptor}), patch.dict(
            MOD["STIG_INVENTORY"], {self.inventory_key: self.inventory}
        ):
            return self.generate("--bundle-dir=" + str(self.out), *extra)

    def supplied(self, root):
        root.find(MOD["X11"] + "plain-text").text = "Release: 2 Benchmark Date: 01 Oct 2026"
        path = self.out / "supplied.xml"
        path.write_bytes(common.ET.tostring(root))
        return ("--stig-xccdf-path=" + str(path),)

    def test_default_complete_bundle_and_provenance(self):
        self.bundle()
        rc, meta = self.run_bundle()
        self.assertEqual(rc, 0)
        self.assertEqual(meta["release_source"], "bundle")
        self.assertEqual(meta["vulns"], 2)
        self.assertEqual(meta["status"], {"NotAFinding": 1, "Not_Reviewed": 1})
        self.assertEqual(meta["bundle"]["source_sha256"], "a" * 64)
        self.assertEqual(meta["bundle"]["sha256"], self.descriptor["json_sha256"])
        for row in self.rows():
            self.assertEqual(row["ccis"], ["CCI-000001"])
            self.assertIn("Content-matched DISA reference", row["finding_details"])
            self.assertIn(meta["bundle"]["sha256"], row["finding_details"])
        self.assertEqual(self.guard(), 0)
        self.assertEqual(self.summary("require").returncode, 0)

    def test_unchanged_checks_keep_pass_fail_and_na_across_revisions(self):
        for result, gates in [
            ("pass", ()),
            ("fail", ()),
            ("notapplicable", ("#system_with_kernel",)),
            ("error", ()),
        ]:
            with self.subTest(result=result):
                self.prepare(fixture([("one", 1, result, gates)]))
                self.bundle()
                rc, meta = self.run_bundle(self.supplied(skeleton(revision=2)))
                self.assertEqual(rc, 0)
                expected = {
                    "pass": "not_a_finding",
                    "fail": "open",
                    "notapplicable": "not_applicable",
                    "error": "not_reviewed",
                }[result]
                self.assertEqual(self.rows()[0]["status"], expected)
                self.assertEqual(meta["revision_drift"], {"unchanged_check": 1})
                self.assertIn("Check content is unchanged", self.rows()[0]["finding_details"])
                self.assertIn("unchanged check text", self.summary("require").stdout)

    def test_check_change_withholds_verdict_even_with_same_rule_id(self):
        for revision in [1, 2]:
            self.bundle()
            root = skeleton(revision=revision)
            root.find(".//" + MOD["X11"] + "check-content").text = "A different check"
            rc, meta = self.run_bundle(self.supplied(root))
            self.assertEqual(rc, 0)
            self.assertEqual(self.rows()[0]["status"], "not_reviewed")
            self.assertEqual(meta["not_reviewed_by_reason"]["check_changed"], 1)
            self.assertEqual(meta["revision_drift"], {"check_changed": 1})
            self.assertIn("check content", self.rows()[0]["comments"])
            self.assertIn("Automated result across", self.rows()[0]["finding_details"])

    def test_nested_check_text_and_tails_are_compared_completely(self):
        for revision in [1, 2]:
            for changed_part in ["child", "tail"]:
                with self.subTest(revision=revision, changed_part=changed_part):
                    original = skeleton()
                    check = original.find(".//" + MOD["X11"] + "check-content")
                    check.text = "Inspect "
                    child = common.ET.SubElement(check, "{http://www.w3.org/1999/xhtml}code")
                    child.text = "setting"
                    child.tail = " equals enabled"
                    self.bundle(original)
                    supplied = copy.deepcopy(original)
                    supplied.find(".//" + MOD["X11"] + "Rule").set("id", f"SV-1r{revision}_rule")
                    rc, meta = self.run_bundle(self.supplied(supplied))
                    self.assertEqual(rc, 0)
                    self.assertEqual(self.rows()[0]["status"], "not_a_finding")
                    self.assertEqual(self.rows()[0]["check_content"], "Inspect setting equals enabled")
                    element = supplied.find(".//{http://www.w3.org/1999/xhtml}code")
                    if changed_part == "child":
                        element.text = "another_setting"
                    else:
                        element.tail = " equals disabled"
                    rc, meta = self.run_bundle(self.supplied(supplied))
                    self.assertEqual(rc, 0)
                    self.assertEqual(self.rows()[0]["status"], "not_reviewed")
                    self.assertEqual(meta["revision_drift"], {"check_changed": 1})
                    self.assertEqual(meta["not_reviewed_by_reason"]["check_changed"], 1)

    def test_strict_text_comparison_and_reverse_release_direction(self):
        self.bundle(skeleton(revision=2))
        self.prepare(fixture([("one", 1, "pass", (), [("sv", "SV-1r2_rule"), ("v", "V-1")])]))
        self.bundle(skeleton(revision=2))
        rc, meta = self.run_bundle(self.supplied(skeleton(revision=1)))
        self.assertEqual(rc, 0)
        self.assertEqual(meta["revision_drift"], {"unchanged_check": 1})
        changed = skeleton(revision=1)
        changed.find(".//" + MOD["X11"] + "check-content").text += " "
        # Parsers strip surrounding whitespace, but internal whitespace differs.
        changed.find(".//" + MOD["X11"] + "check-content").text = "Official check\n Second line"
        rc, meta = self.run_bundle(self.supplied(changed))
        self.assertEqual(meta["revision_drift"], {"check_changed": 1})

    def test_mixed_revisions_cannot_borrow_baseline_check(self):
        self.prepare(
            fixture([("one", 1, "pass", ()), ("two", 1, "pass", (), [("sv", "SV-1r2_rule"), ("v", "V-1")])])
        )
        self.bundle()
        rc, meta = self.run_bundle(self.supplied(skeleton(revision=2)))
        self.assertEqual(rc, 0)
        self.assertEqual(self.rows()[0]["status"], "not_reviewed")
        self.assertEqual(meta["revision_drift"], {"unverified_revision": 1})
        self.assertEqual(meta["not_reviewed_by_reason"]["revision_mismatch"], 1)

    def test_unknown_datastream_never_borrows_known_baseline(self):
        self.bundle()
        self.plan["datastream_sha256"] = "unknown"
        self.save_plan()
        rc, meta = self.run_bundle(self.supplied(skeleton(revision=2)))
        self.assertEqual(rc, 0)
        self.assertIsNone(meta["bundle"])
        self.assertEqual(meta["revision_drift"], {"unverified_revision": 1})

    def test_no_bundle_pin_cannot_silently_fall_back(self):
        self.entry = (*self.entry, {"filename": "ssg-test-ds.xml"})
        rc, meta = self.generate("--bundle-dir=" + str(self.out))
        self.assertEqual(rc, 1)
        self.assertIn("no bundled DISA data", meta["reason"])

    def test_missing_corrupt_wrong_hash_and_size_fail_with_meta(self):
        self.bundle()
        self.assertEqual(self.run_bundle()[0], 0)
        self.bundle_path.unlink()
        rc, meta = self.run_bundle()
        self.assertEqual(rc, 1)
        self.assertEqual(meta["outcome"], "failed")
        self.assertFalse((self.out / "checklist.cklb").exists())
        self.bundle_path.write_text(refresh.render_script("test", "bad-base64"))
        self.assertEqual(self.run_bundle()[0], 1)
        self.bundle()
        compressed = base64.b64decode(self.encoded)
        for invalid in [compressed[:-1], compressed + b"trailing", compressed + compressed]:
            self.bundle_path.write_text(refresh.render_script("test", base64.b64encode(invalid).decode()))
            self.assertIn("truncated or has trailing", self.run_bundle()[1]["reason"])
        self.bundle()
        self.descriptor["json_sha256"] = "wrong"
        self.assertIn("pinned SHA-256", self.run_bundle()[1]["reason"])
        self.bundle()
        with patch.dict(MOD, {"MAX_DISA_BYTES": 100}):
            self.assertIn("exceeds", self.run_bundle()[1]["reason"])

    def test_staged_payload_and_safe_bash_env_path(self):
        self.bundle()
        bash_env = self.out / "bash-env"
        bash_env.write_text("")
        staging_tmp = self.out / "space and $dollar"
        staging_tmp.mkdir()
        env = {**os.environ, "BASH_ENV": str(bash_env), "TMPDIR": str(staging_tmp), "PARAM_CHECKLIST": "auto"}
        p = subprocess.run(["bash", str(self.bundle_path)], env=env, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        exported = subprocess.check_output(
            ["bash", "-c", 'printf "%s" "$STIG_DATA_TEST"'], env=env, text=True
        )
        self.assertTrue(Path(exported).is_file())
        self.bundle_path.unlink()
        with patch.dict(os.environ, {"STIG_DATA_TEST": exported}):
            self.assertEqual(self.run_bundle()[0], 0)
        with patch.dict(os.environ, {"STIG_DATA_TEST": ""}):
            self.assertIn("could not be staged", self.run_bundle()[1]["reason"])

    def test_failed_staging_invalidates_previous_variable_and_none_skips(self):
        self.bundle()
        bash_env = self.out / "bash-env"
        bash_env.write_text("export STIG_DATA_TEST=/previous\n")
        env = {
            **os.environ,
            "BASH_ENV": str(bash_env),
            "TMPDIR": str(self.out / "absent"),
            "PARAM_CHECKLIST": "auto",
        }
        self.assertEqual(
            subprocess.run(["bash", str(self.bundle_path)], env=env, capture_output=True).returncode, 0
        )
        self.assertEqual(
            subprocess.check_output(["bash", "-c", 'printf "%s" "$STIG_DATA_TEST"'], env=env, text=True), ""
        )
        env["PARAM_CHECKLIST"] = "none"
        self.assertEqual(
            subprocess.run(["bash", str(self.bundle_path)], env=env, capture_output=True).returncode, 0
        )
        with patch.dict(os.environ, {"STIG_DATA_TEST": "/missing"}):
            self.assertEqual(self.run_bundle(("--mode=none",))[1]["outcome"], "skipped")

    def test_generation_and_guard_from_stdin_with_staged_data(self):
        self.bundle()
        payload = self.out / "staged-payload"
        payload.write_text(self.encoded)
        script = common.SCRIPT.read_text().replace(
            'if __name__ == "__main__":',
            f"RELEASE_TABLE[{H!r}] = {self.entry!r}\n"
            f"BUNDLE_TABLE[{H!r}] = {self.descriptor!r}\n"
            f"STIG_INVENTORY[{self.inventory_key!r}] = {self.inventory!r}\n"
            'if __name__ == "__main__":',
            1,
        )
        env = {**os.environ, "PARAM_OUTPUT_DIR": str(self.out), "STIG_DATA_TEST": str(payload)}
        result = subprocess.run(["bash", "-s"], input=script, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        meta = json.loads((self.out / "checklist-meta.json").read_text())
        self.assertEqual(meta["outcome"], "generated", meta)
        self.assertEqual(meta["release_source"], "bundle")
        env["PARAM_CHECKLIST_GUARD"] = "true"
        result = subprocess.run(["bash", "-s"], input=script, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["guard"], "kept")

    def test_real_bundles_match_release_source_pins_and_pack_wiring(self):
        sources = json.loads((ROOT / "tools/stig-sources.json").read_text())
        self.assertEqual(set(MOD["BUNDLE_TABLE"]),
                         {sha for sha, entry in MOD["RELEASE_TABLE"].items()
                          if entry[4].get("kind") != "vendor-srg"})
        for sha, descriptor in MOD["BUNDLE_TABLE"].items():
            with patch.dict(os.environ, {}, clear=True):
                disa = MOD["load_bundle"](sha, str(ROOT / "src/scripts/stig-data"))
            self.assertEqual((disa["version"], disa["releaseinfo"]), MOD["RELEASE_TABLE"][sha][3])
            self.assertEqual(disa["source_sha256"], sources[descriptor["alias"]]["sha256"])
            self.assertEqual(disa["source_path"], sources[descriptor["alias"]]["url"])
            self.assertTrue(all(g["ccis"] for g in disa["groups"]))
            self.assertIn(
                "scripts/stig-data/" + descriptor["alias"] + ".sh",
                (ROOT / "src/commands/generate_checklist.yml").read_text(),
            )
        bash_env = self.out / "command-size-bash-env"
        bash_env.write_text("")
        for script in (ROOT / "src/scripts/stig-data").glob("*.sh"):
            self.assertLess(script.stat().st_size, 120000)
            # CircleCI machine execution may pass the full body as one argument.
            result = subprocess.run(
                ["bash", "-c", script.read_text()],
                env={**os.environ, "PARAM_CHECKLIST": "none", "BASH_ENV": str(bash_env)},
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
        total = sum(p.stat().st_size for p in (ROOT / "src/scripts/stig-data").glob("*.sh"))
        self.assertLess(total, 2 << 20)


if __name__ == "__main__":
    unittest.main(verbosity=2)
