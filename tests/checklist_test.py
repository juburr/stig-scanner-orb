"""Docker-free regression coverage for the production checklist contracts.

Load the exact embedded generator; synthetic fixtures use an isolated release
entry so tests never weaken the production release table or require DISA text.
"""

import contextlib
import copy
import hashlib
import io
import json
import os
import re
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "src/scripts/checklist.sh"
CODE = SCRIPT.read_text().split("<<'PY_CHECKLIST'\n", 1)[1].split("\nPY_CHECKLIST\n", 1)[0]
MOD = {"__name__": "checklist_tests"}
exec(compile(CODE, str(SCRIPT), "exec"), MOD)
X = MOD["X12"]
P = "xccdf_org.ssgproject.content_profile_stig"
B = "xccdf_org.ssgproject.content_benchmark_RHEL-9"
H = "1" * 64


def fixture(specs=None, true=(), profile=P, benchmark=B, bench_gates=()):
    """Each spec is (id, V-number, result(s), gate(s), optional references)."""
    specs = specs or [("one", 1, "pass", ())]
    root = ET.Element(X + "Benchmark", id=benchmark)
    ET.SubElement(root, X + "version").text = "0.1.82"
    for gate in bench_gates:
        ET.SubElement(root, X + "platform", idref=gate)
    prof = ET.SubElement(root, X + "Profile", id=profile)
    ET.SubElement(prof, X + "title").text = "Wrong profile label V9R99"
    for spec in specs:
        rid, num, result, gates, *refs = spec
        group = ET.SubElement(root, X + "Group", id="g-" + rid)
        rule = ET.SubElement(group, X + "Rule", id=rid, severity="medium")
        for tag, val in [("title", rid + " title"), ("description", rid + " fix"), ("rationale", rid + " rationale")]:
            ET.SubElement(rule, X + tag).text = val
        for gate in gates:
            ET.SubElement(rule, X + "platform", idref=gate)
        values = refs[0] if refs else [("sv", f"SV-{num}r1_rule"), ("v", f"V-{num}")]
        for kind, value in values:
            href = (
                MOD["HREF_RULE"] if kind == "sv" else MOD["HREF_VULN"] if kind == "v" else "https://example/unix-linux"
            )
            ET.SubElement(rule, X + "reference", href=href).text = value
    tr = ET.SubElement(root, X + "TestResult", id="t", **{"start-time": "2026-10-14T00:00:00Z"})
    ET.SubElement(tr, X + "profile", idref=profile)
    for gate in true:
        ET.SubElement(tr, X + "platform", idref=gate)
    for spec in specs:
        rid, _, results = spec[:3]
        for result in results if isinstance(results, list) else [results]:
            rr = ET.SubElement(tr, X + "rule-result", idref=rid)
            ET.SubElement(rr, X + "result").text = result
    return root


class ChecklistTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.out = Path(self.temp.name)
        self.plan = dict(
            scanner_image_id="sha256:scanner",
            scanner_platform="linux/amd64",
            image="local/app:test",
            image_id="sha256:target",
            image_platform="linux/amd64",
            datastream_sha256=H,
            datastream="ssg-rhel9-ds.xml",
            profile=P,
        )
        self.prepare(fixture())

    def prepare(self, root, register=True):
        data = ET.tostring(root)
        (self.out / "results.xml").write_bytes(data)
        self.plan["results_sha256"] = hashlib.sha256(data).hexdigest()
        self.save_plan()
        if register:
            res = MOD["parse_results"](io.BytesIO(data))
            self.entry = (
                B,
                "0.1.82",
                {res["profile_id"]: MOD["selection_fingerprint"](res)},
                ("2", "Release: 9 Benchmark Date: 01 Jul 2026"),
            )
        return root

    def save_plan(self):
        (self.out / "scan-plan.env").write_text("".join(f"{k}={v}\n" for k, v in self.plan.items()))

    def generate(self, *extra, fault=None, register=True):
        argv = [
            "checklist",
            "--results",
            str(self.out / "results.xml"),
            "--plan",
            str(self.out / "scan-plan.env"),
            "--out-dir",
            str(self.out),
            *extra,
        ]
        handlers = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGHUP)}
        try:
            with patch.object(sys, "argv", argv), patch.dict(
                MOD["RELEASE_TABLE"], {H: self.entry} if register else {}
            ), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                if fault:
                    with fault:
                        rc = MOD["main"]()
                else:
                    rc = MOD["main"]()
        finally:
            for s, handler in handlers.items():
                signal.signal(s, handler)
        return rc, json.loads((self.out / "checklist-meta.json").read_text())

    def rows(self):
        return json.loads((self.out / "checklist.cklb").read_text())["stigs"][0]["rules"]

    def summary(self, mode="auto", findings="false", defer="false"):
        env = {
            **os.environ,
            "PARAM_OUTPUT_DIR": str(self.out),
            "PARAM_CHECKLIST": mode,
            "PARAM_FAIL_ON_FINDING": findings,
            "PARAM_DEFER_GATE": defer,
        }
        return subprocess.run(["bash", str(ROOT / "src/scripts/summarize.sh")], env=env, capture_output=True, text=True)

    def enforce_gate(self, rootfs=""):
        env = {**os.environ, "PARAM_OUTPUT_DIR": str(self.out), "PARAM_ROOTFS_PATH": rootfs}
        return subprocess.run(
            ["bash", str(ROOT / "src/scripts/enforce-gate.sh")], env=env, capture_output=True, text=True
        )

    def wrapper(self, **params):
        # Only tests register the fixture's release; the shell argument handling
        # and complete generator come unchanged from the production script.
        script = self.out / "wrapper.sh"
        script.write_text(
            SCRIPT.read_text().replace(
                'if __name__ == "__main__":', f'RELEASE_TABLE[{H!r}] = {self.entry!r}\n\nif __name__ == "__main__":', 1
            )
        )
        env = {
            **os.environ,
            "PARAM_OUTPUT_DIR": str(self.out),
            "PARAM_CHECKLIST": "auto",
            "PARAM_CHECKLIST_FORMATS": "ckl,cklb",
            "PARAM_CHECKLIST_ASSET_NAME": "",
            **params,
        }
        return subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)

    def guard(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return MOD["guard"](["--out-dir", str(self.out), "--results", str(self.out / "results.xml")])

    def test_status_precedence_instances_and_all_text(self):
        self.prepare(
            fixture(
                [
                    ("a", 1, "pass", ()),
                    ("b", 1, "fail", ()),
                    ("c", 2, ["fixed", "notapplicable"], ()),
                    ("d", 3, ["pass", "error"], ()),
                    ("e", 4, "unexpected", ()),
                    ("f", 5, "notapplicable", ()),
                    ("g", 6, ["pass", "fail"], ()),
                    ("h", 7, "notselected", ()),
                ]
            )
        )
        rc, meta = self.generate()
        self.assertEqual(rc, 0)
        rows = self.rows()
        self.assertEqual(
            [r["status"] for r in rows],
            ["open", "not_a_finding", "not_reviewed", "not_reviewed", "not_applicable", "open"],
        )
        self.assertEqual(rows[0]["rule_title"], "b title / a title")
        self.assertIn("b fix", rows[0]["fix_text"])
        self.assertIn("a fix", rows[0]["fix_text"])
        self.assertIn("a rationale", rows[0]["discussion"])
        self.assertIn("check itself", rows[4]["comments"])
        self.assertEqual(meta["stig"]["releaseinfo"], "Release: 9 Benchmark Date: 01 Jul 2026")
        self.assertEqual(meta["host_name"], "local/app:test")
        self.assertIn("sha256:target) [linux/amd64]", rows[0]["finding_details"])
        self.assertEqual(self.summary().returncode, 0)
        self.assertEqual(self.summary(findings="true").returncode, 1)
        self.assertTrue((self.out / "checklist.ckl").exists())

    def test_na_gate_walk_and_compound_evidence(self):
        root = fixture(
            [
                ("host", 1, "notapplicable", ("#package_gdm",)),
                ("pam", 2, "notapplicable", ("#package_pam_and_system_with_kernel",)),
                ("mixed", 3, "notapplicable", ("#package_gdm_and_package_bash",)),
                ("unknown", 4, "notapplicable", ("#not_container_and_wifi-iface",)),
                ("bootc", 5, "notapplicable", ("#not_bootc_and_not_container",)),
                ("kernelpkg", 6, "notapplicable", ("#package_kernel-tools",)),
            ],
            true=("#package_pam", "#not_bootc_and_package_dnf"),
        )
        ET.SubElement(root.find(X + "Group"), X + "platform", idref="#system_with_kernel")
        self.prepare(root)
        self.generate()
        rows = self.rows()
        self.assertIn("host operating system", rows[0]["comments"])
        self.assertNotIn("gdm", rows[0]["comments"])
        self.assertIn("host operating system", rows[1]["comments"])
        self.assertIn("package", rows[2]["comments"])
        self.assertNotIn("graphical-interface", rows[2]["comments"])
        self.assertEqual(
            rows[3]["comments"],
            "Not Applicable. OpenSCAP platform check not_container_and_wifi-iface was false for the scanned image.",
        )
        self.assertIn("host operating system", rows[4]["comments"])
        self.assertIn("kernel-tools package", rows[5]["comments"])
        # On a kernel-bearing bootc-like target only PAM is known false.
        self.prepare(
            fixture(
                [
                    ("pam", 1, "notapplicable", ("#package_pam",)),
                    ("combo", 2, "notapplicable", ("#package_pam_and_system_with_kernel",)),
                ],
                true=("#system_with_kernel",),
            )
        )
        self.generate()
        self.assertIn("pam package", self.rows()[1]["comments"])
        self.prepare(fixture([("bootc", 1, "notapplicable", ("#not_bootc_and_not_container",))]))
        self.generate()
        self.assertNotIn("host operating system", self.rows()[0]["comments"])

    def test_architecture_recomputes_and_never_hides_errors(self):
        specs = [(r, n, r, ("#not_s390x_arch",)) for n, r in enumerate(["pass", "fail", "error", "notchecked"], 1)]
        self.prepare(fixture(specs, true=("#not_s390x_arch",)))
        for platform, expected in [
            ("linux/amd64", ["not_a_finding", "open", "not_reviewed", "not_reviewed"]),
            ("linux/s390x", ["not_applicable", "not_applicable", "not_reviewed", "not_reviewed"]),
            ("", ["not_reviewed"] * 4),
        ]:
            with self.subTest(platform=platform):
                self.plan["image_platform"] = platform
                self.save_plan()
                self.generate()
                self.assertEqual([r["status"] for r in self.rows()], expected)
        self.plan["scanner_platform"] = "linux/arm64"
        self.plan["image_platform"] = "linux/arm64/v8"
        self.save_plan()
        self.generate()
        self.assertEqual(self.rows()[0]["status"], "not_a_finding")
        self.assertIn("scanned on arm64", self.rows()[0]["finding_details"])

    def test_arch_uncertainty_is_combined_before_vid_aggregation(self):
        self.plan["image_platform"] = "linux/s390x"
        self.save_plan()
        self.prepare(
            fixture(
                [
                    ("p", 1, "pass", ()),
                    ("na", 1, "notapplicable", ("#s390x_arch",)),
                    ("fail", 2, "fail", ()),
                    ("na2", 2, "notapplicable", ("#s390x_arch",)),
                ]
            )
        )
        self.generate()
        self.assertEqual([r["status"] for r in self.rows()], ["not_reviewed", "open"])

    def test_arch_or_alternatives_and_opaque_ids(self):
        self.plan["image_platform"] = "linux/amd64"
        self.plan["scanner_platform"] = "linux/arm64"
        self.save_plan()
        self.prepare(
            fixture(
                [
                    ("or", 1, "pass", ("#aarch64_arch", "#package_pam")),
                    ("opaque", 2, "pass", ("#aarch64_arch_or_x86_64_arch",)),
                ],
                true=("#aarch64_arch", "#package_pam", "#aarch64_arch_or_x86_64_arch"),
            )
        )
        self.generate()
        self.assertEqual([r["status"] for r in self.rows()], ["not_a_finding", "not_reviewed"])
        self.plan["image_platform"] = "linux/arm64/v8"
        self.save_plan()
        self.generate()
        self.assertEqual(self.rows()[1]["status"], "not_a_finding")

    def test_rootfs_asset_and_sanitizing(self):
        self.plan.pop("image")
        self.plan.pop("image_id")
        self.plan.pop("image_platform")
        self.plan["rootfs_path"] = "/tmp/tree"
        self.save_plan()
        self.assertEqual(self.generate()[1]["outcome"], "skipped")
        self.assertEqual(self.summary("require").returncode, 1)
        self.assertEqual(self.generate("--host-name", "   \uffff")[1]["outcome"], "failed")
        self.assertEqual(self.generate("--host-name", "app\uffff")[1]["host_name"], "app")
        ET.parse(self.out / "checklist.ckl")
        self.assertIn(
            "Root filesystem /tmp/tree",
            json.loads((self.out / "checklist.cklb").read_text())["target_data"]["comments"],
        )

    def test_malformed_and_incomplete_results(self):
        mutations = [
            lambda r: r.find(X + "TestResult").append(ET.Element(X + "profile", idref=P)),
            lambda r: r.append(copy.deepcopy(r.find(X + "TestResult"))),
            lambda r: r.find(X + "Group").append(copy.deepcopy(r.find(".//" + X + "Rule"))),
            lambda r: r.find(X + "TestResult").remove(r.find(".//" + X + "rule-result")),
            lambda r: r.find(".//" + X + "rule-result").set("idref", "undefined"),
            lambda r: ET.SubElement(r.find(".//" + X + "rule-result"), X + "result").__setattr__("text", "fail"),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                root = fixture()
                mutate(root)
                self.prepare(root, register=False)
                self.assertEqual(self.generate()[1]["outcome"], "failed")
        (self.out / "results.xml").write_text("<truncated")
        self.assertEqual(self.generate()[1]["outcome"], "failed")
        self.assertFalse((self.out / "checklist.ckl").exists())

    def test_hash_identity_and_mapping_contracts(self):
        for key, val in [("results_sha256", "x"), ("profile", "other"), ("scanner_image_id", ""), ("image_id", "")]:
            original = self.plan[key]
            self.plan[key] = val
            self.save_plan()
            self.assertEqual(self.generate()[1]["outcome"], "failed", key)
            self.plan[key] = original
        self.save_plan()
        root = fixture()
        root.find(X + "version").text = "0.1.83"
        self.prepare(root)
        self.assertEqual(self.generate()[1]["outcome"], "failed")
        self.prepare(fixture())
        root = fixture([("one", 1, "notselected", ())])
        self.prepare(root, register=False)
        self.assertEqual(self.generate()[1]["outcome"], "failed")
        self.prepare(fixture())
        self.plan["datastream_sha256"] = "unknown"
        self.save_plan()
        self.assertEqual(self.generate()[1]["outcome"], "skipped")
        self.assertEqual(self.summary("require").returncode, 1)

    def test_non_stig_skip_and_disabled_generation(self):
        self.prepare(fixture(profile="xccdf_org.ssgproject.content_profile_cis_server_l1"))
        self.assertEqual(self.generate()[1]["outcome"], "skipped")
        self.assertEqual(self.summary().returncode, 0)
        self.assertEqual(self.summary("require").returncode, 1)
        self.prepare(fixture())
        self.generate()
        self.assertEqual(self.generate("--mode", "none")[1]["outcome"], "skipped")
        self.assertFalse((self.out / "checklist.ckl").exists())

    def test_pairing_fallback_repeated_refs_and_rule_ver(self):
        self.prepare(
            fixture(
                [
                    (
                        "a",
                        1,
                        "pass",
                        (),
                        [
                            ("sv", "SV-1r1_rule"),
                            ("v", "V-1"),
                            ("v", "V-1"),
                            ("v", "V-2"),
                            ("sv", "SV-3r1_rule"),
                            ("sv", "SV-123garbage"),
                            ("v", "XX123"),
                            ("stig", "RHEL-09-111111"),
                        ],
                    ),
                    ("fallback", 4, "pass", (), [("sv", "SV-4r1_rule"), ("stig", "RHEL-09-222222")]),
                ]
            )
        )
        rc, meta = self.generate()
        self.assertEqual(rc, 0)
        self.assertEqual([r["group_id"] for r in self.rows()], ["V-1", "V-4"])
        self.assertEqual(self.rows()[0]["rule_version"], "")
        self.assertEqual(self.rows()[1]["rule_version"], "RHEL-09-222222")
        self.assertEqual(len(meta["unpaired_refs"]), 4)
        self.assertIn("(1 SSG rule)", self.rows()[0]["finding_details"])
        self.prepare(fixture([("ambiguous", 1, "pass", (), [("sv", "SV-1r1_rule"), ("sv", "SV-1r2_rule")])]))
        self.assertEqual(self.generate()[1]["outcome"], "skipped")

    def test_formats_symlinks_and_guard(self):
        outside = self.out / "untouched"
        outside.write_text("original")
        for name in [
            "checklist.ckl.partial",
            "checklist.cklb.partial",
            "checklist-meta.json.partial",
            "checklist.ckl",
            "checklist.cklb",
            "checklist-meta.json",
        ]:
            (self.out / name).symlink_to(outside)
        self.assertEqual(self.generate("--formats", "CKL, ckl")[1]["outcome"], "generated")
        self.assertEqual(outside.read_text(), "original")
        self.assertFalse((self.out / "checklist.cklb").exists())
        self.guard()
        self.assertTrue((self.out / "checklist.ckl").exists())
        for formats in ["", "pdf", "ckl,,pdf"]:
            self.assertEqual(self.generate("--formats", formats)[1]["outcome"], "failed")
        self.generate("--formats", "cklb")
        self.assertFalse((self.out / "checklist.ckl").exists())
        (self.out / "checklist.cklb").write_text("tampered")
        self.assertEqual(self.summary().returncode, 1)
        self.guard()
        self.assertFalse((self.out / "checklist.cklb").exists())
        self.generate()
        (self.out / "results.xml").unlink()
        self.guard()
        self.assertFalse((self.out / "checklist.ckl").exists())

    def test_publish_and_writer_failure_cleanup(self):
        replace = os.replace
        for fail_at in ["checklist.cklb", "checklist-meta.json"]:

            def failure(src, dst):
                if str(dst).endswith(fail_at) and (self.out / "checklist.ckl").exists():
                    raise OSError("injected rename failure")
                return replace(src, dst)

            rc, meta = self.generate(fault=patch.object(os, "replace", failure))
            self.assertEqual(meta["outcome"], "failed")
            self.assertEqual(rc, 1)
            self.assertFalse((self.out / "checklist.ckl").exists())
            self.assertFalse((self.out / "checklist.cklb").exists())
        rc, meta = self.generate(
            fault=patch.dict(MOD, {"write_cklb": lambda *args: (_ for _ in ()).throw(OSError("writer failure"))})
        )
        self.assertEqual(meta["outcome"], "failed")
        self.assertFalse(list(self.out.glob("*.partial")))

    def test_termination_cleanup_and_kill_guard(self):
        replace = os.replace

        def terminate(src, dst):
            if str(dst).endswith("checklist.cklb"):
                os.kill(os.getpid(), signal.SIGTERM)
            return replace(src, dst)

        self.assertEqual(self.generate(fault=patch.object(os, "replace", terminate))[1]["outcome"], "failed")
        self.assertFalse((self.out / "checklist.ckl").exists())
        # A hard kill cannot unwind. Exercise a real subprocess at publication.
        driver = CODE.rsplit('if __name__ == "__main__":', 1)[0] + """
entry = ENTRY
RELEASE_TABLE[HASH] = entry
replace = os.replace
def killed(src, dst):
    if str(dst).endswith('checklist.cklb'):
        os.kill(os.getpid(), signal.SIGKILL)
    return replace(src, dst)
os.replace = killed
main()
"""
        driver = driver.replace("ENTRY", repr(self.entry)).replace("HASH", repr(H))
        driver_path = self.out / "kill-driver.py"
        driver_path.write_text(driver)
        result = subprocess.run(
            [
                sys.executable,
                str(driver_path),
                "--results",
                str(self.out / "results.xml"),
                "--plan",
                str(self.out / "scan-plan.env"),
                "--out-dir",
                str(self.out),
            ],
            capture_output=True,
        )
        self.assertEqual(result.returncode, -signal.SIGKILL)
        self.assertNotEqual(json.loads((self.out / "checklist-meta.json").read_text())["outcome"], "generated")
        self.guard()
        self.assertFalse((self.out / "checklist.ckl").exists())

    def test_benchmark_platform_and_meta_missing(self):
        self.prepare(fixture([("one", 1, "notapplicable", ("#package_gdm",))], bench_gates=("#rhel9",)))
        self.assertEqual(self.generate()[1]["outcome"], "skipped")
        self.prepare(fixture(bench_gates=("#rhel9",)))
        self.assertEqual(self.generate()[1]["outcome"], "failed")
        self.prepare(fixture())
        self.generate()
        (self.out / "checklist-meta.json").unlink()
        self.assertEqual(self.summary().returncode, 1)
        self.assertEqual(self.summary("none").returncode, 0)
        self.assertTrue((self.out / "summary.txt").exists())
        self.assertTrue((self.out / "provenance.json").exists())

    def test_size_cap_and_xml_escaping(self):
        self.assertEqual(self.generate(fault=patch.dict(MOD, {"MAX_RESULTS_BYTES": 10}))[1]["outcome"], "failed")
        root = fixture()
        root.find(".//" + X + "title").text = '<& " text'
        self.prepare(root)
        self.generate()
        ET.parse(self.out / "checklist.ckl")
        self.plan["image_id"] = "bad\uffff"
        self.save_plan()
        self.assertEqual(self.generate()[1]["outcome"], "failed")
        self.assertFalse((self.out / "checklist.ckl").exists())

    def test_always_run_guard_never_writes_overlapping_rootfs(self):
        self.generate()
        before = (self.out / "checklist.ckl").read_bytes()
        with contextlib.redirect_stderr(io.StringIO()):
            rc = MOD["guard"](
                ["--out-dir", str(self.out), "--results", "/missing/results.xml", "--rootfs-path", str(self.out)]
            )
        self.assertEqual(rc, 1)
        self.assertEqual((self.out / "checklist.ckl").read_bytes(), before)

    def test_dash_prefixed_values_cannot_accept_stale_asset_output(self):
        self.assertEqual(self.wrapper(PARAM_CHECKLIST_ASSET_NAME="old-asset").returncode, 0)
        for name in ("-new-asset", "--help", "--formats=cklb"):
            with self.subTest(name=name):
                result = self.wrapper(PARAM_CHECKLIST_ASSET_NAME=name)
                self.assertEqual(result.returncode, 0, result.stderr)
                meta = json.loads((self.out / "checklist-meta.json").read_text())
                self.assertEqual(meta["host_name"], name)
                self.assertEqual(meta["outcome"], "generated")
                self.assertEqual(self.summary("require").returncode, 0)
        self.wrapper(PARAM_CHECKLIST_FORMATS="-pdf")
        self.assertEqual(json.loads((self.out / "checklist-meta.json").read_text())["outcome"], "failed")
        self.assertFalse((self.out / "checklist.ckl").exists())
        self.assertEqual(self.summary().returncode, 1)

    def test_circleci_substitution_cli_also_preserves_option_like_values(self):
        cli_dir = self.out / "bin"
        cli_dir.mkdir()
        cli = cli_dir / "circleci"
        # The value must arrive on stdin: as an argument, the real CLI would
        # parse "--help" as its own flag.
        cli.write_text("""#!/bin/sh
[ "$1 $2" = "env subst" ] || exit 2
[ "$#" -eq 2 ] || { echo "value passed as an argument" >&2; exit 2; }
cat
""")
        cli.chmod(0o755)
        result = self.wrapper(PATH=str(cli_dir) + os.pathsep + os.environ["PATH"], PARAM_CHECKLIST_ASSET_NAME="--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((self.out / "checklist-meta.json").read_text())["host_name"], "--help")

    def test_rootfs_na_wording_does_not_assume_a_container_or_separate_host(self):
        self.prepare(
            fixture(
                [
                    ("firmware", 1, "notapplicable", ("#uefi",)),
                    ("kernel", 2, "notapplicable", ("#system_with_kernel",)),
                    ("gui", 3, "notapplicable", ("#package_gdm",)),
                    ("check", 4, "notapplicable", ()),
                    ("package", 5, "notapplicable", ("#package_imagemagick",)),
                ]
            )
        )
        self.generate()
        self.assertIn("container image", self.rows()[0]["comments"])
        for key in ("image", "image_id", "image_platform"):
            self.plan.pop(key)
        self.plan["rootfs_path"] = "/mnt/vm-disk"
        self.save_plan()
        self.assertEqual(self.generate("--host-name=vm-disk")[1]["outcome"], "generated")
        rows = self.rows()
        for row in rows:
            self.assertEqual(row["status"], "not_applicable")
            self.assertIn("root filesystem", row["comments"])
            self.assertNotIn("container", row["comments"])
            self.assertNotIn("receives from", row["comments"])
            self.assertNotIn("host's / platform's STIG checklist", row["comments"])
        self.assertIn("platform check uefi was false", rows[0]["comments"])
        self.assertIn("intended deployment", rows[0]["comments"])
        self.assertIn("imagemagick package", rows[4]["comments"])
        self.assertIn("package_imagemagick", rows[4]["comments"])

    def test_rpm_inventory_missing_skips_unsupported_absence_claims(self):
        self.prepare(fixture([("package", 1, "notapplicable", ("#package_gdm",)), ("evaluated", 2, "pass", ())]))
        self.plan.update(rpm_status="missing", rpm_status_reason="RPM query failed")
        self.save_plan()
        rc, meta = self.generate()
        self.assertEqual(rc, 0)
        self.assertEqual(meta["outcome"], "skipped")
        self.assertIn("rpm_status=missing", meta["reason"])
        self.assertIn("Restore a usable RPM database", meta["reason"])
        self.assertFalse((self.out / "checklist.ckl").exists())
        self.assertEqual(self.summary(mode="auto").returncode, 0)
        self.assertEqual(self.summary(mode="require").returncode, 1)
        self.plan.update(rpm_status="available", rpm_status_packages="12", rpm_status_reason="")
        self.save_plan()
        self.assertEqual(self.generate()[1]["outcome"], "generated")

    def test_rpm_scanner_query_requires_readable_nonempty_inventory(self):
        scan = (ROOT / "src/scripts/scan.sh").read_text()
        section = scan.split('RPM_STATUS=""', 1)[1].split("# The scanner writes", 1)[0]
        cli_dir = self.out / "rpm-bin"
        cli_dir.mkdir()
        rpm = cli_dir / "rpm"
        rpm.write_text("""#!/bin/sh
[ "$1 $2 $3" = "--root /target -qa" ] || exit 2
case "$RPM_PROBE_CASE" in
    available) printf 'one\\ntwo\\n' ;;
    empty) exit 0 ;;
    failed) echo 'cannot open RPM database' >&2; exit 1 ;;
esac
""")
        rpm.chmod(0o755)
        script = (
            r"""set -euo pipefail
ROOTFS_MOUNT=( -v /mounted/disk:/target:ro )
SCANNER_ID=sha256:exact-scanner
FAMILY=rpm
docker() {
    case " $* " in *" --network none -u 0:0 -v /mounted/disk:/target:ro --entrypoint sh sha256:exact-scanner -c "*) ;; *) exit 2 ;; esac
    sh -c "${!#}"
}
RPM_STATUS="""
            + section
            + """
printf '\nSTATE=%s\nPACKAGES=%s\n' "$RPM_STATUS" "$RPM_STATUS_PACKAGES"
"""
        )
        for case in ("available", "empty", "failed"):
            with self.subTest(case=case):
                result = subprocess.run(
                    ["bash", "-c", script],
                    env=dict(os.environ, PATH=str(cli_dir) + os.pathsep + os.environ["PATH"], RPM_PROBE_CASE=case),
                    text=True,
                    capture_output=True,
                    check=True,
                )
                self.assertIn("STATE=" + ("available" if case == "available" else "missing"), result.stdout)
                if case == "available":
                    self.assertIn("PACKAGES=2", result.stdout)
                else:
                    self.assertIn("package absence cannot be verified", result.stderr)

    def test_scanner_records_plain_absence_and_unusable_dpkg_inventory(self):
        scan = (ROOT / "src/scripts/scan.sh").read_text()
        section = scan.split('DPKG_STATUS=""', 1)[1].split("# --- 4.", 1)[0]
        tree = self.out / "rootfs"
        database = tree / "var/lib/dpkg"
        database.mkdir(parents=True)
        script = (
            r"""set -euo pipefail
# Simulate a runner that cannot inspect root-owned package paths. The
# container stub evaluates the actual helper payload with readable data.
rootfs_has() { return 1; }
ROOTFS_MOUNT=( -v "$ROOTFS_DIR:/target:ro" )
resolve_donor() { DONOR_ID=test-donor; }
docker() {
    local payload="${!#}"
    payload="${payload//d=\/target\/var\/lib\/dpkg/d=$ROOTFS_DIR/var/lib/dpkg}"
    payload="${payload//\/target\//$ROOTFS_DIR/}"
    case " $* " in *" --network none -u 0:0 "*) ;; *) exit 2 ;; esac
    if [ "$CLEANUP_ROOTFS" = "0" ]; then
        case " $* " in *":/target:ro "*) ;; *) exit 2 ;; esac
    fi
    STANZA_AWK="${stanza_awk:-}" sh -c "$payload"
}
DPKG_STATUS="""
            + section
            + """
printf '\nSTATE=%s\nREASON=%s\n' "$DPKG_STATUS" "$DPKG_STATUS_REASON"
"""
        )

        def probe(image):
            return subprocess.run(
                ["bash", "-c", script],
                env=dict(os.environ, ROOTFS_DIR=str(tree), FAMILY="dpkg", CLEANUP_ROOTFS="1" if image else "0"),
                text=True,
                capture_output=True,
                check=True,
            ).stdout

        for image in (False, True):
            with self.subTest(image=image, layout="absent"):
                self.assertIn("STATE=missing", probe(image))
        status = database / "status"
        external = self.out / "external-status"
        external.write_text("Package: outside\nStatus: install ok installed\n\n")
        status.symlink_to(external)
        for image in (False, True):
            with self.subTest(image=image, layout="outside-symlink"):
                self.assertIn("STATE=missing", probe(image))
        status.unlink()
        status.mkdir()
        for image in (False, True):
            with self.subTest(image=image, layout="directory"):
                self.assertIn("STATE=missing", probe(image))
        status.rmdir()
        status.symlink_to("missing")
        for image in (False, True):
            with self.subTest(image=image, layout="dangling-symlink"):
                self.assertIn("STATE=missing", probe(image))
        status.unlink()
        status.write_text("Package: test\nStatus: install ok installed\n\n")
        for image in (False, True):
            with self.subTest(image=image, layout="present"):
                self.assertNotIn("STATE=missing", probe(image))
        status.unlink()
        fragments = database / "status.d"
        fragments.mkdir()
        (fragments / "test").write_text("Package: test\nVersion: 1\n")
        self.assertIn("STATE=missing", probe(False))
        self.assertFalse(status.exists())
        self.assertIn("STATE=synthesized", probe(True))
        self.assertIn("Status: install ok installed", status.read_text())

    def test_missing_dpkg_database_skips_supported_stig_without_absence_claims(self):
        benchmark = "xccdf_org.ssgproject.content_benchmark_UBUNTU_22-04"
        self.prepare(
            fixture(
                [
                    ("file", 1, "pass", ()),
                    ("gui", 2, "notapplicable", ("#package_gdm",)),
                    ("host", 3, "notapplicable", ("#system_with_kernel",)),
                ],
                benchmark=benchmark,
            )
        )
        self.entry = (benchmark, *self.entry[1:])
        self.plan["dpkg_status"] = "missing"
        self.plan["dpkg_status_reason"] = "the orb does not modify a rootfs_path tree"
        self.plan["rootfs_path"] = "/tmp/distroless-ubuntu"
        for key in ("image", "image_id", "image_platform"):
            self.plan.pop(key)
        self.save_plan()
        rc, meta = self.generate("--host-name=ubuntu-app")
        self.assertEqual(rc, 0)
        self.assertEqual(meta["outcome"], "skipped")
        self.assertIn("dpkg_status=missing", meta["reason"])
        self.assertIn("Repair /var/lib/dpkg/status", meta["reason"])
        self.assertFalse((self.out / "checklist.ckl").exists())
        self.assertFalse((self.out / "checklist.cklb").exists())
        self.assertEqual(self.summary().returncode, 0)
        self.assertEqual(self.summary("require").returncode, 1)
        self.plan["dpkg_status"] = "synthesized"
        self.save_plan()
        self.assertEqual(self.generate("--host-name=ubuntu-app")[1]["outcome"], "generated")

    def test_deferred_finding_gate_preserves_checklist_then_fails_job(self):
        self.prepare(fixture([("fail", 1, "fail", ())]))
        self.generate()
        self.assertEqual(self.summary(findings="true", defer="true").returncode, 0)
        self.assertEqual((self.out / "summary.txt.exit-code").read_text(), "1\n")
        self.assertEqual(self.guard(), 0)
        self.assertTrue((self.out / "checklist.ckl").exists())
        self.assertEqual(self.enforce_gate().returncode, 1)
        self.assertFalse((self.out / "summary.txt.exit-code").exists())
        self.assertEqual(self.summary(defer="true").returncode, 0)
        self.assertEqual(self.enforce_gate().returncode, 0)

    def test_deferred_checklist_policy_and_parse_errors_still_fail_closed(self):
        self.prepare(fixture(profile="xccdf_org.ssgproject.content_profile_cis_server_l1"))
        self.generate()
        self.assertEqual(self.summary("require", defer="true").returncode, 0)
        self.assertEqual(self.enforce_gate().returncode, 1)
        (self.out / "summary.txt.exit-code").write_text("0\n")
        (self.out / "results.xml").write_text("<truncated")
        self.assertNotEqual(self.summary(defer="true").returncode, 0)
        self.assertFalse((self.out / "summary.txt.exit-code").exists())
        self.assertEqual(self.enforce_gate().returncode, 2)
        (self.out / "summary.txt.exit-code").write_text("not-a-verdict\n")
        self.assertEqual(self.enforce_gate().returncode, 2)

    def test_final_gate_does_not_modify_refused_rootfs_tree(self):
        gate = self.out / "summary.txt.exit-code"
        gate.write_text("0\n")
        self.assertEqual(self.enforce_gate(rootfs=str(self.out)).returncode, 2)
        self.assertEqual(gate.read_text(), "0\n")

    @unittest.skipIf(os.geteuid() == 0, "read-only directory reproduction needs a non-root runner")
    def test_unremovable_bad_checklist_fails_guard_without_losing_scan_evidence(self):
        self.generate()
        self.assertEqual(self.wrapper().returncode, 0)
        self.summary(defer="true")
        (self.out / "report.html").write_text("scan report")
        (self.out / "checklist-meta.json").write_text("{}")
        ordinary = {
            name: (self.out / name).read_bytes()
            for name in ("results.xml", "report.html", "summary.txt", "provenance.json", "scan-plan.env")
        }
        self.out.chmod(0o555)
        try:
            result = self.wrapper(PARAM_CHECKLIST_GUARD="true")
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertTrue((self.out / "checklist.ckl").exists())
            for name, data in ordinary.items():
                self.assertEqual((self.out / name).read_bytes(), data)
        finally:
            self.out.chmod(0o700)

    def test_job_only_uploads_checklists_after_successful_guard(self):
        # This policy is what makes an unremovable source checklist safe:
        # store_artifacts cannot have when:always or upload the whole directory.
        job = (ROOT / "src/jobs/scan.yml").read_text()
        guard = job.index("name: Guard checklist artifacts before upload")
        final_gate = job.index("name: Enforce summarized scan policies")
        uploads = list(re.finditer(r"(?ms)^  - store_artifacts:\n(.*?)(?=^  - |\Z)", job))
        self.assertEqual(len(uploads), 9)
        for step in uploads:
            body = step.group(1)
            if "path: <<parameters.output_dir>>/checklist.ckl" in body:
                self.assertGreater(step.start(), guard)
                self.assertLess(step.start(), final_gate)
                self.assertIn("when: on_success", body)
            else:
                self.assertLess(step.start(), guard)
                self.assertIn("when: always", body)
        self.assertIn("defer_gate: true", job)

    def test_guard_finishes_cleanup_after_one_removal_error(self):
        self.generate()
        (self.out / "checklist-meta.json").write_text("{}")
        remove = os.remove

        def failure(path):
            if str(path).endswith("checklist.ckl"):
                raise PermissionError("injected cleanup failure")
            remove(path)

        with patch.object(os, "remove", failure), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ):
            self.assertEqual(MOD["guard"](["--out-dir", str(self.out), "--results", str(self.out / "results.xml")]), 1)
        self.assertFalse((self.out / "checklist.cklb").exists())

    def test_unknown_benchmark_with_known_datastream_hash_fails(self):
        self.prepare(fixture(benchmark="xccdf_custom_benchmark"), register=False)
        self.assertEqual(self.generate()[1]["outcome"], "failed")

    def test_empty_mapping_is_skipped(self):
        self.prepare(fixture([("no_mapping", 1, "pass", (), [])]))
        self.assertEqual(self.generate()[1]["outcome"], "skipped")
        self.assertEqual(self.summary("require").returncode, 1)

    def test_pre_scan_cleanup_preserves_symlink_targets_and_rootfs(self):
        outside = self.out / "outside"
        outside.write_text("keep")
        for name in ["checklist-meta.json", "checklist.ckl", "checklist.cklb.partial"]:
            (self.out / name).symlink_to(outside)
        env = {**os.environ, "PARAM_OUTPUT_DIR": str(self.out)}
        result = subprocess.run(["bash", str(ROOT / "src/scripts/reserve-output.sh")], env=env, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(outside.read_text(), "keep")
        (self.out / "checklist.ckl").write_text("keep rootfs")
        env["PARAM_ROOTFS_PATH"] = str(self.out)
        result = subprocess.run(["bash", str(ROOT / "src/scripts/reserve-output.sh")], env=env, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual((self.out / "checklist.ckl").read_text(), "keep rootfs")

    def test_fingerprint_requires_one_complete_unambiguous_release(self):
        # A hand-made skeleton contains only identifiers; no DISA text is shipped.
        self.prepare(fixture())
        candidates = self.out / "candidates"
        candidates.mkdir()
        skeleton = ET.Element(X + "Benchmark")
        ET.SubElement(skeleton, X + "Rule", id="SV-1r1_rule")
        ET.SubElement(skeleton, X + "plain-text", id="release-info").text = "Release: 9 Benchmark Date: 01 Jul 2026"
        (candidates / "one.xml").write_bytes(ET.tostring(skeleton))
        argv = [
            sys.executable,
            str(ROOT / "tools/fingerprint-stig.py"),
            str(self.out / "results.xml"),
            str(candidates / "*.xml"),
        ]
        self.assertEqual(subprocess.run(argv, capture_output=True).returncode, 0)
        (candidates / "two.xml").write_bytes(ET.tostring(skeleton))
        self.assertNotEqual(subprocess.run(argv, capture_output=True).returncode, 0)
        (candidates / "two.xml").unlink()
        self.prepare(fixture([("extra", 1, "pass", (), [("sv", "SV-1r1_rule"), ("v", "V-2")])]))
        self.assertNotEqual(subprocess.run(argv, capture_output=True).returncode, 0)
        self.prepare(fixture([("no_mapping", 1, "pass", (), [])]))
        self.assertNotEqual(subprocess.run(argv, capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
