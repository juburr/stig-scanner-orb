"""CI-only interoperability checks against both exact pinned OpenSCAP engines."""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
scan = (ROOT / "src/scripts/scan.sh").read_text()
preflight = {"__name__": "compat"}
exec(scan.split("<<'PY_TAILORING'\n", 1)[1].split("\nPY_TAILORING\n", 1)[0], preflight)
checklist = {"__name__": "compat"}
exec(
    (ROOT / "src/scripts/checklist.sh").read_text().split("<<'PY_CHECKLIST'\n", 1)[1].split("\nPY_CHECKLIST\n", 1)[0],
    checklist,
)
X = checklist["X12"]
P = "xccdf_org.ssgproject.content_profile_stig"
MID = "xccdf_org.example_profile_intermediary"
CUSTOM = "xccdf_org.example_profile_custom"
V = "xccdf_org.example_value_setting"
G = "xccdf_org.example_group_items"
RULES = ["xccdf_org.example_rule_one", "xccdf_org.example_rule_two"]
ET.register_namespace("", X[1:-1])


def benchmark():
    root = ET.Element(X + "Benchmark", id="xccdf_org.example_benchmark_compat")
    for tag, value in [("status", "draft"), ("title", "Compatibility"), ("version", "1")]:
        ET.SubElement(root, X + tag).text = value
    for pid, base in [(P, None), (MID, P)]:
        p = ET.SubElement(root, X + "Profile", id=pid, **({"extends": base} if base else {}))
        ET.SubElement(p, X + "title").text = pid
    # An inherited benchmark alias must also be materialized; the local
    # override must win after expansion without duplicate concrete idrefs.
    ET.SubElement(p, X + "set-value", idref="settings").text = "intermediary"
    value = ET.SubElement(root, X + "Value", id=V, type="string", **{"cluster-id": "settings"})
    ET.SubElement(value, X + "title").text = "Setting"
    ET.SubElement(value, X + "value").text = "original"
    group = ET.SubElement(root, X + "Group", id=G, selected="true", **{"cluster-id": "groups"})
    ET.SubElement(group, X + "title").text = "Items"
    for rid in RULES:
        rule = ET.SubElement(group, X + "Rule", id=rid, selected="true", severity="low", **{"cluster-id": "rules"})
        ET.SubElement(rule, X + "title").text = rid
    return root


def tailoring(group_case):
    root = ET.Element(X + "Tailoring", id="xccdf_org.example_tailoring_compat")
    ET.SubElement(root, X + "benchmark", href="benchmark.xml")
    ET.SubElement(root, X + "version", time="2026-10-15T00:00:00Z").text = "1"
    p = ET.SubElement(root, X + "Profile", id=CUSTOM, extends=MID)
    ET.SubElement(p, X + "title").text = "Custom"
    ET.SubElement(p, X + "select", idref="groups" if group_case else "rules", selected="false")
    if group_case:
        ET.SubElement(p, X + "select", idref=RULES[0], selected="true")
    ET.SubElement(p, X + "set-value", idref="settings").text = "custom"
    return root


images = [
    re.search(r"^" + name + r'="([^"]+)"$', scan, re.M).group(1)
    for name in ("DEFAULT_RPM_SCANNER_IMAGE", "DEFAULT_CHAINGUARD_IMAGE")
]
for image in images:
    for group_case in (False, True):
        with tempfile.TemporaryDirectory(prefix="stig-tailoring-compat-") as directory:
            directory = Path(directory)
            ET.ElementTree(benchmark()).write(directory / "benchmark.xml", encoding="utf-8", xml_declaration=True)
            # Deliberately compact: adjacent generated empty selectors exposed
            # a real skip in the pinned RPM XML reader without separators.
            ET.ElementTree(tailoring(group_case)).write(
                directory / "original.xml", encoding="utf-8", xml_declaration=True
            )
            meta = preflight["prepare"](
                str(directory / "original.xml"),
                str(directory / "benchmark.xml"),
                CUSTOM,
                str(directory / "evaluated.xml"),
            )
            assert meta["base_profile_ancestry"] == [MID, P]
            assert meta["deselected_rules"] == RULES
            subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "-u",
                    "0:0",
                    "-v",
                    str(directory) + ":/out",
                    "-e",
                    "HOST_UID=" + str(os.getuid()),
                    "-e",
                    "HOST_GID=" + str(os.getgid()),
                    "--entrypoint",
                    "sh",
                    image,
                    "-c",
                    "set -eu; oscap xccdf validate --skip-schematron /out/evaluated.xml; "
                    "oscap xccdf eval --profile " + CUSTOM + " --tailoring-file /out/evaluated.xml "
                    "--results /out/results.xml /out/benchmark.xml; "
                    'chown "$HOST_UID:$HOST_GID" /out/results.xml',
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            res = checklist["parse_results"](str(directory / "results.xml"), meta)
            checklist["validate_tailored_results"](res, meta)
            assert res["results"] == {rid: "notselected" for rid in RULES}, res["results"]
            assert res["set_values"][V] == "custom", res["set_values"]
        print(f"{image}: {'group hierarchy' if group_case else 'rule cluster'} and value-cluster settings applied")
