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


def benchmark(case):
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
    if case == "base-group":
        ET.SubElement(root.find(X + "Profile"), X + "select", idref=G, selected="false")
    if case == "default-group":
        group.set("selected", "false")
    if case == "inherited-value":
        value.set("extends", V + "_base")
        base_value = ET.Element(X + "Value", id=V + "_base", type="string")
        ET.SubElement(base_value, X + "title").text = "Inherited setting"
        ET.SubElement(base_value, X + "value", selector="high").text = "20"
        root.insert(list(root).index(value), base_value)
        p.remove(p.find(X + "set-value"))
    if case == "requires":
        ET.SubElement(list(group)[2], X + "requires", idref=RULES[0])
    if case == "conflicts":
        ET.SubElement(list(group)[2], X + "conflicts", idref=RULES[0])
    if case in ("fallback", "fallback-base-set", "fallback-local-set", "set-after-refine"):
        if case != "fallback-base-set":
            p.remove(p.find(X + "set-value"))
        else:
            p.find(X + "set-value").text = "25"
        value.set("type", "number")
        value.find(X + "value").text = "15"
        ET.SubElement(value, X + "lower-bound", selector="bounded").text = "10"
    if case in ("refine-after-set", "partial-refine-last"):
        ET.SubElement(value, X + "value", selector="high").text = "20"
    return root


def tailoring(case):
    root = ET.Element(X + "Tailoring", id="xccdf_org.example_tailoring_compat")
    ET.SubElement(root, X + "benchmark", href="benchmark.xml")
    ET.SubElement(root, X + "version", time="2026-10-15T00:00:00Z").text = "1"
    p = ET.SubElement(
        root, X + "Profile", id=P if case == "shadow" else CUSTOM, extends=P if case == "shadow" else MID
    )
    ET.SubElement(p, X + "title").text = "Custom"
    if case in ("requires", "conflicts"):
        ET.SubElement(p, X + "select", idref=RULES[0], selected="false" if case == "requires" else "true")
    elif case in ("base-group", "default-group"):
        for rid in RULES:
            ET.SubElement(p, X + "select", idref=rid, selected="true")
    else:
        ET.SubElement(p, X + "select", idref="groups" if case == "group" else "rules", selected="false")
        if case == "group":
            ET.SubElement(p, X + "select", idref=RULES[0], selected="true")
    if case == "rule-refinement":
        ET.SubElement(p, X + "select", idref=RULES[0], selected="true")
        ET.SubElement(
            p, X + "refine-rule", idref=RULES[0], role="unchecked", severity="high", weight="2.5", selector="alternate"
        )
    if case == "inherited-metadata":
        for element in list(p):
            if element.tag in (X + "select", X + "set-value", X + "refine-value", X + "refine-rule"):
                p.remove(element)
        ET.SubElement(ET.SubElement(p, X + "metadata"), "{urn:stig:compat}note").text = "Retained metadata"
        return root
    if case == "repeated":
        ET.SubElement(p, X + "select", idref=RULES[0], selected="true")
        ET.SubElement(p, X + "select", idref=RULES[0], selected="false")
        ET.SubElement(p, X + "set-value", idref=V).text = "first"
    if case in ("fallback-local-set", "refine-after-set"):
        ET.SubElement(p, X + "set-value", idref=V).text = "25"
    if case in (
        "fallback",
        "fallback-base-set",
        "fallback-local-set",
        "set-after-refine",
        "inherited-value",
        "refine-after-set",
        "partial-refine-last",
    ):
        selector = "high" if case in ("inherited-value", "refine-after-set", "partial-refine-last") else "bounded"
        ET.SubElement(p, X + "refine-value", idref=V, selector=selector)
        if case in ("set-after-refine", "partial-refine-last"):
            ET.SubElement(p, X + "set-value", idref=V).text = "25"
        if case == "partial-refine-last":
            ET.SubElement(p, X + "refine-value", idref=V, operator="equals")
    else:
        ET.SubElement(p, X + "set-value", idref="settings").text = "custom"
    return root


images = [
    re.search(r"^" + name + r'="([^"]+)"$', scan, re.M).group(1)
    for name in ("DEFAULT_RPM_SCANNER_IMAGE", "DEFAULT_CHAINGUARD_IMAGE")
]
for image in images:
    for case in (
        "rule-cluster",
        "group",
        "base-group",
        "default-group",
        "fallback",
        "fallback-base-set",
        "fallback-local-set",
        "refine-after-set",
        "set-after-refine",
        "partial-refine-last",
        "inherited-value",
        "requires",
        "conflicts",
        "repeated",
        "rule-refinement",
        "inherited-metadata",
        "shadow",
    ):
        with tempfile.TemporaryDirectory(prefix="stig-tailoring-compat-") as directory:
            directory = Path(directory)
            bench = benchmark(case)
            for element in bench.iter():
                for child in element:
                    child.tail = "\n  "
            ET.ElementTree(bench).write(directory / "benchmark.xml", encoding="utf-8", xml_declaration=True)
            # Deliberately compact: adjacent generated empty selectors exposed
            # a real skip in the pinned RPM XML reader without separators.
            ET.ElementTree(tailoring(case)).write(directory / "original.xml", encoding="utf-8", xml_declaration=True)
            selected_profile = P if case == "shadow" else CUSTOM
            meta = preflight["prepare"](
                str(directory / "original.xml"),
                str(directory / "benchmark.xml"),
                selected_profile,
                str(directory / "evaluated.xml"),
            )
            assert meta["base_profile_ancestry"] == ([P] if case == "shadow" else [MID, P])
            expected_deselected = (
                [RULES[0]]
                if case == "requires"
                else (
                    [RULES[1]]
                    if case == "rule-refinement"
                    else [] if case in ("conflicts", "inherited-metadata") else RULES
                )
            )
            assert meta["deselected_rules"] == expected_deselected, meta["deselected_rules"]
            if case == "inherited-value":
                assert not meta["value_fallbacks_materialized"]
                assert meta["values"][V]["value"] == "20"
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
                    "oscap xccdf eval --profile " + selected_profile + " --tailoring-file /out/evaluated.xml "
                    "--results /out/results.xml /out/benchmark.xml; "
                    'chown "$HOST_UID:$HOST_GID" /out/results.xml',
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            res = checklist["parse_results"](str(directory / "results.xml"), meta)
            checklist["validate_tailored_results"](res, meta)
            expected_results = {rid: "notselected" for rid in RULES}
            if case in ("conflicts", "rule-refinement"):
                expected_results[RULES[0]] = "notchecked"
            if case == "inherited-metadata":
                expected_results = {rid: "notchecked" for rid in RULES}
            assert res["results"] == expected_results, res["results"]
            expected = (
                "15"
                if case in ("fallback", "fallback-base-set", "fallback-local-set")
                else (
                    "20"
                    if case in ("inherited-value", "refine-after-set")
                    else (
                        "25"
                        if case in ("set-after-refine", "partial-refine-last")
                        else "intermediary" if case == "inherited-metadata" else "custom"
                    )
                )
            )
            assert res["set_values"][V] == expected, res["set_values"]
            if case == "rule-refinement":
                actual = res["rule_properties"][RULES[0]][0]
                assert actual["role"] == "unchecked" and actual["severity"] == "high", actual
                assert float(actual["weight"]) == 2.5, actual
                request = meta["rule_refinements"][RULES[0]]["directives"][0]
                assert request["attributes"]["selector"] == "alternate", request
        print(f"{image}: {case} selections and resolved values verified")
