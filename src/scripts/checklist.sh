#!/usr/bin/env bash
# Offline STIG checklist generation. summarize remains the job's gatekeeper.
set -euo pipefail
subst() {
    if command -v circleci >/dev/null 2>&1; then
        circleci env subst -- "$1"
    else
        printf '%s\n' "$1"
    fi
}
OUTPUT_DIR="$(subst "${PARAM_OUTPUT_DIR:-build/stig}")"
CHECKLIST="$(subst "${PARAM_CHECKLIST:-auto}")"
FORMATS="$(subst "${PARAM_CHECKLIST_FORMATS-ckl,cklb}")"
ASSET_NAME="$(subst "${PARAM_CHECKLIST_ASSET_NAME:-}")"
GUARD="$(subst "${PARAM_CHECKLIST_GUARD:-false}")"
STIG_XCCDF_PATH="$(subst "${PARAM_STIG_XCCDF_PATH:-}")"
# Included CircleCI commands can run from stdin, without BASH_SOURCE.
# Packaged commands use staged payloads; sibling scripts are a local fallback.
BUNDLE_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ]; then
    BUNDLE_DIR="$(dirname "${BASH_SOURCE[0]}")/stig-data"
fi
ROOTFS_PATH="$(subst "${PARAM_ROOTFS_PATH:-}")"
args=("--results=${OUTPUT_DIR}/results.xml" "--out-dir=${OUTPUT_DIR}")
if [ "${GUARD}" = "true" ]; then
    args=(--guard "${args[@]}" "--rootfs-path=${ROOTFS_PATH}")
else
    args+=("--plan=${OUTPUT_DIR}/scan-plan.env" "--mode=${CHECKLIST}"
           "--host-name=${ASSET_NAME}" "--formats=${FORMATS}" "--stig-xccdf-path=${STIG_XCCDF_PATH}" "--bundle-dir=${BUNDLE_DIR}")
fi
# Conversion errors are recorded in meta; do not suppress summarize.
if python3 - "${args[@]}" <<'PY_CHECKLIST'
import argparse
import base64
import lzma
import collections
import datetime as dt
import hashlib
import io
import html
import json
import os
import re
import signal
import sys
import uuid
import zipfile
import xml.etree.ElementTree as ET

X12 = "{http://checklists.nist.gov/xccdf/1.2}"
HREF_RULE = "https://www.cyber.mil/stigs/srg-stig-tools/"
HREF_VULN = "https://www.cyber.mil/stigs/srg-stig-tools#vulnerability_id"
# A DISA Rule ID, whole: a prefix match would pair "SV-123garbage" with V-123
# and write it as the row's Rule_ID.
SV_RE = re.compile(r"SV-([0-9]+)r[0-9]+_rule")  # ASCII digits only (\d matches any Unicode digit)
# Bound untrusted XML before parsing: real results.xml is about 15–20 MiB.
GENERATOR_VERSION = "1.2.0"
MAX_RESULTS_BYTES = 128 << 20
MAX_DISA_BYTES = 16 << 20
X11 = "{http://checklists.nist.gov/xccdf/1.1}"
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def open_fresh(path):
    """Open path for writing as a new file: drop whatever is there first (a
    stale or planted symlink only loses the link) and create it exclusively,
    never following a link, so a leftover in a reused output_dir can't
    redirect the write elsewhere."""
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    return os.fdopen(fd, "w", encoding="utf-8")


def read_capped(path, cap, what):
    """Read at most cap bytes; a bigger file is refused, never parsed."""
    with open(path, "rb") as f:
        data = f.read(cap + 1)
    if len(data) > cap:
        raise ValueError(f"{what} is larger than {cap >> 20} MiB; refusing to parse it")
    return data


# ---------------------------------------------------------------- results


def text_of(el):
    if el is None:
        return ""
    return re.sub(r"\s+", " ", "".join(el.itertext())).strip()


XCCDF_RESULTS = {
    "pass",
    "fail",
    "error",
    "unknown",
    "notapplicable",
    "notchecked",
    "notselected",
    "informational",
    "fixed",
}


def combine_instances(rs):
    """One result per rule from its rule-results, with the V-ID combining
    rule's precedence: any fail, else any unevaluated, else all N/A, else
    pass. An unrecognized result string was already mapped to unknown, so it
    can never read as a pass."""
    rs = [r for r in rs if r != "notselected"]
    if not rs:
        return "notselected"
    for r in ("fail", "error", "unknown", "notchecked", "informational"):
        if r in rs:
            return r
    if all(r == "notapplicable" for r in rs):
        return "notapplicable"
    return "pass" if "pass" in rs else "fixed"  # what's left is pass/fixed/notapplicable


def parse_results(source, tailoring=None):
    root = ET.parse(source).getroot()
    # One Benchmark (oscap's results.xml is the Benchmark itself): with
    # several, XML order would pair one's mappings and gates with another's
    # verdicts. The single TestResult must sit inside it (checked below).
    benches = list(root.iter(X12 + "Benchmark"))
    if len(benches) != 1:
        raise ValueError(f"results.xml has {len(benches)} Benchmark elements; expected exactly one")
    bench = benches[0]
    parent = {c: p for p in bench.iter() for c in p}

    def chain_platforms(el):
        """Platform idrefs per level: the rule, its ancestor groups, then the
        Benchmark. Every level must hold: OpenSCAP checks an item's platforms
        only once its parent is applicable, up to the Benchmark
        (xccdf_policy_model_item_is_applicable), and XCCDF's processing model
        stops at a non-applicable Group, so a rule's own platforms never
        override an ancestor's."""
        levels = []
        while el is not None:
            ps = [p.get("idref") for p in el.findall(X12 + "platform")]
            if ps:
                levels.append(ps)
            if el is bench:
                break
            el = parent.get(el)
        return levels

    def check_key(check):
        # TestResult normally records the executed check's system/content
        # references, without the source selector or check-export elements.
        refs = tuple(sorted((e.get("href", ""), e.get("name", ""))
                            for e in check.findall(X12 + "check-content-ref")))
        inline = tuple("".join(e.itertext()) for e in check.findall(X12 + "check-content"))
        return (check.get("system"), refs, inline) if refs or inline else None

    check_exports = {}
    rules = {}
    # XCCDF ids are unique; a repeated Rule id would let the last copy decide
    # the mapping, text and gates silently.
    dup_ids = sorted(i for i, c in collections.Counter(r.get("id") for r in bench.iter(X12 + "Rule")).items() if c > 1)
    if dup_ids:
        raise ValueError(
            f"results.xml defines {len(dup_ids)} Rule id(s) more than once (e.g. {', '.join(dup_ids[:5])})"
        )
    for r in bench.iter(X12 + "Rule"):
        if not r.get("id"):
            raise ValueError("results.xml defines a Rule without an id")
        refs = [(x.get("href") or "", (x.text or "").strip()) for x in r.findall(X12 + "reference")]
        ref = lambda pred: next((v for h, v in refs if pred(h, v)), None)
        sv_refs = sorted({v for h, v in refs if h == HREF_RULE})
        svs = collections.defaultdict(list)
        for v in sv_refs:
            if SV_RE.fullmatch(v):
                svs[SV_RE.fullmatch(v).group(1)].append(v)
        check_exports[r.get("id")] = [
            (check_key(check), {e.get("value-id") for e in check.findall(X12 + "check-export") if e.get("value-id")})
            for check in r.iter(X12 + "check")
        ]
        rules[r.get("id")] = {
            "id": r.get("id"),
            "title": text_of(r.find(X12 + "title")),
            "severity": r.get("severity") or "unknown",
            "description": text_of(r.find(X12 + "description")),
            "rationale": text_of(r.find(X12 + "rationale")),
            # Many-to-many: one SSG rule can cite several DISA rules, and
            # several SSG rules can cite one. Pair SV-n…_rule with V-n by n.
            # n -> every SV-n…_rule revision the rule cites (normally one;
            # never let XML order pick one of several).
            "svs": dict(svs),
            "bad_svs": [v for v in sv_refs if not SV_RE.fullmatch(v)],
            # Unique, in order: a repeated reference must not count the rule
            # twice toward its row.
            "vids": list(dict.fromkeys(v for h, v in refs if h == HREF_VULN)),
            "stig_ids": [v for h, v in refs if "unix-linux" in h],
            "srg": ref(lambda h, v: v.startswith("SRG-")),
            "cce": next((text_of(i) for i in r.findall(X12 + "ident") if "cce" in (i.get("system") or "")), None),
            "platform_levels": chain_platforms(r),
            "value_ids": sorted({e.get("value-id") for e in r.iter(X12 + "check-export") if e.get("value-id")}),
        }

    # oscap writes exactly one TestResult; with several, XML order would
    # pick which evaluation the checklist reports.
    trs = list(root.iter(X12 + "TestResult"))
    if len(trs) != 1:
        raise ValueError(f"results.xml has {len(trs)} TestResult elements; expected exactly one")
    tr = trs[0]
    if not any(t is tr for t in bench.iter(X12 + "TestResult")):
        raise ValueError("results.xml's TestResult is outside its Benchmark")
    true_platforms = {p.get("idref") for p in tr.findall(X12 + "platform")}
    # XCCDF allows several rule-results per rule (multi-check, multiple
    # instances): keep them all and combine, never let the last one win.
    instances = collections.defaultdict(list)
    executed_values = collections.defaultdict(set)
    checks_complete = {}
    for rr in tr.findall(X12 + "rule-result"):
        # Exactly one result per rule-result: with <result>pass</result>
        # <result>fail</result>, findtext would read only the pass.
        res_els = rr.findall(X12 + "result")
        if len(res_els) != 1:
            raise ValueError(f"rule-result {rr.get('idref')} has {len(res_els)} result elements; expected exactly one")
        r = (res_els[0].text or "").strip()
        rid = rr.get("idref")
        instances[rid].append(r if r in XCCDF_RESULTS else "unknown")
        recorded = list(rr.iter(X12 + "check"))
        checks_complete[rid] = checks_complete.get(rid, True) and bool(recorded)
        for check in recorded:
            key = check_key(check)
            candidates = [exports for candidate, exports in check_exports.get(rid, []) if key and candidate == key]
            if not candidates or any(exports != candidates[0] for exports in candidates):
                checks_complete[rid] = False
            else:
                executed_values[rid].update(candidates[0])
    for rid, rule in rules.items():
        rule["executed_value_ids"] = sorted(executed_values[rid])
        rule["check_exports_complete"] = checks_complete.get(rid, False)
    results = {rid: combine_instances(rs) for rid, rs in instances.items()}
    profiles = tr.findall(X12 + "profile")
    if len(profiles) != 1 or not profiles[0].get("idref"):
        raise ValueError(f"results.xml's TestResult names {len(profiles)} evaluated profiles; expected exactly one")
    profile_id = profiles[0].get("idref")
    matching = [p for p in bench.iter(X12 + "Profile") if p.get("id") == profile_id]
    if tailoring and profile_id != tailoring["profile_id"]:
        raise ValueError("results.xml does not name the validated tailoring profile")
    if len(matching) != 1 and not (tailoring and not matching):
        raise ValueError(f"evaluated profile {profile_id} has {len(matching)} definitions; expected exactly one")
    profile = matching[0] if matching else None
    set_values = {}
    for el in tr:
        if el.tag not in (X12 + "set-value", X12 + "set-complex-value"):
            continue
        if not el.get("idref") or el.get("idref") in set_values:
            raise ValueError("results.xml has a missing or repeated set-value idref")
        set_values[el.get("idref")] = (
            ["".join(v.itertext()) for v in el.findall(X12 + "item")]
            if el.tag == X12 + "set-complex-value" else "".join(el.itertext())
        )
    return {
        "benchmark_id": bench.get("id"),
        "benchmark_version": bench.findtext(X12 + "version"),
        "profile_id": profile_id,
        "profile_title": text_of(profile.find(X12 + "title")) if profile is not None else tailoring["profile_title"],
        "set_values": set_values,
        "tailoring": tailoring,
        "bench_platforms": [p.get("idref") for p in bench.findall(X12 + "platform")],
        "true_platforms": true_platforms,
        "rules": rules,
        "results": results,
        "instances": {rid: rs for rid, rs in instances.items() if len(rs) > 1},
        "start": tr.get("start-time"),
        "end": tr.get("end-time"),
        "test_system": tr.get("test-system"),
    }


# ------------------------------------------------- N/A classification


def unmet_gates(rule, true_platforms):
    """Platforms at the outermost level where none evaluated true.

    XCCDF: an item is applicable if any of its platforms match, and only if
    every ancestor group (and the Benchmark) is applicable too. OpenSCAP
    evaluates top-down and lists in TestResult only the platforms it
    evaluated true, so a gate below a failed outer gate was never evaluated:
    walk Benchmark -> outermost group -> rule.
    """
    for level in reversed(rule["platform_levels"]):
        if not any(p in true_platforms for p in level):
            return level
    return []


# Gate names are SSG CPE platform ids; compound ones join terms with "_and_"
# (e.g. "package_pam_and_system_with_kernel"). Classify on the terms.
# not_bootc / not_osbuild are deliberately absent: being a bootc (image-mode)
# system or an osbuild build is not "receives this from its host", and the
# plan treats a kernel-bearing bootc image as a host.
HOST_TERMS = re.compile(r"^(system_with_kernel|machine|not_container|grub2|uefi|.*kernel.*)$")
GUI_PACKAGES = {"gdm", "gnome-shell", "dconf", "xorg-x11-server-common", "xwayland"}


def gate_terms(gates):
    terms = []
    for g in gates:
        g = g.lstrip("#")
        terms += g.split("_and_")
    return terms


def classify_na(gates):
    """Category for gate terms known to be false (a single-term gate, or the
    known-false terms of a compound). Host wins: a rule that *requires* a
    package (audit, aide, openssh-server) is kernel-gated in SSG, so it never
    lands in "package absent"."""
    terms = gate_terms(gates)
    if not terms:
        return "check"
    # An "_or_" inside a compound id hides its logical structure (results.xml
    # carries no CPE platform-specification), so don't claim a category.
    if any("_or_" in g for g in gates):
        return "platform"
    # Package terms never count as host terms, even when the package name
    # contains "kernel" (e.g. package_kernel-tools): a rule N/A because such
    # a package is absent is a "package not installed" row.
    if any(HOST_TERMS.match(t) for t in terms if not t.startswith("package_")):
        return "host"
    pk = [t[len("package_") :] for t in terms if t.startswith("package_")]
    if pk and len(pk) == len(terms):
        # "gui" only when every package is a GUI component: a mixed compound
        # (package_gdm_and_package_pam) must not call PAM a graphical component.
        return ("gui:" if set(pk) <= GUI_PACKAGES else "package:") + ",".join(pk)
    if all(t.endswith("_arch") for t in terms):
        return "arch"
    return "platform"


JUSTIFICATION = {
    "host": (
        "Not Applicable to the container image. This requirement configures the host "
        "operating system (kernel, boot loader, audit subsystem, partitions or system "
        "services), which a container receives from its host and cannot implement itself. "
        "OpenSCAP determined this automatically: platform check {gates} was false for the "
        "scanned image. Assess it on the container host's / platform's STIG checklist. "
        "Ref: DISA Container Hardening Process Guide V1R2, Appendix B."
    ),
    # Component-specific on purpose: package_gdm being false proves only that
    # gdm is absent, not that the image has no graphical interface at all.
    "gui": (
        "Not Applicable. This requirement configures a graphical-interface component ({pkgs}) "
        "that is not installed in this image (OpenSCAP platform check {gates} was false). That "
        "establishes only that {pkgs} is absent; if the image provides a different graphical "
        "interface, assess this requirement manually."
    ),
    "package": (
        "Not Applicable. The {pkgs} package is not installed in this image, so the "
        "configuration this requirement checks does not exist (OpenSCAP platform check {gates} "
        "was false). If {pkgs} is added, this requirement applies and must be re-evaluated."
    ),
    "arch": "Not Applicable. This requirement applies only to another CPU architecture (OpenSCAP platform check {gates} was false).",
    "platform": "Not Applicable. OpenSCAP platform check {gates} was false for the scanned image.",
    # Recomputed for the target: OpenSCAP evaluated the gate on the scanning
    # host, where it held, so don't say OpenSCAP found it false.
    "arch@target": (
        "Not Applicable. This requirement applies only to another CPU architecture: platform check {gates} "
        "is false for this image's architecture. (It held on the scanning host, where OpenSCAP evaluated it.)"
    ),
    "platform@target": (
        "Not Applicable. No alternative of platform check {gates} holds for this image. (One held only on "
        "the scanning host, through an architecture term, where OpenSCAP evaluated it.)"
    ),
    "check": "Not Applicable per OpenSCAP: the automated check itself returned notapplicable for this image.",
}


def justification(cat, gates, rootfs=False):
    kind, _, arg = cat.partition(":")
    if arg == "target":
        kind += "@target"
    gate_text = ", ".join(g.lstrip("#") for g in gates) or "n/a"
    if rootfs and kind == "host":
        return (
            f"Not Applicable per OpenSCAP: platform check {gate_text} was false for the scanned root filesystem. "
            "Assess this host or firmware condition against the intended deployment; "
            "the checklist reflects the offline filesystem evaluation."
        )
    template = JUSTIFICATION[kind]
    if rootfs:
        template = template.replace("image", "root filesystem")
    return template.format(gates=gate_text, pkgs=arg.replace(",", " / "))


# ------------------------------------------------------ aggregation


def aggregate(rule_results):
    """rule_results: [(ssg_rule_id, xccdf_result)] for one DISA Vuln."""
    rs = [r for _, r in rule_results if r != "notselected"]
    if not rs:
        return "Not_Reviewed"
    if "fail" in rs:
        return "Open"
    if any(r in ("error", "unknown", "notchecked", "informational") for r in rs):
        return "Not_Reviewed"
    if all(r == "notapplicable" for r in rs):
        return "Not_Applicable"
    return "NotAFinding"  # pass/fixed, possibly mixed with notapplicable


SSG_STIG_IDS = {  # SSG benchmark -> DISA benchmark id / title (SSG-only mode)
    "RHEL-9": ("RHEL_9_STIG", "Red Hat Enterprise Linux 9 Security Technical Implementation Guide"),
    "RHEL-8": ("RHEL_8_STIG", "Red Hat Enterprise Linux 8 Security Technical Implementation Guide"),
    "RHEL-10": ("RHEL_10_STIG", "Red Hat Enterprise Linux 10 Security Technical Implementation Guide"),
    "UBUNTU_22-04": ("CAN_Ubuntu_22-04_LTS_STIG", "Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide"),
}


# Known DISA releases: (benchmark id, version, release) -> (row count, sha256
# of the sorted "V-ID Rule-ID" pairs, the release's canonical release info).
# Identifiers only. Pairs, not just V-IDs:
# several releases share a V-ID set (Ubuntu V2R7-V2R9, RHEL 10 V1R1-V1R2) and
# differ only in Rule ID revisions, which consumers match exactly.
STIG_INVENTORY = {
    ("CAN_Ubuntu_22-04_LTS_STIG", "2", "7"): (
        188,
        "12de845e06062acb595732396579707e79d18217e8f3b430ef19733bf90cbb7f",
        "Release: 7 Benchmark Date: 05 Jan 2026",
    ),
    ("CAN_Ubuntu_22-04_LTS_STIG", "2", "8"): (
        188,
        "f0c0a27b9381f0e6fc35556b3ae5fc90c2238f91f7057e0c9b793e37ba0a3ddd",
        "Release: 8 Benchmark Date: 01 Apr 2026",
    ),
    ("CAN_Ubuntu_22-04_LTS_STIG", "2", "9"): (
        188,
        "19f8465e1cc1c16910e152252023ca1050a8fdc1143931a200f6e3a2c900427c",
        "Release: 9 Benchmark Date: 01 Jul 2026",
    ),
    ("CAN_Ubuntu_22-04_LTS_STIG", "2", "10"): (
        191,
        "7851e77f61f7fc4597369ee394cd13da0041612e7fea6fe34951fddf7659ae60",
        "Release: 10 Benchmark Date: 30 Sep 2026",
    ),
    ("RHEL_8_STIG", "2", "7"): (
        366,
        "bc381b88e0f69335edcf6eb86a17695df981162e5d0ab9ee58c7efb3f771a2d7",
        "Release: 7 Benchmark Date: 01 Apr 2026",
    ),
    ("RHEL_8_STIG", "2", "8"): (
        369,
        "edb2cb7a36599a78a6b3d0c8223d7d13faa9753a81a9e9515c9be9fd554ce922",
        "Release: 8 Benchmark Date: 01 Jul 2026",
    ),
    ("RHEL_8_STIG", "2", "9"): (
        371,
        "1984e68e60f9772174c278f062f5b949e089dfb0d250ce8898a4a118c874aafc",
        "Release: 9 Benchmark Date: 30 Sep 2026",
    ),
    ("RHEL_9_STIG", "2", "9"): (
        445,
        "d1290dec54ac0c7bac3a0ea0e3f76175e382245725409fc80f1c0a4d6f4baa89",
        "Release: 9 Benchmark Date: 01 Jul 2026",
    ),
    ("RHEL_9_STIG", "2", "10"): (
        445,
        "71c7dd9d19b48e606700d0f3a4d39530eb7666272271fb68db045eefa26595dc",
        "Release: 10 Benchmark Date: 30 Sep 2026",
    ),
    ("RHEL_10_STIG", "1", "1"): (
        434,
        "04685a247e535e1a2e770d8097e417c11fe5c55daecb5fa03fa624a39c2e33e5",
        "Release: 1 Benchmark Date: 26 Feb 2026",
    ),
    ("RHEL_10_STIG", "1", "2"): (
        434,
        "ef19aa40608019b68764c2628f35faf9117b9c721c9d42a2ede0366c425f4ed6",
        "Release: 2 Benchmark Date: 01 Jul 2026",
    ),
    ("RHEL_10_STIG", "1", "3"): (
        435,
        "65bcc7e6af3a182ff9b738448f0432ae81f680e0da715fc9ff1974c85e3e41e8",
        "Release: 3 Benchmark Date: 30 Sep 2026",
    ),
}


TARGET_STIG = {
    "rhel8": "RHEL_8_STIG",
    "rhel9": "RHEL_9_STIG",
    "rhel10": "RHEL_10_STIG",
    "ubuntu2204": "CAN_Ubuntu_22-04_LTS_STIG",
}

# D4 release table: the sha256 of the datastream the scan evaluated
# (scan-plan.env datastream_sha256) -> its benchmark id and version, accepted
# STIG profiles and DISA release (version, the release file's canonical
# release info), as fingerprint.py verified it. The profile label is never used: it says V2R7 for the pinned
# Ubuntu content, whose Rule IDs are V2R8's. Each profile records OpenSCAP's
# selection for it with every Rule's DISA references (selection_fingerprint(),
# as fingerprint.py prints it): it depends only on the datastream and
# profile, so a results.xml with anything else is incomplete or edited, and
# the verified release wouldn't hold for it.
_P = "xccdf_org.ssgproject.content_profile_"
RELEASE_TABLE = {
    "27fc84bb2ea29619a944d5a75b361961e1ac7a8dadd48f4165f00d106b0ef944": (
        "xccdf_org.ssgproject.content_benchmark_RHEL-9",
        "0.1.82",
        {
            _P + "stig": (477, "ab340c9d784fcd1cf70833256729658e2dbb63bc0b43bf3900788527e3bd0476"),
            _P + "stig_gui": (473, "fa7d1f76d13a890b70d56bf7ad087dfc8f42ecb77e0e4f95e20def174a2be001"),
        },
        ("2", "Release: 9 Benchmark Date: 01 Jul 2026"),
        {
            "filename": "ssg-rhel9-ds.xml",
            "profiles": {
                "stig": {"vids": 436, "unmapped": ["enable_authselect"]},
                "stig_gui": {"vids": 432, "unmapped": ["enable_authselect"]},
            },
        },
    ),
    "b0c25f6ef5cdbb5cf72d88c8e17a300aa24e4536ca5d1037c92f67474435217a": (
        "xccdf_org.ssgproject.content_benchmark_RHEL-8",
        "0.1.82",
        {
            _P + "stig": (393, "f0d35edf3a0e08a2fe6d597a1210c187f852da8bf8d65fe4f90f9f10a9dc4015"),
            _P + "stig_gui": (389, "4d91163c3a88ab70e05ccf928ad67972cf79b4301eea4f9a03de60f9fc742b4d"),
        },
        ("2", "Release: 8 Benchmark Date: 01 Jul 2026"),
        {
            "filename": "ssg-rhel8-ds.xml",
            "profiles": {
                "stig": {"vids": 362, "unmapped": ["enable_authselect"]},
                "stig_gui": {"vids": 359, "unmapped": ["enable_authselect"]},
            },
        },
    ),
    "58b6e4cb1032a29b21aede508817dc83335e1a3e34304f3093538e8b64c3988d": (
        "xccdf_org.ssgproject.content_benchmark_RHEL-10",
        "0.1.82",
        {
            _P + "stig": (473, "27d0e02530f6b2b6f9891edda642582c3e1905215dad2cb9b507b1fe41b96979"),
            _P + "stig_gui": (470, "2ccaf4a401b15a07d1c7e8427d1ac4864160d462649f2f23e52df4d5932ead2e"),
        },
        ("1", "Release: 2 Benchmark Date: 01 Jul 2026"),
        {
            "filename": "ssg-rhel10-ds.xml",
            "profiles": {"stig": {"vids": 434, "unmapped": []}, "stig_gui": {"vids": 431, "unmapped": []}},
        },
    ),
    "5ee6c1d4dcf8ca1245e1f532771e9c56a615a415ac076092229209d680f90989": (
        "xccdf_org.ssgproject.content_benchmark_UBUNTU_22-04",
        "0.1.82",
        {_P + "stig": (230, "0056fded4ac8ca00f90907285150142852c3bed8676036a4d21589286914fdfb")},
        ("2", "Release: 8 Benchmark Date: 01 Apr 2026"),
        {"filename": "ssg-ubuntu2204-ds.xml", "profiles": {"stig": {"vids": 188, "unmapped": []}}},
    ),
}


# BEGIN GENERATED BUNDLE_TABLE (tools/refresh-stig-data.py)
BUNDLE_TABLE = {
    "27fc84bb2ea29619a944d5a75b361961e1ac7a8dadd48f4165f00d106b0ef944": {
        "alias": "rhel9",
        "json_sha256": "7252ba062da96c688911f862ceade4ab57232bc3a075227f1fe251d1d8113cd5",
        "source_sha256": "1875de2543d01695c5a346c51888cc336113e9199bfe6726d74a08de286ca1ae",
        "xccdf_sha256": "c912407aa6a2f151979db8bf6d901a06116f1624bf60b19b3737febf73bba539"
    },
    "58b6e4cb1032a29b21aede508817dc83335e1a3e34304f3093538e8b64c3988d": {
        "alias": "rhel10",
        "json_sha256": "211a79b40c9b99b1828ba7d2a0e1af71c2a65ba6f457129686fbd17342a3a834",
        "source_sha256": "d050b93c00d3c2cf8b0adec4a852f27bd827720cc4510ce32f3368006ad63ac3",
        "xccdf_sha256": "91327cd50ab0b4041463a9a1bdaf9b7c365576d67b6ed9864ab99b002bb33ae1"
    },
    "5ee6c1d4dcf8ca1245e1f532771e9c56a615a415ac076092229209d680f90989": {
        "alias": "ubuntu2204",
        "json_sha256": "b870ffe3d51e26ff94cb131d0da25a302d3bed5fd8fd4a921324195c33ba68c3",
        "source_sha256": "649bb9efb5bbcb69b07ee49732783d8b44b424f228792ec58c687d20c827f3b5",
        "xccdf_sha256": "73c26b6592dfc02f7f0eb456e0f89143ea1e2d8af7ebc61bd8bfae01f5a4c9d8"
    },
    "b0c25f6ef5cdbb5cf72d88c8e17a300aa24e4536ca5d1037c92f67474435217a": {
        "alias": "rhel8",
        "json_sha256": "2a3eacf704657158b1d852c092cbc5e8dcbf67f3e72f07843ab516aa7072f465",
        "source_sha256": "5180ff6be545c306950f2041330e0cba835b148529e3c51c55c386f95c363a8c",
        "xccdf_sha256": "4dcfbe0aa0d9745e2c37ec1d63bc2922d67bb86dc8e2bda10c851a461318a3ff"
    }
}
# END GENERATED BUNDLE_TABLE


ARCH_ALIASES = {"x86_64": "amd64", "aarch64": "arm64"}
ARCH_TERM = re.compile(r"^(not_)?(x86_64|aarch64|ppc64le|s390x)_arch$")
SSG_CPU = {"x86_64": "amd64", "aarch64": "arm64", "ppc64le": "ppc64le", "s390x": "s390x"}


# "<cpu>_arch" terms inside an opaque id (e.g. "aarch64_arch_or_x86_64_arch"),
# unrecognized CPUs included, so they can never be trusted by accident.
ARCH_IN_ID = re.compile(r"(?:^|_and_|_or_)((?:not_)?(?:x86_64|[a-z0-9]+)_arch)(?=_and_|_or_|$)")


def arch_terms(p):
    """Architecture terms of a platform id: the "_and_" terms ending in _arch,
    or, for an opaque "_or_" id, every arch term found inside it."""
    p = p.lstrip("#")
    if "_or_" in p:
        return ARCH_IN_ID.findall(p)
    return [t for t in gate_terms([p]) if t.endswith("_arch")]


def norm_arch(a):
    return ARCH_ALIASES.get(a, a) if a else None


def arch_term_value(term, arch):
    """Truth of an SSG architecture term (e.g. not_s390x_arch) on a CPU, or
    None when the term or the CPU is unknown."""
    m = ARCH_TERM.match(term)
    if not m or not arch:
        return None
    hit = SSG_CPU[m.group(2)] == arch
    return not hit if m.group(1) else hit


def selection_fingerprint(res):
    """(selected count, sha256) over every Rule's selection and DISA
    references: one line per Rule, "rule<TAB>S|N<TAB>SV refs<TAB>V-ID refs",
    sorted. Rows and Rule IDs come from the selected rules' references, and
    the "deselected" wording from the notselected ones', so the release the
    table verified holds only for this exact mapping. fingerprint.py
    computes the same from the XML."""
    lines, selected = [], 0
    for rid in sorted(res["rules"]):
        r = res["rules"][rid]
        sel = res["results"].get(rid, "notselected") != "notselected"
        selected += sel
        svs = sorted({v for revs in r["svs"].values() for v in revs} | set(r["bad_svs"]))
        lines.append(f"{rid}\t{'S' if sel else 'N'}\t{' '.join(svs)}\t{' '.join(sorted(set(r['vids'])))}")
    return selected, hashlib.sha256("\n".join(lines).encode()).hexdigest()


def read_tailoring(plan, plan_path):
    """Only the scan's hash-bound, derived manifest is needed for conversion.
    Never reopen the caller's original file, which may have changed or gone."""
    keys = ("tailoring_file", "tailoring_sha256", "tailoring_profile", "tailoring_meta_sha256", "tailoring_evaluated_sha256")
    if not any(plan.get(k) for k in keys):
        return None
    if not all(plan.get(k) for k in keys):
        raise ValueError("the scan plan has incomplete tailoring provenance")
    for key in ("tailoring_sha256", "tailoring_meta_sha256", "tailoring_evaluated_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", plan[key]):
            raise ValueError("invalid tailoring hash in the scan plan")
    raw = read_capped(os.path.join(os.path.dirname(plan_path), "tailoring-meta.json"), 16 << 20, "tailoring metadata")
    if hashlib.sha256(raw).hexdigest() != plan["tailoring_meta_sha256"]:
        raise ValueError("tailoring metadata hash differs from the scan plan")
    def unique(pairs):
        result = {}
        for key, val in pairs:
            if key in result:
                raise ValueError("tailoring metadata repeats " + key)
            result[key] = val
        return result
    meta = json.loads(raw, object_pairs_hook=unique)
    if (meta.get("schema") != "stig-scanner-orb/tailoring/v1"
            or meta.get("sha256") != plan["tailoring_sha256"]
            or meta.get("datastream_sha256") != plan.get("datastream_sha256")
            or meta.get("evaluated_sha256") != plan["tailoring_evaluated_sha256"]
            or meta.get("profile_id") != plan["tailoring_profile"]
            or meta.get("profile_id") != plan.get("profile")):
        raise ValueError("tailoring metadata identity differs from the scan plan")
    if (not isinstance(meta.get("values"), dict) or not isinstance(meta.get("deselected_rules"), list)
            or not isinstance(meta.get("base_profile_ancestry"), list)
            or not meta.get("base_profile_id")
            or not meta["base_profile_ancestry"]
            or meta["base_profile_ancestry"][0] != meta["base_profile_id"]
            or any(not isinstance(p, str) or not p for p in meta["base_profile_ancestry"])
            or not re.fullmatch(r"[0-9a-f]{64}", meta.get("references_sha256", ""))):
        raise ValueError("invalid tailoring metadata inventory")
    return meta


def validate_tailored_results(res, tailoring):
    if (res["benchmark_id"], res["benchmark_version"]) != (
            tailoring["benchmark_id"], tailoring["benchmark_version"]):
        raise ValueError("tailoring metadata and results name different benchmarks")
    lines = []
    for rid, rule in sorted(res["rules"].items()):
        svs = sorted({v for revs in rule["svs"].values() for v in revs} | set(rule["bad_svs"]))
        lines.append(rid + "\t" + " ".join(svs) + "\t" + " ".join(sorted(set(rule["vids"]))))
    if hashlib.sha256("\n".join(lines).encode()).hexdigest() != tailoring["references_sha256"]:
        raise ValueError("tailored results' Rule/DISA reference inventory differs from the source datastream")
    if set(tailoring["deselected_rules"]) - set(res["rules"]):
        raise ValueError("tailoring metadata names undefined deselected rules")
    unapplied = sorted(rid for rid in tailoring["deselected_rules"] if res["results"].get(rid) != "notselected")
    if unapplied:
        raise ValueError("OpenSCAP did not apply requested tailoring deselections: " + ", ".join(unapplied[:5]))
    def valid_value(value):
        return value is None or isinstance(value, str) or (
            isinstance(value, list) and all(isinstance(v, str) for v in value)
        )

    for rid, value in tailoring["values"].items():
        if (not isinstance(value, dict) or not valid_value(value.get("value"))
                or not isinstance(value.get("directives"), list)):
            raise ValueError("invalid tailoring value metadata")
        # TestResult is authoritative for resolved values: a set-value and a
        # refine-value can coexist, and inherited selectors/operators need not
        # resolve like the source Value's default. Retain all requested
        # directives alongside the actual value instead of reimplementing
        # OpenSCAP's resolution semantics here.


def target_ref(plan):
    """Digest-bound target identity: registry digest, else the local image id
    that ran (with the tag for readability), else the rootfs path."""
    if plan.get("image_repo_digests"):
        return plan["image_repo_digests"]
    if plan.get("image_id"):
        return " ".join(filter(None, (plan.get("image"), f"(image id {plan['image_id']})")))
    return plan.get("image") or plan.get("rootfs_path") or ""


def parse_disa(source):
    root = ET.parse(source).getroot()
    if root.tag not in (X11 + "Benchmark", X12 + "Benchmark"):
        raise ValueError("the DISA file must be an XCCDF 1.1 or 1.2 Benchmark")
    ns = X11 if root.tag.startswith(X11) else X12
    for el in root.iter():
        for tag in (
            "version",
            "title",
            "description",
            "check",
            "check-content",
            "check-content-ref",
            "fixtext",
        ):
            if len(el.findall(ns + tag)) > 1:
                raise ValueError(f"the DISA file repeats {tag} in {el.get('id') or el.tag}")
    releases = [p for p in root.findall(ns + "plain-text") if p.get("id") == "release-info"]
    if len(releases) != 1:
        raise ValueError("the DISA file must have exactly one release-info")
    groups = root.findall(ns + "Group")
    if len(groups) != len(list(root.iter(ns + "Group"))) or len(list(root.iter(ns + "Rule"))) != sum(
        len(g.findall(ns + "Rule")) for g in groups
    ):
        raise ValueError("the DISA file has nested Groups or Rules outside its Groups")
    info = {
        # DISA's manual XCCDFs carry profiles (9 on every file seen) that each
        # select exactly the file's groups: an inventory inside the file.
        "profiles": [
            {s.get("idref") for s in p.findall(ns + "select") if s.get("selected") == "true"}
            for p in root.findall(ns + "Profile")
        ],
        "benchmark_id": root.get("id"),
        "title": text_of(root.find(ns + "title")),
        "description": text_of(root.find(ns + "description")),
        "version": (root.findtext(ns + "version") or "").strip(),
        "releaseinfo": next(
            (text_of(p) for p in root.findall(ns + "plain-text") if p.get("id") == "release-info"), ""
        ),
        "groups": [],
    }
    for g in groups:
        # One Rule per Group in every DISA file: an extra Rule would be
        # dropped silently while the group/profile inventory still matched.
        rs = g.findall(ns + "Rule")
        if len(rs) != 1:
            raise ValueError(f"DISA group {g.get('id')} has {len(rs)} Rule elements, expected exactly one")
        r = rs[0]
        desc_raw = r.findtext(ns + "description") or ""
        tags = dict(re.findall(r"<(\w+)>(.*?)</\1>", html.unescape(desc_raw), re.S))
        chk = r.find(ns + "check")
        info["groups"].append(
            {
                "vid": g.get("id"),
                "group_title": text_of(g.find(ns + "title")),
                "rule_id": r.get("id"),
                "severity": r.get("severity"),
                "weight": r.get("weight") or "10.0",
                "rule_ver": r.findtext(ns + "version") or "",
                "rule_title": text_of(r.find(ns + "title")),
                "discussion": tags.get("VulnDiscussion", "").strip(),
                "false_positives": tags.get("FalsePositives", ""),
                "false_negatives": tags.get("FalseNegatives", ""),
                "documentable": tags.get("Documentable", "false"),
                "mitigations": tags.get("Mitigations", ""),
                "potential_impacts": tags.get("PotentialImpacts", ""),
                "third_party": tags.get("ThirdPartyTools", ""),
                "mitigation_control": tags.get("MitigationControl", ""),
                "responsibility": tags.get("Responsibility", ""),
                "sec_override": tags.get("SeverityOverrideGuidance", ""),
                "check_content": (
                    "".join(chk.find(ns + "check-content").itertext()).strip()
                    if chk is not None and chk.find(ns + "check-content") is not None
                    else ""
                ),
                "check_ref": (
                    (chk.find(ns + "check-content-ref").get("name") or "M")
                    if chk is not None and chk.find(ns + "check-content-ref") is not None
                    else "M"
                ),
                "fix_text": (r.findtext(ns + "fixtext") or "").strip(),
                "ccis": [
                    (i.text or "").strip()
                    for i in r.findall(ns + "ident")
                    if "cci" in (i.get("system") or "").lower()
                ],
                "legacy": [
                    (i.text or "").strip()
                    for i in r.findall(ns + "ident")
                    if "legacy" in (i.get("system") or "").lower()
                ],
            }
        )
    if not info["groups"] or not info["title"]:
        raise ValueError("the DISA file has no groups or benchmark title")
    for p in root.findall(ns + "Profile"):
        selects = p.findall(ns + "select")
        ids = [x.get("idref") for x in selects]
        if len(set(ids)) != len(ids) or any(x.get("selected") not in ("true", "1") for x in selects):
            raise ValueError("the DISA file has repeated or disabled profile selections")
    info["profiles"] = [
        {x.get("idref") for x in p.findall(ns + "select")} for p in root.findall(ns + "Profile")
    ]
    return info


def read_disa(path, expected):
    """Snapshot once in bounded memory; hash exactly the bytes parsed. ZIP
    members are read in memory, never extracted or resolved as local paths.
    Record both archive and member hashes, since the source may be a ZIP."""
    raw = read_capped(path, MAX_DISA_BYTES, "the DISA file")
    data, member = raw, None
    if zipfile.is_zipfile(io.BytesIO(raw)):
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            members = [
                i for i in z.infolist() if not i.is_dir() and i.filename.lower().endswith("manual-xccdf.xml")
            ]
            if len(members) != 1:
                raise ValueError(
                    f"the DISA ZIP has {len(members)} manual XCCDF members; expected exactly one"
                )
            entry = members[0]
            if entry.file_size > MAX_DISA_BYTES:
                raise ValueError("the DISA ZIP manual XCCDF member is larger than 16 MiB")
            with z.open(entry) as f:
                data = f.read(MAX_DISA_BYTES + 1)
            if len(data) > MAX_DISA_BYTES:
                raise ValueError("the DISA ZIP manual XCCDF member is larger than 16 MiB")
            member = entry.filename
    disa = parse_disa(io.BytesIO(data))
    if not expected:
        raise ValueError("can't tell which DISA STIG this scan implements; the DISA file can't be checked")
    if disa["benchmark_id"] != expected:
        raise ValueError(
            f"the DISA file is {disa['benchmark_id']}, but this scan's content implements {expected}"
        )
    validate_disa(disa)
    disa.update(
        sha256=hashlib.sha256(data).hexdigest(),
        source_sha256=hashlib.sha256(raw).hexdigest(),
        source_path=path,
        member=member,
    )
    return disa


def validate_disa(disa):
    # Consumers key rows on the V-ID and on the full Rule ID: each must
    # be well formed and unique, or two rows could collide.
    for field, label, pat in (("vid", "V-IDs", r"V-[0-9]+"), ("rule_id", "Rule IDs", SV_RE.pattern)):
        ids = [g[field] or "" for g in disa["groups"]]
        bad = sorted({i for i in ids if not re.fullmatch(pat, i)})
        dups = sorted(i for i, c in collections.Counter(ids).items() if c > 1)
        if bad or dups:
            why = [f"malformed {label}: {', '.join(bad[:5])}"] * bool(bad) + [
                f"repeated {label}: {', '.join(dups[:5])}"
            ] * bool(dups)
            raise ValueError(f"the DISA file has {'; '.join(why)}")
    # A DISA severity is the row's CAT level: every DISA Rule has
    # high/medium/low, so a missing or other value is an edited file.
    bad_sev = sorted(
        {
            f"{g['vid']}={g['severity']!r}"
            for g in disa["groups"]
            if g["severity"] not in ("high", "medium", "low")
        }
    )
    if bad_sev:
        raise ValueError(
            f"the DISA file has {len(bad_sev)} Rule(s) without a "
            f"high/medium/low severity, e.g. {', '.join(bad_sev[:5])}"
        )
    # And each Group's Rule must be its own: V-n carries SV-n…_rule
    # (every DISA file), or the row joins one requirement to another's
    # Rule ID.
    # Every DISA Rule has a title, discussion, check procedure and fix
    # text: manual-only rows are reviewed from them (the requirement
    # statement comes only from the skeleton), so a blank one is an
    # edited file.
    blank = sorted(
        g["vid"]
        for g in disa["groups"]
        if not all(g[k].strip() for k in ("rule_title", "discussion", "check_content", "fix_text"))
    )
    if blank:
        raise ValueError(
            f"the DISA file has {len(blank)} Rule(s) without a title, "
            f"discussion, check content or fix text, e.g. {', '.join(blank[:5])}"
        )
    crossed = [
        f"{g['vid']} {g['rule_id']}"
        for g in disa["groups"]
        if SV_RE.fullmatch(g["rule_id"]).group(1) != g["vid"][2:]
    ]
    if crossed:
        raise ValueError(
            f"the DISA file pairs V-IDs with other numbers' Rule IDs: " f"{', '.join(crossed[:5])}"
        )
    # Completeness, independent of what this scan maps: the file's own
    # profiles must each select exactly its groups (deleting groups,
    # mapped or manual-only, breaks that), and a known release must
    # carry exactly its recorded V-ID set.
    vids = {g["vid"] for g in disa["groups"]}
    if not disa["profiles"] or any(sel != vids for sel in disa["profiles"]):
        raise ValueError(
            "the DISA file's profiles don't select exactly its V-IDs: "
            "groups were removed or added (truncated or edited file)"
        )
    # The release info is copied into the checklist as its release
    # identity, so it must have DISA's whole format (every DISA file
    # does), not merely start with "Release: N".
    # Canonical ASCII numbers only: "02" or "Release: 09" (or other
    # Unicode digits) would miss the inventory key and pass a known
    # release off as unknown.
    rel_m = re.fullmatch(
        r"Release: ([1-9][0-9]*) Benchmark Date: ([0-9]{2}) ([A-Z][a-z]{2}) ([0-9]{4})", disa["releaseinfo"]
    )
    if rel_m:
        # A real calendar date (no locale: month names spelled out).
        try:
            dt.date(int(rel_m.group(4)), MONTHS.index(rel_m.group(3)) + 1, int(rel_m.group(2)))
        except ValueError:
            rel_m = None
    if not re.fullmatch(r"[1-9][0-9]*", disa["version"]) or not rel_m:
        # Without both, the checklist can't name its release (CKL
        # version empty, CKLB version null) and no inventory applies.
        raise ValueError(
            f"the DISA file names no release: version "
            f"{disa['version']!r}, release-info {disa['releaseinfo'][:60]!r}"
        )
    inv = STIG_INVENTORY.get((disa["benchmark_id"], disa["version"], rel_m.group(1)))
    pairs = sorted(f"{g['vid']} {g['rule_id']}" for g in disa["groups"])
    if inv and (len(pairs), hashlib.sha256("\n".join(pairs).encode()).hexdigest()) != inv[:2]:
        raise ValueError(
            f"the DISA file claims {disa['benchmark_id']} "
            f"V{disa['version']}R{rel_m.group(1)}, but its {len(pairs)} V-ID/Rule ID pairs don't match "
            f"that release's {inv[0]}"
        )
    if inv and disa["releaseinfo"] != inv[2]:
        # Right pairs, wrong date: the published identity must be the
        # release's own.
        raise ValueError(
            f"the DISA file claims {disa['benchmark_id']} "
            f"V{disa['version']}R{rel_m.group(1)} with release info {disa['releaseinfo']!r}; that "
            f"release's is {inv[2]!r}"
        )
    disa["completeness"] = "inventory" if inv else "internal"


def load_bundle(datastream_sha256, directory):
    """Load only the bundle bound to these exact datastream bytes. Hash the
    compact JSON before trusting it and cap both encoded and expanded bytes.
    CircleCI stages data in a separate included step; local scripts can read
    the same payload directly from their sibling generated shell files."""
    descriptor = BUNDLE_TABLE.get(datastream_sha256)
    if not descriptor:
        # Entries identifying a pinned content file require a bundle. Missing
        # data indicates an incomplete pin bump, never a reason to downgrade.
        ent = RELEASE_TABLE.get(datastream_sha256)
        if ent and len(ent) > 4 and ent[4].get("filename"):
            raise ValueError("the verified datastream has no bundled DISA data; refresh the bundles")
        return None
    alias = descriptor["alias"]
    path = os.environ.get("STIG_DATA_" + alias.upper())
    if path is not None:
        if not path:
            raise ValueError(f"bundled DISA data for {alias} could not be staged")
        encoded = read_capped(path, 2 << 20, "encoded DISA bundle")
    else:
        script = read_capped(os.path.join(directory, alias + ".sh"), 2 << 20, "DISA bundle script")
        markers = script.split(b"\nSTIG_DATA_B64\n")
        prefix, sep, encoded = markers[0].partition(b"<<'STIG_DATA_B64'\n")
        if len(markers) != 2 or not sep:
            raise ValueError(f"bundled DISA data for {alias} has no unique payload")
    compressed = base64.b64decode(b"".join(encoded.split()), validate=True)
    decoder = lzma.LZMADecompressor(memlimit=64 << 20)
    data = decoder.decompress(compressed, max_length=MAX_DISA_BYTES + 1)
    if len(data) > MAX_DISA_BYTES:
        raise ValueError("bundled DISA data exceeds 16 MiB")
    if not decoder.eof or decoder.unused_data:
        raise ValueError("bundled DISA data is truncated or has trailing compressed data")
    if hashlib.sha256(data).hexdigest() != descriptor["json_sha256"]:
        raise ValueError(f"bundled DISA data for {alias} does not match its pinned SHA-256")
    payload = json.loads(data)
    if payload["schema"] != "stig-scanner-orb/stig-data/v1":
        raise ValueError("unsupported DISA bundle schema")
    disa = payload["stig"]
    ent = RELEASE_TABLE.get(datastream_sha256)
    if not ent or payload["datastream_sha256"] != datastream_sha256:
        raise ValueError("DISA bundle does not match the verified datastream")
    expected = SSG_STIG_IDS[ent[0].replace("xccdf_org.ssgproject.content_benchmark_", "")][0]
    if disa["benchmark_id"] != expected or (disa["version"], disa["releaseinfo"]) != ent[3]:
        raise ValueError("DISA bundle does not match the pinned STIG release")
    source = payload["source"]
    if (
        source["sha256"] != descriptor["source_sha256"]
        or source["xccdf_sha256"] != descriptor["xccdf_sha256"]
    ):
        raise ValueError("DISA bundle source hashes do not match their pins")
    disa["profiles"] = [set(p) for p in disa["profiles"]]
    validate_disa(disa)
    if disa["completeness"] != "inventory":
        raise ValueError("bundled DISA release has no verified inventory")
    disa.update(
        sha256=source["xccdf_sha256"],
        source_sha256=source["sha256"],
        source_path=source["url"],
        member=source["member"],
        bundle_sha256=descriptor["json_sha256"],
        credits=source["credits"],
    )
    return disa


def release_label(disa):
    return f"V{disa['version']}R{disa['releaseinfo'].split()[1]}"


def build_model(res, plan, runner_arch=None, release=None, disa=None, baseline=None):
    # OpenSCAP's architecture platforms read the scanning host's /proc, not
    # the target. Image mode records the target platform (os/arch[/variant]);
    # rootfs_path doesn't. Compare architectures only, keep the full platform
    # for provenance.
    target_platform = plan.get("image_platform") or None
    target_arch = (
        norm_arch(target_platform.split("/")[1]) if target_platform and target_platform.count("/") >= 1 else None
    )
    runner_arch = norm_arch(runner_arch)
    true_p = res["true_platforms"]

    # Platforms known to have evaluated *false*: OpenSCAP walks top-down, so
    # the outermost level of a notapplicable rule with no true platform was
    # evaluated, and every platform on it came out false. (An evaluated rule
    # has no such level: everything it passed is in the true set.)
    known_false = set()
    for rid, result in res["results"].items():
        if result == "notapplicable" and rid in res["rules"]:
            known_false.update(unmet_gates(res["rules"][rid], true_p))

    # A true "_and_" compound proves each of its terms true (e.g. a true
    # not_bootc_and_package_dnf proves not_bootc); a false one says nothing
    # about any single term, and an "_or_" id says nothing either way.
    true_terms = {t for p in true_p if p.startswith("#") and "_or_" not in p for t in gate_terms([p])}

    def term_state(t):
        """True / False / None (unknown) for a non-arch gate term."""
        if "#" + t in true_p or t in true_terms:
            return True
        return False if "#" + t in known_false else None

    def arch_trusted(terms):
        """OpenSCAP's verdict on these arch terms holds for the target only if
        each has the same, known value on the runner and on the target."""
        return all(
            arch_term_value(t, runner_arch) is not None
            and arch_term_value(t, runner_arch) == arch_term_value(t, target_arch)
            for t in terms
        )

    def classify_gate(g):
        """Category for one false platform id at a rule's deciding level."""
        arch_ts = arch_terms(g)
        if "_or_" in g:
            # Opaque: results.xml has no CPE logic, so only the runner's
            # verdict on the whole id exists, and it holds for the target
            # only if no arch term inside can differ between the two.
            return "platform" if arch_trusted(arch_ts) else "arch?"
        terms = gate_terms([g])
        other = [t for t in terms if t not in arch_ts]
        if len(terms) == 1 and not arch_ts:
            return classify_na([g])  # the gate itself is the term: known false
        # A non-arch term known false decides the N/A by itself.
        false_other = [t for t in other if term_state(t) is False]
        if false_other:
            return classify_na(["#" + "_and_".join(false_other)])
        # The compound is false, so if every other term is known true, the
        # one remaining term is the false one.
        unknown = [t for t in other if term_state(t) is None]
        if not arch_ts and len(unknown) == 1:
            return classify_na(["#" + unknown[0]])
        if arch_ts and all(term_state(t) is True for t in other):
            # Only the arch terms can have failed.
            if not arch_trusted(arch_ts):
                return "arch?"
            return "arch" if any(arch_term_value(t, target_arch) is False for t in arch_ts) else "platform"
        if arch_ts and not arch_trusted(arch_ts):
            return "arch?"
        return "platform"  # which term failed is unknown: claim no reason

    def classify_level(gates):
        if not gates:
            return "check"
        cats = {classify_gate(g) for g in gates}
        if "arch?" in cats:
            return "arch?"
        return cats.pop() if len(cats) == 1 else "platform"

    def platform_target_truth(p):
        """True / False / None: does platform p hold for the *target*?"""
        arch_ts = arch_terms(p)
        if "_or_" in p:
            # Opaque: a false arch term inside proves nothing about the id.
            if arch_trusted(arch_ts):
                return True if p in true_p else False if p in known_false else None
            return None
        if any(arch_term_value(t, target_arch) is False for t in arch_ts):
            return False
        if arch_trusted(arch_ts):  # runner verdict carries over (vacuously so without arch terms)
            if p in true_p:
                return True
            if p in known_false:
                return False
        other = [t for t in gate_terms([p]) if t not in arch_ts]
        if any(term_state(t) is False for t in other):
            return False
        if all(arch_term_value(t, target_arch) is True for t in arch_ts) and all(term_state(t) is True for t in other):
            return True
        return None

    def target_verdict(rule):
        """For a rule OpenSCAP evaluated (got past every gate on the runner).
        Platforms on one level are alternatives: the level holds for the
        target if any alternative holds. Returns ('na', level) when every
        alternative on some level is false for the target, ('uncertain',
        None) when some level has no alternative known to hold, else None."""
        uncertain = False
        for level in rule["platform_levels"]:
            truths = [platform_target_truth(p) for p in level]
            if any(t is True for t in truths):
                continue
            if all(t is False for t in truths):
                return "na", level
            uncertain = True
        return ("uncertain", None) if uncertain else (None, None)

    by_vid = collections.defaultdict(list)
    # V-IDs whose scanner checks the profile didn't select (notselected:
    # a profile conflict, a selection default, tailoring). They don't count
    # toward any status. SSG-only output omits their rows.
    deselected = collections.defaultdict(list)
    unpaired = []
    for rid, result in res["results"].items():
        r = res["rules"][rid]
        # Pair every rule's references, deselected ones included (their V-IDs
        # drive the "deselected" wording, so a bad reference is reported too).
        # A reference that isn't a whole SV-<digits>r<digits>_rule names no
        # DISA rule: report it, never write it as a Rule_ID.
        unpaired += [f"{rid}: {sv}" for sv in r["bad_svs"]]
        if r["vids"]:
            # Only a V-n with a matching SV-n is a row (D3); anything else
            # can't name a DISA rule, so report it instead of keying on it.
            # Only a well-formed V-<digits> can pair; "XX123" must not key
            # a row just because its tail matches an SV number.
            vids = [v for v in r["vids"] if re.fullmatch(r"V-[0-9]+", v) and v[2:] in r["svs"]]
            unpaired += [f"{rid}: {v}" for v in r["vids"] if v not in vids]
            unpaired += [f"{rid}: {sv}" for n, revs in r["svs"].items() if f"V-{n}" not in r["vids"] for sv in revs]
        else:
            # SSG < 0.1.82 has no #vulnerability_id references: derive V-n from SV-n.
            vids = [f"V-{n}" for n in r["svs"]]
        for vid in vids:
            (deselected if result == "notselected" else by_vid)[vid].append(rid)

    prov = []
    if plan:
        # Registry digest first; a locally built or loaded image has none, so
        # fall back to the image id that actually ran, never the mutable tag.
        scanner = plan.get("scanner_repo_digests") or " ".join(
            filter(
                None, (plan.get("scanner"), plan.get("scanner_image_id") and f"(image id {plan['scanner_image_id']})")
            )
        )
        prov.append(f"Scanner: {scanner}; datastream {plan.get('datastream')} sha256 {plan.get('datastream_sha256')}")
        target = target_ref(plan)
        prov.append(
            f"Target: {target}"
            + (f" [{target_platform}]" if target_platform else "")
            + (f"; scanned on {runner_arch}" if runner_arch else "")
        )
    prov.append(
        f"Content: {res['benchmark_id']} {res['benchmark_version']}, profile {res['profile_id']}; "
        f"scan {res['start']} .. {res['end']} ({res['test_system']})"
    )
    if res.get("tailoring"):
        t = res["tailoring"]
        prov.append(f"Tailoring: {plan.get('tailoring_file')}; original sha256 {t['sha256']}; "
                    f"evaluated sha256 {t['evaluated_sha256']}; "
                    f"profile {t['profile_id']} extends {t['base_profile_id']}")
    if disa:
        prov.append(
            f"DISA STIG file: {disa['benchmark_id']} V{disa['version']} ({disa['releaseinfo']}); "
            f"file {disa['source_path']}; XCCDF sha256 {disa['sha256']}; source sha256 {disa['source_sha256']}"
            + (f"; ZIP member {disa['member']}" if disa["member"] else "")
        )
    if baseline:
        prov.append(f"Reference content credits: {baseline['credits']}; reuse policy https://www.cyber.mil/privacy-security")
        prov.append(f"Content-matched DISA reference: {baseline['benchmark_id']} {release_label(baseline)}; "
                    f"XCCDF sha256 {baseline['sha256']}; source ZIP sha256 {baseline['source_sha256']}; "
                    f"bundle sha256 {baseline['bundle_sha256']}")
    prov_txt = "\n".join(prov)
    arch_note = f"[architecture gate evaluated on the scanning host ({runner_arch}); target architecture {target_arch or 'unknown'}]"

    def tailoring_value_notes(rids):
        notes = []
        if not res.get("tailoring"):
            return notes
        value_ids = sorted({
            value_id for rid in rids
            for value_id in res["rules"][rid]["executed_value_ids" if res["rules"][rid]["check_exports_complete"] else "value_ids"]
        })
        for value_id in value_ids:
            if value_id not in res["tailoring"]["values"]:
                continue
            configured = res["tailoring"]["values"][value_id]
            actual = res["set_values"].get(value_id)
            notes.append(f"Tailored value {value_id}: " +
                         (f"{actual!r} (resolved by OpenSCAP)" if actual is not None else
                          "not recorded in TestResult"))
            linked = sorted(rid for rid in rids if value_id in res["rules"][rid]["executed_value_ids"])
            if linked:
                notes.append("  Export declared by recorded check(s): " + ", ".join(linked) +
                             ". The resolved value above is global TestResult evidence.")
            else:
                notes.append("  Declared by Rule check definitions only; association with an executed check "
                             "is not established. Alternatives may not have run. "
                             "The resolved value above is global TestResult evidence, not proof of use by this Rule.")
            for directive in configured["directives"]:
                notes.append("  Requested " + json.dumps(directive, sort_keys=True, ensure_ascii=False))
        return notes

    def vuln_from_ssg(vid, rids):
        details, comments, ruleids = [], [], set()
        na_cats, effective, uncertain = set(), [], set()
        for rid in sorted(rids):
            r, result = res["rules"][rid], res["results"][rid]
            ruleids.update(r["svs"].get(vid[2:], ()))
            line = f"{rid.replace('xccdf_org.ssgproject.content_rule_', '')}: {result}"
            if rid in res["instances"]:
                tally = collections.Counter(res["instances"][rid])
                line += f" (combined from {sum(tally.values())} results: {', '.join(f'{k} {v}' for k, v in sorted(tally.items()))})"
            eff = result
            if result == "notapplicable":
                gates = unmet_gates(r, true_p)
                cat = classify_level(gates)
                if gates:
                    line += f" (platform not met: {', '.join(g.lstrip('#') for g in gates)})"
                if cat == "arch?":
                    # The N/A may not hold for the target, so the rule counts
                    # as unevaluated *before* aggregation: a passing sibling
                    # rule must not carry the V-ID to NotAFinding.
                    eff = "notchecked"
                    uncertain.add("na")
                    line += " -> not reviewed " + arch_note
                else:
                    na_cats.add((cat, tuple(gates)))
            elif result in ("pass", "fixed", "fail"):
                # Only an evaluated result is recomputed for the target; an
                # error/unknown/notchecked/informational stays unevaluated
                # (Not_Reviewed), never hidden as an N/A row.
                verdict, level = target_verdict(r)
                if verdict == "na":
                    # Every alternative at this level is false for the target.
                    # Say "another CPU architecture" only if each is false
                    # through an arch term; a known-false package (say) beside
                    # it means the requirement could still apply here.
                    eff = "notapplicable"
                    by_arch = all(
                        "_or_" not in p and any(arch_term_value(t, target_arch) is False for t in arch_terms(p))
                        for p in level
                    )
                    na_cats.add(("arch:target" if by_arch else "platform:target", tuple(level)))
                    line += f" -> notapplicable for the target ({target_arch}): " + (
                        "an architecture gate passed on the scanning host " f"({runner_arch}) is false for it"
                        if by_arch
                        else f"no platform alternative at this level holds for it (scanned on {runner_arch})"
                    )
                elif verdict == "uncertain":
                    eff = "notchecked"
                    uncertain.add("eval")
                    line += " -> not reviewed " + arch_note
            effective.append((rid, eff))
            details.append(line)
            details.extend(tailoring_value_notes([rid]))
        status = aggregate(effective)
        if status == "Not_Applicable":
            comments = [justification(c, list(g), rootfs=bool(plan.get("rootfs_path"))) for c, g in sorted(na_cats)]
        elif status == "Not_Reviewed" and uncertain:
            if "na" in uncertain:
                comments.append(
                    f"Not reviewed: OpenSCAP marked a contributing check notapplicable on a CPU-architecture "
                    f"condition it evaluated against the scanning host ({runner_arch}); the target's "
                    f"architecture is {target_arch or 'unknown'}. Verify applicability manually."
                )
            if "eval" in uncertain:
                comments.append(
                    f"Not reviewed: OpenSCAP evaluated a contributing check past a CPU-architecture condition on "
                    f"the scanning host ({runner_arch}), which can't be decided for the target "
                    f"({target_arch or 'architecture unknown'}). The automated result is kept in the finding "
                    f"details; verify manually."
                )
        # The N/A category travels in the model, so reporting never has to
        # parse it back out of the justification prose.
        na_category = (
            "+".join(sorted({c.partition(":")[0] for c, _ in na_cats})) if status == "Not_Applicable" else None
        )
        # Why a row is Not_Reviewed travels the same way, for the meta.
        nr_reason = ("architecture" if uncertain else "unevaluated") if status == "Not_Reviewed" else None
        head = f"Automated result from OpenSCAP ({len(rids)} SSG rule{'s' if len(rids) > 1 else ''}):"
        return (
            status,
            head + "\n" + "\n".join(details) + "\n\n" + prov_txt,
            "\n".join(dict.fromkeys(comments)),
            ruleids,
            na_category,
            nr_reason,
        )

    vulns = []
    if disa:
        stig = {k: disa[k] for k in ("benchmark_id", "title", "description", "version", "releaseinfo")}
        rel = re.search(r"Release: *([0-9]+)", disa["releaseinfo"]).group(1)
        stig["filename"] = f"U_{disa['benchmark_id']}_V{disa['version']}R{rel}_Manual-xccdf.xml"
        seen = set()
        baseline_rows = {g["vid"]: g for g in baseline["groups"]} if baseline else {}
        for g in disa["groups"]:
            rids = by_vid.get(g["vid"], [])
            seen.add(g["vid"])
            na_category, drift = None, None
            if rids:
                status, detail, comment, ssg_rule_ids, na_category, nr_reason = vuln_from_ssg(g["vid"], rids)
                reference = baseline_rows.get(g["vid"])
                # The exact pinned datastream must cite *only* the reference's
                # Rule ID in every contributor before its check text can prove
                # equivalence. A mixed revision set never earns a carry-forward.
                verified_reference = reference and ssg_rule_ids == {reference["rule_id"]}
                revision_changed = ssg_rule_ids != {g["rule_id"]}
                check_changed = verified_reference and reference["check_content"] != g["check_content"]
                if revision_changed or check_changed:
                    detail += (
                        f"\n\nRevision comparison: scanner references {', '.join(sorted(ssg_rule_ids))}; "
                        f"checklist {release_label(disa)} has {g['rule_id']}. Automated result across the content's revisions: {status}."
                    )
                    if verified_reference:
                        detail += (
                            f"\nCheck-content SHA-256: content-matched {hashlib.sha256(reference['check_content'].encode()).hexdigest()}; "
                            f"supplied {hashlib.sha256(g['check_content'].encode()).hexdigest()}."
                        )
                    if verified_reference and not check_changed:
                        drift = "unchanged_check"
                        note = (
                            f"Check content is unchanged between the content-matched {release_label(baseline)} "
                            f"and checklist {release_label(disa)}; automated result retained: {status}."
                        )
                        detail += "\n" + note
                        comment = "\n".join(filter(None, (comment, note)))
                    else:
                        drift = "check_changed" if check_changed else "unverified_revision"
                        reason = (
                            (
                                f"check content in {release_label(disa)} differs from the content-matched "
                                f"{release_label(baseline)}"
                            )
                            if check_changed
                            else "a different revision cannot be verified against content-matched check text"
                        )
                        detail += "\nNot reviewed: " + reason + "."
                        status, na_category = "Not_Reviewed", None
                        nr_reason = "check_changed" if check_changed else "revision_mismatch"
                        comment = "Not reviewed: " + reason + "; re-verify this requirement."
            elif deselected.get(g["vid"]):
                # The content checks it, but the profile didn't select the
                # check: say so, not "no automated check".
                names = ", ".join(
                    sorted(x.replace("xccdf_org.ssgproject.content_rule_", "") for x in deselected[g["vid"]])
                )
                # Same revision rule as evaluated rows: a check citing another
                # Rule ID revision isn't a check of this release's text.
                revs = sorted(
                    {sv for x in deselected[g["vid"]] for sv in res["rules"][x]["svs"].get(g["vid"][2:], ())}
                )
                other = [sv for sv in revs if sv != g["rule_id"]]
                # The reason stays "deselected" (nothing was evaluated, so no
                # verdict is withheld); revision_mismatch counts withheld ones.
                status, nr_reason = "Not_Reviewed", "deselected"
                what = (
                    (
                        f"a different revision of this requirement ({', '.join(revs)}; this checklist's STIG release "
                        f"has {g['rule_id']})"
                    )
                    if other
                    else "this requirement"
                )
                detail = (
                    f"The scanner content checks {what} with {names}, but OpenSCAP did not select it "
                    f"for the evaluated profile (notselected: a profile conflict, a selection default or "
                    f"tailoring), so nothing was evaluated.\n\n" + prov_txt
                )
                comment = (
                    f"Not reviewed: the scanner content has an automated check for {what}, but the "
                    "evaluated profile did not select it; manual review required."
                )
            else:
                # Still name the scan and the skeleton file this row came from.
                status, nr_reason = "Not_Reviewed", "no_scanner_rule"
                detail = "No scanner rule maps to this requirement.\n\n" + prov_txt
                comment = (
                    "No automated check for this requirement in the scanner content; manual review required."
                )
            vulns.append(
                {
                    **g,
                    "status": status,
                    "finding_details": detail,
                    "comments": comment,
                    "na_category": na_category,
                    "nr_reason": nr_reason,
                    "revision_drift": drift,
                }
            )
        stig["unmatched_ssg_vids"] = sorted(set(by_vid) - seen)
        stig["mapped_vids"] = len(set(by_vid) & seen)
        stig["unpaired_refs"] = sorted(unpaired)
    else:
        key = res["benchmark_id"].replace("xccdf_org.ssgproject.content_benchmark_", "")
        bid, title = SSG_STIG_IDS[key]  # main() skips unknown benchmarks
        ver, releaseinfo = release  # main() skips content the release table doesn't verify
        # The DISA file's own release info, verbatim: consumers read the
        # release and date from it. The table lookup is in the meta.
        stig = {
            "benchmark_id": bid,
            "title": title,
            "description": res["profile_title"],
            "version": ver,
            "releaseinfo": releaseinfo,
            "filename": f"{res['benchmark_id']}-{res['profile_id']}.xml",
            "mapped_vids": len(by_vid),
            "unpaired_refs": sorted(unpaired),
            "ambiguous_vids": [],
        }
        for vid in sorted(by_vid, key=lambda v: int(v[2:])):
            rids = by_vid[vid]
            first = res["rules"][sorted(rids)[0]]
            sev = max(
                (res["rules"][r]["severity"] for r in rids), key=lambda s: {"high": 3, "medium": 2, "low": 1}.get(s, 0)
            )
            status, detail, comment, ssg_rule_ids, na_category, nr_reason = vuln_from_ssg(vid, rids)
            if len(ssg_rule_ids) > 1:
                # The content itself cites several revisions of this
                # requirement, so no single Rule ID (D4) is provably right,
                # and any one written would be arbitrary: main() skips.
                stig["ambiguous_vids"].append(f"{vid} ({', '.join(sorted(ssg_rule_ids))})")
                continue
            # Rule_Ver (the DISA STIG id, e.g. RHEL-09-211010) carries no V-ID
            # number to pair on, so use it only when it can only belong to
            # this row: one id across the contributors, each citing one SV
            # (a malformed one counts: the id could be its).
            # Otherwise leave it empty and list the candidates as evidence.
            stig_ids = sorted({sid for r in rids for sid in res["rules"][r]["stig_ids"]})
            pairable = len(stig_ids) == 1 and all(
                len(res["rules"][r]["svs"]) == 1 and not res["rules"][r]["bad_svs"] for r in rids
            )
            if stig_ids and not pairable:
                detail += (
                    f"\n\nSTIG IDs cited by the contributing rules: {', '.join(stig_ids)}. They can't be "
                    f"paired with this V-ID, so Rule_Ver is left empty."
                )
            # SSG-only text follows ComplianceAsCode's own convention
            # (discussion <- rationale, fix text <- description), from *every*
            # contributing rule, failing ones first, so a fix for the rule that
            # actually failed is never hidden behind another rule's text.
            order = sorted(rids, key=lambda x: (res["results"][x] != "fail", x))
            rules_ = [res["rules"][x] for x in order]

            def labeled(field):
                if len(rules_) == 1:
                    return rules_[0][field]
                return "\n\n".join(
                    f"[{r['id'].replace('xccdf_org.ssgproject.content_rule_', '')}] {r[field]}" for r in rules_
                )

            vulns.append(
                {
                    "vid": vid,
                    "group_title": first["srg"] or "",
                    "rule_id": sorted(ssg_rule_ids)[0],
                    "severity": sev,
                    "weight": "10.0",
                    "rule_ver": stig_ids[0] if pairable else "",
                    "rule_title": " / ".join(dict.fromkeys(r["title"] for r in rules_)),
                    "discussion": labeled("rationale"),
                    "check_content": "Automated OpenSCAP check: " + ", ".join(sorted(rids)),
                    "check_ref": "M",
                    "fix_text": labeled("description"),
                    "ccis": [],
                    "legacy": [],
                    "documentable": "false",
                    "status": status,
                    "finding_details": detail,
                    "comments": comment,
                    "na_category": na_category,
                    "nr_reason": nr_reason,
                }
            )
    if res.get("tailoring"):
        t = res["tailoring"]
        # Dependencies/conflicts and item inheritance can deselect additional
        # contributors. TestResult is authoritative: conservatively withhold
        # a shared requirement whenever a tailored scan left any contributor
        # unselected, without claiming that stock exclusions were user actions.
        explicit = set(t["deselected_rules"])
        affected = {
            vid: sorted(rids if vid in by_vid else set(rids) & explicit)
            for vid, rids in deselected.items()
            if vid in by_vid or set(rids) & explicit
        }
        if not disa:
            vulns = [v for v in vulns if v["vid"] not in affected]
            stig["mapped_vids"] = len(vulns)
        else:
            for v in vulns:
                if v["vid"] not in affected:
                    continue
                direct = set(affected[v["vid"]]) & explicit
                indirect = set(affected[v["vid"]]) - direct
                notes = []
                if direct:
                    notes.append(f"Deselected by tailoring {t['profile_id']}: {', '.join(sorted(direct))}.")
                if indirect:
                    notes.append(f"Not selected under tailored profile {t['profile_id']}: {', '.join(sorted(indirect))}.")
                note = " ".join(notes)
                v["finding_details"] += "\n" + note + " Remaining automated evidence does not assess the complete requirement."
                values = tailoring_value_notes(affected[v["vid"]])
                if values:
                    v["finding_details"] += "\nDeselected checks' settings (checks were not evaluated):\n" + "\n".join(values)
                v["comments"] = note + " Manual review required."
                reason = "tailoring_deselected" if direct else "tailored_partial_selection"
                v["status"], v["nr_reason"], v["na_category"] = "Not_Reviewed", reason, None
    stig["uuid"] = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL, f"stig-scanner-orb:{stig['benchmark_id']}:{stig['version']}:{stig['releaseinfo']}"
        )
    )
    return stig, vulns


# ------------------------------------------------------------- writers

CKL_ATTRS = [
    ("Vuln_Num", "vid"),
    ("Severity", "severity"),
    ("Group_Title", "group_title"),
    ("Rule_ID", "rule_id"),
    ("Rule_Ver", "rule_ver"),
    ("Rule_Title", "rule_title"),
    ("Vuln_Discuss", "discussion"),
    ("IA_Controls", None),
    ("Check_Content", "check_content"),
    ("Fix_Text", "fix_text"),
    ("False_Positives", "false_positives"),
    ("False_Negatives", "false_negatives"),
    ("Documentable", "documentable"),
    ("Mitigations", "mitigations"),
    ("Potential_Impact", "potential_impacts"),
    ("Third_Party_Tools", "third_party"),
    ("Mitigation_Control", "mitigation_control"),
    ("Responsibility", "responsibility"),
    ("Security_Override_Guidance", "sec_override"),
    ("Check_Content_Ref", "check_ref"),
    ("Weight", "weight"),
    ("Class", "_class"),
    ("STIGRef", "_stigref"),
    ("TargetKey", None),
    ("STIG_UUID", "_stig_uuid"),
]


def stigref(stig):
    return f"{stig['title']} :: Version {stig['version']}, {stig['releaseinfo']}"


def indent_xml(element, level=0):
    """Indent generated CKL with the same layout on Python 3.8 and newer."""
    prefix = "\n" + "\t" * level
    if len(element):
        if not element.text or not element.text.strip():
            element.text = prefix + "\t"
        for child in element:
            indent_xml(child, level + 1)
        if not child.tail or not child.tail.strip():
            child.tail = prefix
    if level and (not element.tail or not element.tail.strip()):
        element.tail = prefix


def write_ckl(path, asset, stig, vulns):
    ck = ET.Element("CHECKLIST")
    a = ET.SubElement(ck, "ASSET")
    for k in (
        "ROLE",
        "ASSET_TYPE",
        "MARKING",
        "HOST_NAME",
        "HOST_IP",
        "HOST_MAC",
        "HOST_FQDN",
        "TARGET_COMMENT",
        "TECH_AREA",
        "TARGET_KEY",
        "WEB_OR_DATABASE",
        "WEB_DB_SITE",
        "WEB_DB_INSTANCE",
    ):
        ET.SubElement(a, k).text = asset.get(k, "")
    ist = ET.SubElement(ET.SubElement(ck, "STIGS"), "iSTIG")
    si = ET.SubElement(ist, "STIG_INFO")
    for name, val in (
        ("version", stig["version"]),
        ("classification", "UNCLASSIFIED"),
        ("customname", None),
        ("stigid", stig["benchmark_id"]),
        ("description", stig["description"]),
        ("filename", stig["filename"]),
        ("releaseinfo", stig["releaseinfo"]),
        ("title", stig["title"]),
        ("uuid", stig["uuid"]),
        ("notice", "terms-of-use"),
        ("source", "STIG.DOD.MIL"),
    ):
        d = ET.SubElement(si, "SI_DATA")
        ET.SubElement(d, "SID_NAME").text = name
        if val is not None:
            ET.SubElement(d, "SID_DATA").text = val
    extra = {"_class": "Unclass", "_stigref": stigref(stig), "_stig_uuid": stig["uuid"]}
    for v in vulns:
        ve = ET.SubElement(ist, "VULN")
        for attr, key in CKL_ATTRS:
            sd = ET.SubElement(ve, "STIG_DATA")
            ET.SubElement(sd, "VULN_ATTRIBUTE").text = attr
            ET.SubElement(sd, "ATTRIBUTE_DATA").text = extra[key] if key in extra else (v.get(key, "") if key else "")
        for lid in v.get("legacy", []):
            sd = ET.SubElement(ve, "STIG_DATA")
            ET.SubElement(sd, "VULN_ATTRIBUTE").text = "LEGACY_ID"
            ET.SubElement(sd, "ATTRIBUTE_DATA").text = lid
        for cci in v.get("ccis", []):
            sd = ET.SubElement(ve, "STIG_DATA")
            ET.SubElement(sd, "VULN_ATTRIBUTE").text = "CCI_REF"
            ET.SubElement(sd, "ATTRIBUTE_DATA").text = cci
        ET.SubElement(ve, "STATUS").text = v["status"]
        ET.SubElement(ve, "FINDING_DETAILS").text = v["finding_details"]
        ET.SubElement(ve, "COMMENTS").text = v["comments"]
        ET.SubElement(ve, "SEVERITY_OVERRIDE").text = ""
        ET.SubElement(ve, "SEVERITY_JUSTIFICATION").text = ""
    indent_xml(ck)
    with open_fresh(path) as f:
        # Neutral tool provenance (D9): this file isn't STIG Viewer's output.
        # Neither STIG Viewer 3's import nor STIG Manager's parser reads it.
        f.write(f'<?xml version="1.0" encoding="UTF-8"?>\n<!--stig-scanner-orb :: {GENERATOR_VERSION}-->\n')
        f.write(ET.tostring(ck, encoding="unicode"))
        f.write("\n")


CKLB_STATUS = {
    "NotAFinding": "not_a_finding",
    "Open": "open",
    "Not_Applicable": "not_applicable",
    "Not_Reviewed": "not_reviewed",
}


def write_cklb(path, asset, stig, vulns, now):
    cid = str(uuid.uuid4())
    stig_uuid = stig["uuid"]
    rules = []
    for v in vulns:
        rules.append(
            {
                "uuid": str(uuid.uuid4()),
                "stig_uuid": stig_uuid,
                "target_key": None,
                "stig_ref": None,
                "group_id": v["vid"],
                "rule_id": v["rule_id"].replace("_rule", "").rsplit("r", 1)[0] if v["rule_id"] else "",
                "rule_id_src": v["rule_id"],
                "weight": v["weight"],
                "classification": "Unclassified",
                "severity": v["severity"],
                "rule_version": v["rule_ver"],
                "group_title": v["group_title"],
                "rule_title": v["rule_title"],
                "fix_text": v["fix_text"],
                "false_positives": v.get("false_positives", ""),
                "false_negatives": v.get("false_negatives", ""),
                "discussion": v["discussion"],
                "check_content": v["check_content"],
                "documentable": v.get("documentable", "false"),
                "mitigations": v.get("mitigations", ""),
                "potential_impacts": v.get("potential_impacts", ""),
                "third_party_tools": v.get("third_party", ""),
                "mitigation_control": v.get("mitigation_control", ""),
                "responsibility": v.get("responsibility", ""),
                "security_override_guidance": v.get("sec_override", ""),
                "ia_controls": "",
                "check_content_ref": {"href": "", "name": v.get("check_ref", "M")},
                "legacy_ids": v.get("legacy", []),
                "ccis": v.get("ccis", []),
                "group_tree": [
                    {"id": v["vid"], "title": v["group_title"], "description": "<GroupDescription></GroupDescription>"}
                ],
                "createdAt": now,
                "updatedAt": now,
                "STIGUuid": stig_uuid,
                "status": CKLB_STATUS[v["status"]],
                "overrides": {},
                "comments": v["comments"],
                "finding_details": v["finding_details"],
            }
        )
    doc = {
        "title": f"{stig['benchmark_id']} - {asset['HOST_NAME']}",
        "id": cid,
        "stigs": [
            {
                "stig_name": stig["title"],
                "display_name": stig["title"].replace(" Security Technical Implementation Guide", ""),
                "stig_id": stig["benchmark_id"],
                "release_info": stig["releaseinfo"],
                "version": stig["version"],
                "uuid": stig_uuid,
                "reference_identifier": "",
                "size": len(rules),
                "rules": rules,
            }
        ],
        "active": False,
        "mode": 1,
        "has_path": True,
        "target_data": {
            "target_type": "Computing",
            "host_name": asset["HOST_NAME"],
            "ip_address": "",
            "mac_address": "",
            "fqdn": "",
            "comments": asset["TARGET_COMMENT"],
            "role": asset["ROLE"],
            "is_web_database": False,
            "technology_area": asset["TECH_AREA"],
            "web_db_site": "",
            "web_db_instance": "",
            "classification": None,
        },
        "cklb_version": "1.0",
    }
    with open_fresh(path) as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


# ---------------------------------------------------------------- main


def guard(argv):
    """--guard --out-dir DIR --results results.xml [--stem S]: run as a
    `when: always` step right before store_artifacts (D8). A SIGKILL between
    the format renames and the meta rename (or any kill of the checklist
    step, after which no later step but `when: always` ones runs) can leave
    checklist files beside a meta that doesn't vouch for them. Keep them only
    when the meta says generated, every format it lists is present with its
    sha256, and it was built from this results.xml; otherwise (a missing or
    unreadable results.xml or meta included) delete them."""
    ap = argparse.ArgumentParser(prog="checklist --guard")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--stem", default="checklist")
    # Required: without it a previous run's valid pair would pass even when
    # this scan never produced a results.xml.
    ap.add_argument("--results", required=True)
    ap.add_argument("--rootfs-path", default="")
    a = ap.parse_args(argv)
    # This always-run step can follow a scan refused for output/tree overlap.
    # Never undo that protection by deleting artifacts inside the caller's tree.
    if a.rootfs_path:
        tree, out = os.path.realpath(a.rootfs_path), os.path.realpath(a.out_dir)
        if os.path.commonpath((tree, out)) in (tree, out):
            print("Checklist guard skipped: output_dir overlaps rootfs_path", file=sys.stderr)
            return 1

    def sha(p):
        try:
            with open(p, "rb") as f:
                digest = hashlib.sha256()
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    digest.update(chunk)
                return digest.hexdigest()
        except OSError:
            return None  # unreadable never matches a recorded hash

    files = {ext: f"{a.out_dir}/{a.stem}.{ext}" for ext in ("ckl", "cklb")}
    try:
        with open(f"{a.out_dir}/{a.stem}-meta.json", encoding="utf-8") as fh:
            meta = json.loads(fh.read((1 << 20) + 1))
    except (OSError, ValueError):
        meta = {}
    meta = meta if isinstance(meta, dict) else {}
    listed = meta.get("formats") if meta.get("outcome") == "generated" else {}
    listed = listed if isinstance(listed, dict) else {}
    results_sha = sha(a.results)
    ok = (
        bool(listed)
        and set(listed) <= set(files)
        and all(
            os.path.isfile(files[e]) and not os.path.islink(files[e]) and sha(files[e]) == h for e, h in listed.items()
        )
        and results_sha is not None
        and meta.get("results_sha256") == results_sha
    )
    removed, stuck = [], []
    for ext, path in files.items():
        if (not ok or ext not in listed) and os.path.lexists(path):
            try:
                os.remove(path)
                removed.append(path)
            except OSError:
                stuck.append(path)
    for path in [p + ".partial" for p in files.values()] + [f"{a.out_dir}/{a.stem}-meta.json.partial"]:
        if os.path.lexists(path):
            try:
                os.remove(path)
                removed.append(path)
            except OSError:
                stuck.append(path)
    print(json.dumps({"guard": "kept" if ok else "removed", "removed": removed}))
    if stuck:
        print(f"Guard could not remove: {', '.join(stuck)}", file=sys.stderr)
        return 1
    return 0


def main():
    if sys.argv[1:2] == ["--guard"]:
        return guard(sys.argv[2:])
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--plan", required=True, help="the scan's scan-plan.env (scanner, target, datastream hash)")
    ap.add_argument("--host-name", default="")
    ap.add_argument("--stig-xccdf-path", default="", help="DISA manual XCCDF or ZIP, read offline")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--bundle-dir", default="", help="local generated bundle scripts; CircleCI uses staged payloads")
    ap.add_argument("--stem", default="checklist")
    ap.add_argument("--mode", default="auto")
    ap.add_argument("--formats", default="ckl,cklb", help="comma-separated: ckl, cklb")
    a = ap.parse_args()

    # Python's default SIGTERM/SIGHUP handling exits without unwinding, so a
    # termination between the two publishing renames would skip cleanup and
    # leave one final checklist for store_artifacts. Raise instead.
    def terminate(signum, _frame):
        raise SystemExit(128 + signum)

    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, terminate)

    meta_path = f"{a.out_dir}/{a.stem}-meta.json"
    artifacts = [f"{a.out_dir}/{a.stem}.{e}{p}" for e in ("ckl", "cklb") for p in ("", ".partial")] + [
        meta_path + ".partial"
    ]

    def remove_all(paths):
        """Remove every path; one failure doesn't stop the rest."""
        stuck = []
        for path in paths:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
            except OSError:
                stuck.append(path)
        return stuck

    results_sha, res = None, None

    def invalidate_meta():
        """Drop any existing meta in one syscall, then write the "did not
        finish" placeholder. Staging the placeholder takes time; the unlink
        doesn't, so a SIGKILL anywhere leaves no previous "generated" meta."""
        try:
            os.remove(meta_path)
        except FileNotFoundError:
            pass
        write_meta({"outcome": "failed", "reason": "the checklist step did not finish (interrupted)"})

    def write_meta(meta):
        """Replace the meta atomically (staged, then renamed)."""
        with open_fresh(meta_path + ".partial") as f:
            json.dump(meta, f, indent=1, default=list)
        os.replace(meta_path + ".partial", meta_path)

    def emit(meta, rc):
        """Write the meta and print it."""
        meta = {
            "schema": "stig-scanner-orb/checklist/v1",
            "generator_version": GENERATOR_VERSION,
            "mode": a.mode,
            "profile_id": res["profile_id"] if res else None,
            **meta,
            "results_sha256": results_sha,
        }
        write_meta(meta)
        print(json.dumps(meta, indent=1, default=list))
        return rc

    # Everything that can fail runs under one handler, so a crash (truncated
    # results.xml, malformed DISA file, writer error, termination) still
    # leaves a fresh "failed" meta with the reason (D8), never no meta.
    try:
        # Never leave a previous run's checklist behind for this run to
        # "publish". First drop any old meta (one unlink) and put a "did not
        # finish" placeholder in its place: from then on even a SIGKILL/OOM
        # (no handler runs) can't leave a previous "generated" meta beside
        # surviving old files. Then remove the files, inside the
        # handler, so a termination or error part-way still finishes it.
        invalidate_meta()
        stuck = remove_all(artifacts)
        if stuck:
            raise OSError(f"can't remove previous checklist outputs: {', '.join(stuck)}")
        # Hash and parse the same bytes, so the recorded sha256 is what the
        # checklist was built from.
        results_bytes = read_capped(a.results, MAX_RESULTS_BYTES, "results.xml")
        results_sha = hashlib.sha256(results_bytes).hexdigest()
        if a.mode not in ("auto", "require", "none"):
            raise ValueError(f"checklist must be auto, require, or none; got {a.mode!r}")
        if a.mode == "none":
            return emit({"outcome": "skipped", "reason": "checklist generation disabled (checklist: none)"}, 0)

        # Only known tokens; an empty or unknown selection is a config error, not
        # a silently empty "generated" checklist (D8).
        formats = list(dict.fromkeys(t.strip().lower() for t in a.formats.split(",") if t.strip()))
        if not formats or set(formats) - {"ckl", "cklb"}:
            return emit(
                {"outcome": "failed", "reason": f"checklist_formats {a.formats!r}: use one or both of ckl, cklb"}, 1
            )
        plan = {}
        with open(a.plan, encoding="utf-8") as plan_file:
            for line in plan_file:
                k, sep, v = line.rstrip("\n").partition("=")
                if sep:
                    if k in plan:
                        raise ValueError(f"the scan plan repeats {k}")
                    plan[k] = v
        tailoring = read_tailoring(plan, a.plan)
        res = parse_results(io.BytesIO(results_bytes), tailoring)
        if tailoring:
            validate_tailored_results(res, tailoring)
        ancestry = tailoring["base_profile_ancestry"] if tailoring else [res["profile_id"]]
        stig_bases = [p for p in ancestry if re.search(r"_profile_stig(_gui)?$", p)]
        source_profile = stig_bases[0] if stig_bases else None
        # Gate on the evaluated profile, not on SV references: SSG reuses rules
        # across profiles, so e.g. RHEL 9 CIS L1 selects 160 rules that carry
        # DISA references and would otherwise yield a partial "STIG" checklist.
        if not source_profile:
            return emit({"outcome": "skipped", "reason": f"profile {res['profile_id']} is not a DISA STIG profile"}, 0)
        # Every rule-result must resolve to a Rule in the file's benchmark. One
        # that doesn't (a truncated or edited file) would be dropped silently,
        # a fail included, while the rest still map and generate.
        undefined = sorted(rid for rid in res["results"] if rid not in res["rules"])
        if undefined:
            return emit(
                {
                    "outcome": "failed",
                    "reason": f"results.xml has {len(undefined)} rule-result(s) with no Rule "
                    f"definition (e.g. {', '.join(undefined[:5])}): incomplete or edited file",
                },
                1,
            )
        # And the other way: OpenSCAP writes a rule-result for every Rule,
        # notselected included, so a Rule without one was dropped (and with
        # it maybe a fail), in any mode.
        unresulted = sorted(set(res["rules"]) - set(res["results"]))
        if unresulted:
            return emit(
                {
                    "outcome": "failed",
                    "reason": f"results.xml has no rule-result for {len(unresulted)} Rule(s) "
                    f"(e.g. {', '.join(unresulted[:5])}): incomplete or edited file",
                },
                1,
            )
        # Every row's provenance and TARGET_COMMENT name the scanner and the
        # target by digest or id (a rootfs_path scan by its path): without
        # them a checklist can't be tied back to what was assessed.
        if not (plan.get("scanner_repo_digests") or plan.get("scanner_image_id")) or not (
            plan.get("image_repo_digests") or plan.get("image_id") or plan.get("rootfs_path")
        ):
            return emit(
                {
                    "outcome": "failed",
                    "reason": "the scan plan doesn't identify the scanner and the target "
                    "(scanner_repo_digests/scanner_image_id, image_repo_digests/image_id/rootfs_path)",
                },
                1,
            )
        # And it must be this results.xml's scan: scan.sh records the profile
        # it evaluated, so another profile's results can't borrow its
        # scanner and target provenance.
        if plan.get("profile") != res["profile_id"]:
            return emit(
                {
                    "outcome": "failed",
                    "reason": f"the scan plan's profile {plan.get('profile') or '(none)'} isn't "
                    f"results.xml's {res['profile_id']}: results and plan come from different scans",
                },
                1,
            )
        # The exact file: scan.sh records the sha256 of the results.xml it
        # published (PR 1), so another scan of the same profile and
        # datastream can't borrow this plan's scanner and target.
        if plan.get("results_sha256") != results_sha:
            return emit(
                {
                    "outcome": "failed",
                    "reason": f"the scan plan records results.xml sha256 "
                    f"{plan.get('results_sha256') or '(none)'}, but the file read is {results_sha}: results and plan "
                    f"come from different scans",
                },
                1,
            )
        # The release table (D4) identifies the exact datastream bytes the scan
        # evaluated, for that entry's benchmark, version and STIG profiles.
        ent = RELEASE_TABLE.get(plan.get("datastream_sha256", ""))
        if ent and tailoring:
            # An intermediary benchmark profile can inherit the verified STIG
            # profile. Locate that actual base instead of trusting its label.
            source_profile = next((p for p in stig_bases if p in ent[2]), source_profile)
        if ent and ((res["benchmark_id"], res["benchmark_version"]) != ent[:2] or source_profile not in ent[2]):
            # The plan names a known datastream, but results.xml can't have
            # come from it: the inputs are from different scans. Never let a
            # different inputs supply the release (provenance would be wrong).
            return emit(
                {
                    "outcome": "failed",
                    "reason": f"the plan's datastream sha256 is the pinned {ent[0]} {ent[1]}, "
                    f"but results.xml is {res['benchmark_id']} {res['benchmark_version']} {res['profile_id']}: "
                    f"results and plan come from different scans",
                },
                1,
            )
        if ent and not tailoring:
            # Known datastream and profile, so OpenSCAP's selection is known:
            # a results.xml selecting anything else is incomplete or edited,
            # whatever names the release.
            sel, fp = selection_fingerprint(res)
            if (sel, fp) != ent[2][res["profile_id"]]:
                return emit(
                    {
                        "outcome": "failed",
                        "reason": f"results.xml selects {sel} rules, but this datastream's "
                        f"{res['profile_id']} selects {ent[2][res['profile_id']][0]}, or their DISA references differ "
                        f"from what the release table verified: incomplete or edited file",
                    },
                    1,
                )
        key = res["benchmark_id"].replace("xccdf_org.ssgproject.content_benchmark_", "")
        expected_stig = SSG_STIG_IDS.get(key, (None,))[0] or TARGET_STIG.get(plan.get("target_base", ""))
        baseline = load_bundle(plan.get("datastream_sha256", ""), a.bundle_dir) if ent else None
        disa = read_disa(a.stig_xccdf_path, expected_stig) if a.stig_xccdf_path else baseline
        if tailoring and not disa:
            # Tailoring may select rules outside the stock profile's verified
            # release mapping. A complete DISA reference must supply identity
            # and revision checks; never borrow the stock SSG-only release.
            return emit({"outcome": "skipped", "reason":
                         "tailored checklists require bundled DISA data or stig_xccdf_path"}, 0)
        if not disa and key not in SSG_STIG_IDS:
            # A DISA benchmark id can't be derived from an SSG benchmark name,
            # and consumers merge rows on the exact id: never invent one.
            return emit(
                {
                    "outcome": "skipped",
                    "reason": f"no known DISA STIG id for {res['benchmark_id']}; " f"use a supported pinned datastream",
                },
                0,
            )
        if not ent and not disa:
            return emit(
                {
                    "outcome": "skipped",
                    "reason": f"the DISA release of {res['benchmark_id']} "
                    f"{res['benchmark_version']} {res['profile_id']} (datastream sha256 "
                    f"{plan.get('datastream_sha256') or 'not recorded'}) isn't in the verified release table; "
                    "use the pinned content or update the release table",
                },
                0,
            )
        release = ent[3] if ent else None
        unavailable_inventory = next((db for db in ("dpkg", "rpm") if plan.get(f"{db}_status") == "missing"), None)
        if unavailable_inventory:
            # Package and kernel platform conditions can depend on inventory probes.
            # results.xml does not identify which false gates came from a failed
            # probe; without that database we cannot certify absence or N/A.
            return emit(
                {
                    "outcome": "skipped",
                    "reason": f"the scan recorded {unavailable_inventory}_status=missing"
                    + (
                        f" ({plan[unavailable_inventory + '_status_reason']})"
                        if plan.get(unavailable_inventory + "_status_reason")
                        else ""
                    )
                    + "; package absence and applicability cannot be verified. "
                    + (
                        "Repair /var/lib/dpkg/status"
                        if unavailable_inventory == "dpkg"
                        else "Restore a usable RPM database"
                    )
                    + " and rerun the scan before generating a checklist",
                },
                0,
            )
        if plan.get("rootfs_path") and not a.host_name:
            return emit(
                {
                    "outcome": "skipped",
                    "reason": "rootfs_path scans require checklist_asset_name; "
                    "set it to a stable, unique asset name",
                },
                0,
            )
        a.host_name = a.host_name or plan.get("image", "")
        # HOST_NAME / host_name must be non-empty (STIG Manager rejects it):
        # control characters dropped, capped at 255.
        # Only characters XML 1.0 allows, minus controls: anything else (e.g.
        # U+FFFF, or a lone surrogate from undecodable argv bytes) would make
        # the CKL unparseable.
        host_name = re.sub(r"[^\x20-\x7e\x80-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]", "", a.host_name).strip()[:255]
        if not host_name:
            return emit({"outcome": "failed", "reason": "the checklist asset name is empty"}, 1)

        # OpenSCAP evaluates a rule only after one of the Benchmark's own
        # platforms holds, and lists every platform that held in TestResult.
        # None listed: it assessed nothing against this target, and every row
        # would blame inner gates it never evaluated ("gdm is not installed").
        bench_ps = res["bench_platforms"]
        if bench_ps and not set(bench_ps) & res["true_platforms"]:
            named = ", ".join(bench_ps[:3]) + (f" and {len(bench_ps) - 3} more" if len(bench_ps) > 3 else "")
            evaluated = [
                r
                for r, v in res["results"].items()
                if v in ("pass", "fail", "error", "unknown", "informational", "fixed")
            ]
            if evaluated:
                return emit(
                    {
                        "outcome": "failed",
                        "reason": f"results.xml has {len(evaluated)} evaluated rule(s) but lists none "
                        f"of the Benchmark's platforms ({named}) as true; OpenSCAP evaluates a rule only after one "
                        f"holds: edited or incomplete file",
                    },
                    1,
                )
            return emit(
                {
                    "outcome": "skipped",
                    "reason": f"OpenSCAP found none of the Benchmark's platforms ({named}) true "
                    f"for the target, so it assessed no rule: wrong target_base, or a scanner that can't "
                    f"recognize this OS",
                },
                0,
            )
        # The architecture OpenSCAP's arch platforms saw is the scanner
        # image's that ran on the daemon (natively, or emulated: uname then
        # reports the image's), never this host's: a remote daemon or a later
        # conversion elsewhere differs. Unknown leaves arch rows unreviewed.
        sp = plan.get("scanner_platform", "")
        runner_arch = sp.split("/")[1] if sp.count("/") >= 1 else None
        stig, vulns = build_model(res, plan, runner_arch, release, disa, baseline)
        # Severity is published as is: it must be a CKLB severity (the
        # schema's enum; SSG itself marks a few rules "unknown", which SSG-only
        # rows carry), never a blank, null or made-up value.
        bad_sev = sorted(
            {
                f"{v['vid']}={v['severity']!r}"
                for v in vulns
                if v["severity"] not in ("unknown", "low", "medium", "high")
            }
        )
        if bad_sev:
            return emit(
                {
                    "outcome": "failed",
                    "reason": f"{len(bad_sev)} row(s) have no valid severity, " f"e.g. {', '.join(bad_sev[:5])}",
                },
                1,
            )
        if stig.get("ambiguous_vids"):
            # Same rule as the STIG id and release: never write an arbitrary
            # Rule ID under the claimed release.
            return emit(
                {
                    "outcome": "skipped",
                    "reason": f"the scanner content cites several revisions for "
                    f"{len(stig['ambiguous_vids'])} V-ID(s), e.g. {'; '.join(stig['ambiguous_vids'][:3])}, so no "
                    f"single release's Rule ID can be written",
                },
                0,
            )
        # A STIG-named profile still proves nothing about the mapping: content
        # whose references moved to another URL (or a custom datastream without
        # them) would yield an empty "checklist" that row-count checks can't
        # catch. Require at least one selected rule mapped to a DISA V-ID.
        if ent and len(ent) > 4 and not tailoring:
            expected = ent[4]["profiles"][res["profile_id"].replace(_P, "", 1)]
            unmapped = sorted(
                rid.replace("xccdf_org.ssgproject.content_rule_", "", 1)
                for rid, result in res["results"].items()
                if result != "notselected" and not res["rules"][rid]["svs"]
            )
            if unmapped != expected["unmapped"]:
                raise ValueError(
                    f"selected rules without DISA references differ from the verified allowlist: {unmapped}"
                )
            mapped_count = len(stig.get("unmatched_ssg_vids", [])) + stig["mapped_vids"]
            if mapped_count != expected["vids"]:
                raise ValueError(
                    f"scanner content maps {mapped_count} V-IDs; the verified profile maps {expected['vids']}"
                )
        if disa:
            missing = len(stig["unmatched_ssg_vids"])
            mapped = missing + stig["mapped_vids"]
            if not stig["mapped_vids"]:
                raise ValueError("the DISA file shares no V-ID with selected scanner rules")
            if missing > max(10, mapped // 20):
                raise ValueError(
                    f"the DISA file lacks {missing} of the {mapped} V-IDs this scan maps: incomplete, or not this STIG"
                )
        if not stig["mapped_vids"]:
            return emit(
                {
                    "outcome": "skipped",
                    "reason": f"profile {res['profile_id']} has no selected rule "
                    f"with a DISA reference ({HREF_RULE} SV-..._rule)",
                },
                0,
            )
        asset = {
            "ROLE": "None",
            "ASSET_TYPE": "Computing",
            "MARKING": "",
            "HOST_NAME": host_name,
            "TARGET_COMMENT": (
                "Container image " if plan.get("image_repo_digests") or plan.get("image_id") else "Root filesystem "
            )
            + target_ref(plan)
            + (f" [{plan['image_platform']}]" if plan.get("image_platform") else ""),
            "TECH_AREA": "",
            "TARGET_KEY": "",
            "WEB_OR_DATABASE": "false",
        }
        now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        # Stage every requested format and the meta, then publish them in one
        # handler, the meta last: a failure or termination anywhere before the
        # meta is in place removes every final file, so no checklist is ever
        # left for store_artifacts without its "generated" meta (D8).
        final = {ext: f"{a.out_dir}/{a.stem}.{ext}" for ext in formats}
        staged = {ext: path + ".partial" for ext, path in final.items()}
        writers = {
            "ckl": lambda p: write_ckl(p, asset, stig, vulns),
            "cklb": lambda p: write_cklb(p, asset, stig, vulns, now),
        }
        counts = collections.Counter(v["status"] for v in vulns)
        na = collections.Counter(v["na_category"] for v in vulns if v["status"] == "Not_Applicable")
        nr = collections.Counter(v["nr_reason"] for v in vulns if v["status"] == "Not_Reviewed")
        try:
            for ext in formats:
                writers[ext](staged[ext])
                # Never publish a file the consumers can't parse, whatever
                # field broke it.
                if ext == "ckl":
                    ET.parse(staged[ext])
                else:
                    with open(staged[ext], encoding="utf-8") as f:
                        json.load(f)
            meta = {
                "schema": "stig-scanner-orb/checklist/v1",
                "generator_version": GENERATOR_VERSION,
                "mode": a.mode,
                "profile_id": res["profile_id"],
                "outcome": "generated",
                "host_name": host_name,
                # The detailed manifest has a separate 16 MiB budget. Keep
                # this summary within the guard/summarizer's 1 MiB contract.
                "tailoring": ({
                    "sha256": tailoring["sha256"],
                    "evaluated_sha256": tailoring["evaluated_sha256"],
                    "profile_id": tailoring["profile_id"],
                    "datastream_sha256": tailoring["datastream_sha256"],
                    "metadata_sha256": plan["tailoring_meta_sha256"],
                    "deselected_rule_count": len(tailoring["deselected_rules"]),
                    "value_count": len(tailoring["values"]),
                } if tailoring else None),
                "release_source": "skeleton" if a.stig_xccdf_path else "bundle" if baseline else "table",
                "bundle": (
                    {
                        "sha256": baseline["bundle_sha256"],
                        "source_sha256": baseline["source_sha256"],
                        "xccdf_sha256": baseline["sha256"],
                        "source_url": baseline["source_path"],
                        "credits": baseline["credits"],
                        "stig": {k: baseline[k] for k in ("benchmark_id", "version", "releaseinfo")},
                    }
                    if baseline
                    else None
                ),
                "revision_drift": collections.Counter(v.get("revision_drift") for v in vulns if v.get("revision_drift")),
                "skeleton_completeness": disa["completeness"] if disa else None,
                "skeleton_sha256": disa["sha256"] if disa else None,
                "skeleton_source_sha256": disa["source_sha256"] if disa else None,
                "skeleton_path": disa["source_path"] if disa else None,
                "skeleton_member": disa["member"] if disa else None,
                "unmatched_ssg_vids": stig.get("unmatched_ssg_vids", []),
                "datastream_sha256": plan.get("datastream_sha256"),
                "stig": {k: stig[k] for k in ("benchmark_id", "version", "releaseinfo")},
                "formats": {
                    ext: hashlib.sha256(read_capped(staged[ext], MAX_RESULTS_BYTES, "checklist")).hexdigest()
                    for ext in formats
                },
                "vulns": len(vulns),
                "status": counts,
                "na_by_reason": na,
                "not_reviewed_by_reason": nr,
                "unpaired_refs": stig["unpaired_refs"],
                "results_sha256": results_sha,
            }
            with open_fresh(meta_path + ".partial") as f:
                json.dump(meta, f, indent=1, default=list)
            for ext in formats:
                os.replace(staged[ext], final[ext])
            os.replace(meta_path + ".partial", meta_path)
        except BaseException:
            # Meta first again: a generated meta may already be in place.
            try:
                invalidate_meta()
            except Exception:
                pass
            remove_all([*staged.values(), *final.values(), meta_path + ".partial"])
            raise
        print(json.dumps(meta, indent=1, default=list))
        return 0
    except BaseException as e:
        stuck = remove_all(artifacts)
        try:
            emit({"outcome": "failed", "reason": f"{type(e).__name__}: {e}"[:500], "cleanup_errors": stuck}, 1)
        except Exception:
            pass  # best effort; summarize fails a missing meta anyway
        print(f"Checklist failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
PY_CHECKLIST
then
    :
else
    if [ "${GUARD}" = "true" ]; then
        echo "ERROR: checklist artifact guard could not complete cleanup." >&2
        exit 1
    fi
    echo "WARNING: checklist generation failed; summarize will report and enforce it." >&2
fi
