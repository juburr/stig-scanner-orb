#!/usr/bin/env python3
"""Spike: build a STIG Viewer checklist (CKL + CKLB) from an OpenSCAP/SSG
XCCDF results.xml, optionally overlaid on DISA's manual STIG XCCDF.

    xccdf2ckl.py --results results.xml [--disa U_..._Manual-xccdf.xml]
                 [--plan scan-plan.env] --host-name NAME --out-dir DIR

Stdlib only. Prototype quality: the point is to learn the data, not ship.
"""
import argparse
import collections
import datetime as dt
import hashlib
import html
import json
import os
import platform
import re
import signal
import sys
import uuid
import xml.etree.ElementTree as ET

X12 = "{http://checklists.nist.gov/xccdf/1.2}"
X11 = "{http://checklists.nist.gov/xccdf/1.1}"
HREF_RULE = "https://www.cyber.mil/stigs/srg-stig-tools/"
HREF_VULN = "https://www.cyber.mil/stigs/srg-stig-tools#vulnerability_id"

# ---------------------------------------------------------------- results


def text_of(el):
    if el is None:
        return ""
    return re.sub(r"\s+", " ", "".join(el.itertext())).strip()


XCCDF_RESULTS = {"pass", "fail", "error", "unknown", "notapplicable", "notchecked", "notselected", "informational", "fixed"}


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


def parse_results(path):
    root = ET.parse(path).getroot()
    bench = root if root.tag == X12 + "Benchmark" else next(root.iter(X12 + "Benchmark"))
    parent = {c: p for p in bench.iter() for c in p}

    def chain_platforms(el):
        """Platform idrefs per level, rule first, then ancestor groups."""
        levels = []
        while el is not None and el is not bench:
            ps = [p.get("idref") for p in el.findall(X12 + "platform")]
            if ps:
                levels.append(ps)
            el = parent.get(el)
        return levels

    rules = {}
    for r in bench.iter(X12 + "Rule"):
        refs = [(x.get("href") or "", (x.text or "").strip()) for x in r.findall(X12 + "reference")]
        ref = lambda pred: next((v for h, v in refs if pred(h, v)), None)
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
            "svs": {n: sorted({v for h, v in refs if h == HREF_RULE and re.match(rf"SV-{n}(?!\d)", v)})
                    for n in {re.match(r"SV-(\d+)", v).group(1) for h, v in refs if h == HREF_RULE and re.match(r"SV-\d+", v)}},
            "vids": [v for h, v in refs if h == HREF_VULN],
            "stig_id": ref(lambda h, v: "unix-linux" in h),
            "srg": ref(lambda h, v: v.startswith("SRG-")),
            "cce": next((text_of(i) for i in r.findall(X12 + "ident") if "cce" in (i.get("system") or "")), None),
            "platform_levels": chain_platforms(r),
        }

    tr = next(root.iter(X12 + "TestResult"))
    true_platforms = {p.get("idref") for p in tr.findall(X12 + "platform")}
    # XCCDF allows several rule-results per rule (multi-check, multiple
    # instances): keep them all and combine, never let the last one win.
    instances = collections.defaultdict(list)
    for rr in tr.findall(X12 + "rule-result"):
        r = (rr.findtext(X12 + "result") or "").strip()
        instances[rr.get("idref")].append(r if r in XCCDF_RESULTS else "unknown")
    results = {rid: combine_instances(rs) for rid, rs in instances.items()}
    profile_id = tr.find(X12 + "profile").get("idref")
    profile = next(p for p in bench.iter(X12 + "Profile") if p.get("id") == profile_id)
    pdesc = text_of(profile.find(X12 + "description"))
    m = re.search(r"DISA STIG for (.+?) V(\d+)R(\d+)", pdesc) or re.search(r"\(STIG\) V(\d+)R(\d+)", text_of(profile.find(X12 + "title")))
    return {
        "benchmark_id": bench.get("id"),
        "benchmark_version": bench.findtext(X12 + "version"),
        "profile_id": profile_id,
        "profile_title": text_of(profile.find(X12 + "title")),
        "disa_version": m.groups()[-2:] if m else None,
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
    every ancestor group is applicable too. OpenSCAP evaluates top-down and
    lists in TestResult only the platforms it evaluated true, so a gate below
    a failed group gate was never evaluated: walk outermost group -> rule.
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
    pk = [t[len("package_"):] for t in terms if t.startswith("package_")]
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
    "check": "Not Applicable per OpenSCAP: the automated check itself returned notapplicable for this image.",
}


def justification(cat, gates):
    kind, _, arg = cat.partition(":")
    return JUSTIFICATION[kind].format(gates=", ".join(g.lstrip("#") for g in gates) or "n/a", pkgs=arg.replace(",", " / "))


# ------------------------------------------------------ aggregation

# XCCDF result -> CKL status, per SSG rule.
PER_RULE = {
    "pass": "NotAFinding", "fixed": "NotAFinding",
    "fail": "Open",
    "notapplicable": "Not_Applicable",
    "notchecked": "Not_Reviewed", "informational": "Not_Reviewed",
    "error": "Not_Reviewed", "unknown": "Not_Reviewed",
}


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


# ------------------------------------------------------- DISA skeleton


def parse_disa(path):
    root = ET.parse(path).getroot()
    ns = X11 if root.tag.startswith(X11) else X12
    info = {
        "benchmark_id": root.get("id"),
        "title": text_of(root.find(ns + "title")),
        "description": text_of(root.find(ns + "description")),
        "version": root.findtext(ns + "version"),
        "releaseinfo": next((text_of(p) for p in root.findall(ns + "plain-text") if p.get("id") == "release-info"), ""),
        "groups": [],
    }
    for g in root.iter(ns + "Group"):
        r = g.find(ns + "Rule")
        if r is None:
            continue
        desc_raw = r.findtext(ns + "description") or ""
        tags = dict(re.findall(r"<(\w+)>(.*?)</\1>", html.unescape(desc_raw), re.S))
        chk = r.find(ns + "check")
        info["groups"].append({
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
            "check_content": (chk.findtext(ns + "check-content") or "").strip() if chk is not None else "",
            "check_ref": (chk.find(ns + "check-content-ref").get("name") if chk is not None and chk.find(ns + "check-content-ref") is not None else "M"),
            "fix_text": (r.findtext(ns + "fixtext") or "").strip(),
            "ccis": [i.text.strip() for i in r.findall(ns + "ident") if "cci" in (i.get("system") or "").lower()],
            "legacy": [i.text.strip() for i in r.findall(ns + "ident") if "legacy" in (i.get("system") or "").lower()],
        })
    return info


# ------------------------------------------------------------- model

SSG_STIG_IDS = {  # SSG benchmark -> DISA benchmark id / title (SSG-only mode)
    "RHEL-9": ("RHEL_9_STIG", "Red Hat Enterprise Linux 9 Security Technical Implementation Guide"),
    "RHEL-8": ("RHEL_8_STIG", "Red Hat Enterprise Linux 8 Security Technical Implementation Guide"),
    "RHEL-10": ("RHEL_10_STIG", "Red Hat Enterprise Linux 10 Security Technical Implementation Guide"),
    "UBUNTU_22-04": ("CAN_Ubuntu_22-04_LTS_STIG", "Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide"),
}


# scan-plan.env target_base -> DISA benchmark id, for checking a user's DISA file
# when the results' benchmark isn't one of the SSG_STIG_IDS above.
TARGET_STIG = {"rhel8": "RHEL_8_STIG", "rhel9": "RHEL_9_STIG", "rhel10": "RHEL_10_STIG", "ubuntu2204": "CAN_Ubuntu_22-04_LTS_STIG"}


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


def target_ref(plan):
    """Digest-bound target identity: registry digest, else the local image id
    that ran (with the tag for readability), else the rootfs path."""
    if plan.get("image_repo_digests"):
        return plan["image_repo_digests"]
    if plan.get("image_id"):
        return " ".join(filter(None, (plan.get("image"), f"(image id {plan['image_id']})")))
    return plan.get("image") or plan.get("rootfs_path") or ""


def build_model(res, disa, plan, runner_arch=None):
    # OpenSCAP's architecture platforms read the scanning host's /proc, not
    # the target. Image mode records the target platform (os/arch[/variant]);
    # rootfs_path doesn't. Compare architectures only, keep the full platform
    # for provenance.
    target_platform = plan.get("image_platform") or None
    target_arch = norm_arch(target_platform.split("/")[1]) if target_platform and target_platform.count("/") >= 1 else None
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
        return all(arch_term_value(t, runner_arch) is not None
                   and arch_term_value(t, runner_arch) == arch_term_value(t, target_arch)
                   for t in terms)

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
    unpaired = []
    for rid, result in res["results"].items():
        r = res["rules"].get(rid)
        if result == "notselected" or not r:
            continue
        if r["vids"]:
            # Only a V-n with a matching SV-n is a row (D3); anything else
            # can't name a DISA rule, so report it instead of keying on it.
            vids = [v for v in r["vids"] if v[2:] in r["svs"]]
            unpaired += [f"{rid}: {v}" for v in r["vids"] if v[2:] not in r["svs"]]
            unpaired += [f"{rid}: {sv}" for n, revs in r["svs"].items() if f"V-{n}" not in r["vids"] for sv in revs]
        else:
            # SSG < 0.1.82 has no #vulnerability_id references: derive V-n from SV-n.
            vids = [f"V-{n}" for n in r["svs"]]
        for vid in vids:
            by_vid[vid].append(rid)

    prov = []
    if plan:
        # Registry digest first; a locally built or loaded image has none, so
        # fall back to the image id that actually ran, never the mutable tag.
        scanner = plan.get("scanner_repo_digests") or " ".join(filter(None, (plan.get("scanner"), plan.get("scanner_image_id") and f"(image id {plan['scanner_image_id']})")))
        prov.append(f"Scanner: {scanner}; datastream {plan.get('datastream')} sha256 {plan.get('datastream_sha256')}")
        target = target_ref(plan)
        prov.append(f"Target: {target}" + (f" [{target_platform}]" if target_platform else "")
                    + (f"; scanned on {runner_arch}" if runner_arch else ""))
    prov.append(f"Content: {res['benchmark_id']} {res['benchmark_version']}, profile {res['profile_id']}; "
                f"scan {res['start']} .. {res['end']} ({res['test_system']})")
    prov_txt = "\n".join(prov)
    arch_note = f"[architecture gate evaluated on the scanning host ({runner_arch}); target architecture {target_arch or 'unknown'}]"

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
            elif result != "notselected":
                verdict, level = target_verdict(r)
                if verdict == "na":
                    # OpenSCAP passed an arch gate on the runner that the
                    # target fails: the requirement doesn't apply to it.
                    eff = "notapplicable"
                    na_cats.add(("arch", tuple(level)))
                    line += f" -> notapplicable for the target ({target_arch}): an architecture gate passed on the scanning host ({runner_arch}) is false for it"
                elif verdict == "uncertain":
                    eff = "notchecked"
                    uncertain.add("eval")
                    line += " -> not reviewed " + arch_note
            effective.append((rid, eff))
            details.append(line)
        status = aggregate(effective)
        if status == "Not_Applicable":
            comments = [justification(c, list(g)) for c, g in sorted(na_cats)]
        elif status == "Not_Reviewed" and uncertain:
            if "na" in uncertain:
                comments.append(f"Not reviewed: OpenSCAP marked a contributing check notapplicable on a CPU-architecture "
                                f"condition it evaluated against the scanning host ({runner_arch}); the target's "
                                f"architecture is {target_arch or 'unknown'}. Verify applicability manually.")
            if "eval" in uncertain:
                comments.append(f"Not reviewed: OpenSCAP evaluated a contributing check past a CPU-architecture condition on "
                                f"the scanning host ({runner_arch}), which can't be decided for the target "
                                f"({target_arch or 'architecture unknown'}). The automated result is kept in the finding "
                                f"details; verify manually.")
        # The N/A category travels in the model, so reporting never has to
        # parse it back out of the justification prose.
        na_category = "+".join(sorted({c.partition(":")[0] for c, _ in na_cats})) if status == "Not_Applicable" else None
        head = f"Automated result from OpenSCAP ({len(rids)} SSG rule{'s' if len(rids) > 1 else ''}):"
        return status, head + "\n" + "\n".join(details) + "\n\n" + prov_txt, "\n".join(dict.fromkeys(comments)), ruleids, na_category

    vulns = []
    if disa:
        stig = {k: disa[k] for k in ("benchmark_id", "title", "description", "version", "releaseinfo")}
        rel = re.search(r"Release: *(\d+)", disa["releaseinfo"]).group(1)
        stig["filename"] = f"U_{disa['benchmark_id']}_V{disa['version']}R{rel}_Manual-xccdf.xml"
        seen = set()
        for g in disa["groups"]:
            rids = by_vid.get(g["vid"], [])
            seen.add(g["vid"])
            na_category = None
            if rids:
                status, detail, comment, ssg_rule_ids, na_category = vuln_from_ssg(g["vid"], rids)
                if ssg_rule_ids != {g["rule_id"]}:
                    # The content's revision of the requirement differs from the
                    # skeleton's (the skeleton may be newer *or* older), and
                    # nothing here proves the check is unchanged, so don't carry
                    # the verdict: keep it as evidence only. Every contributing
                    # rule must cite the skeleton's revision: a mixed set still
                    # evaluates part of another revision.
                    other_revs = sorted(ssg_rule_ids - {g["rule_id"]})
                    detail += (f"\n\nRevision mismatch: the scanner content maps this check to "
                               f"{', '.join(sorted(ssg_rule_ids))}; this checklist's STIG release has {g['rule_id']}, "
                               f"so {', '.join(other_revs)} {'is a different revision' if len(other_revs) == 1 else 'are different revisions'}. "
                               f"Automated result across the content's revisions: {status}.")
                    status, na_category = "Not_Reviewed", None
                    comment = (f"Not reviewed: this checklist's STIG release has {g['rule_id']}, and the automated result "
                               f"comes from content aligned to a different revision of this requirement. Re-verify.")
            else:
                status, detail, comment = "Not_Reviewed", "", "No automated check for this requirement in the scanner content; manual review required."
            vulns.append({**g, "status": status, "finding_details": detail, "comments": comment, "na_category": na_category})
        stig["unmatched_ssg_vids"] = sorted(set(by_vid) - seen)
        stig["mapped_vids"] = len(set(by_vid) & seen)
        stig["unpaired_refs"] = sorted(unpaired)
    else:
        key = res["benchmark_id"].replace("xccdf_org.ssgproject.content_benchmark_", "")
        bid, title = SSG_STIG_IDS.get(key, (key + "_STIG", res["profile_title"]))
        ver, rel = res["disa_version"] or ("0", "0")
        stig = {"benchmark_id": bid, "title": title, "description": res["profile_title"], "version": ver,
                "releaseinfo": f"Release: {rel} Benchmark Date: unknown (derived from {res['benchmark_id']} {res['benchmark_version']})",
                "filename": f"{res['benchmark_id']}-{res['profile_id']}.xml", "unmatched_ssg_vids": [],
                "mapped_vids": len(by_vid), "unpaired_refs": sorted(unpaired)}
        for vid in sorted(by_vid, key=lambda v: int(v[2:])):
            rids = by_vid[vid]
            first = res["rules"][sorted(rids)[0]]
            sev = max((res["rules"][r]["severity"] for r in rids), key=lambda s: {"high": 3, "medium": 2, "low": 1}.get(s, 0))
            status, detail, comment, ssg_rule_ids, na_category = vuln_from_ssg(vid, rids)
            if len(ssg_rule_ids) > 1:
                # The content itself cites several revisions of this
                # requirement, so no single Rule ID (D4) is provably right.
                detail += (f"\n\nRevision ambiguity: the scanner content cites {', '.join(sorted(ssg_rule_ids))} "
                           f"for this requirement. Automated result across them: {status}.")
                status, na_category = "Not_Reviewed", None
                comment = ("Not reviewed: the scanner content cites more than one revision of this requirement, "
                           "so the result can't be tied to this checklist's release. Re-verify.")
            # SSG-only text follows ComplianceAsCode's own convention
            # (discussion <- rationale, fix text <- description), from *every*
            # contributing rule, failing ones first, so a fix for the rule that
            # actually failed is never hidden behind another rule's text.
            order = sorted(rids, key=lambda x: (res["results"][x] != "fail", x))
            rules_ = [res["rules"][x] for x in order]
            def labeled(field):
                if len(rules_) == 1:
                    return rules_[0][field]
                return "\n\n".join(f"[{r['id'].replace('xccdf_org.ssgproject.content_rule_', '')}] {r[field]}" for r in rules_)
            vulns.append({
                "vid": vid, "group_title": first["srg"] or "", "rule_id": sorted(ssg_rule_ids)[0], "severity": sev,
                "weight": "10.0", "rule_ver": first["stig_id"] or "",
                "rule_title": " / ".join(dict.fromkeys(r["title"] for r in rules_)),
                "discussion": labeled("rationale"), "check_content": "Automated OpenSCAP check: " + ", ".join(sorted(rids)),
                "check_ref": "M", "fix_text": labeled("description"), "ccis": [], "legacy": [], "documentable": "false",
                "status": status, "finding_details": detail, "comments": comment, "na_category": na_category,
            })
    stig["uuid"] = str(uuid.uuid5(uuid.NAMESPACE_URL, f"stig-scanner-orb:{stig['benchmark_id']}:{stig['version']}:{stig['releaseinfo']}"))
    return stig, vulns


# ------------------------------------------------------------- writers

CKL_ATTRS = [
    ("Vuln_Num", "vid"), ("Severity", "severity"), ("Group_Title", "group_title"), ("Rule_ID", "rule_id"),
    ("Rule_Ver", "rule_ver"), ("Rule_Title", "rule_title"), ("Vuln_Discuss", "discussion"), ("IA_Controls", None),
    ("Check_Content", "check_content"), ("Fix_Text", "fix_text"), ("False_Positives", "false_positives"),
    ("False_Negatives", "false_negatives"), ("Documentable", "documentable"), ("Mitigations", "mitigations"),
    ("Potential_Impact", "potential_impacts"), ("Third_Party_Tools", "third_party"),
    ("Mitigation_Control", "mitigation_control"), ("Responsibility", "responsibility"),
    ("Security_Override_Guidance", "sec_override"), ("Check_Content_Ref", "check_ref"), ("Weight", "weight"),
    ("Class", "_class"), ("STIGRef", "_stigref"), ("TargetKey", None), ("STIG_UUID", "_stig_uuid"),
]


def stigref(stig):
    return f"{stig['title']} :: Version {stig['version']}, {stig['releaseinfo']}"


def write_ckl(path, asset, stig, vulns):
    ck = ET.Element("CHECKLIST")
    a = ET.SubElement(ck, "ASSET")
    for k in ("ROLE", "ASSET_TYPE", "MARKING", "HOST_NAME", "HOST_IP", "HOST_MAC", "HOST_FQDN",
              "TARGET_COMMENT", "TECH_AREA", "TARGET_KEY", "WEB_OR_DATABASE", "WEB_DB_SITE", "WEB_DB_INSTANCE"):
        ET.SubElement(a, k).text = asset.get(k, "")
    ist = ET.SubElement(ET.SubElement(ck, "STIGS"), "iSTIG")
    si = ET.SubElement(ist, "STIG_INFO")
    for name, val in (("version", stig["version"]), ("classification", "UNCLASSIFIED"), ("customname", None),
                      ("stigid", stig["benchmark_id"]), ("description", stig["description"]),
                      ("filename", stig["filename"]), ("releaseinfo", stig["releaseinfo"]),
                      ("title", stig["title"]), ("uuid", stig["uuid"]), ("notice", "terms-of-use"),
                      ("source", "STIG.DOD.MIL")):
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
    ET.indent(ck, "\t")
    with open(path, "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n<!--DISA STIG Viewer :: 2.18-->\n')
        f.write(ET.tostring(ck, encoding="unicode"))
        f.write("\n")


CKLB_STATUS = {"NotAFinding": "not_a_finding", "Open": "open", "Not_Applicable": "not_applicable", "Not_Reviewed": "not_reviewed"}


def write_cklb(path, asset, stig, vulns, now):
    cid = str(uuid.uuid4())
    stig_uuid = stig["uuid"]
    rules = []
    for v in vulns:
        rules.append({
            "uuid": str(uuid.uuid4()), "stig_uuid": stig_uuid, "target_key": None, "stig_ref": None,
            "group_id": v["vid"], "rule_id": v["rule_id"].replace("_rule", "").rsplit("r", 1)[0] if v["rule_id"] else "",
            "rule_id_src": v["rule_id"], "weight": v["weight"], "classification": "Unclassified",
            "severity": v["severity"], "rule_version": v["rule_ver"], "group_title": v["group_title"],
            "rule_title": v["rule_title"], "fix_text": v["fix_text"], "false_positives": v.get("false_positives", ""),
            "false_negatives": v.get("false_negatives", ""), "discussion": v["discussion"],
            "check_content": v["check_content"], "documentable": v.get("documentable", "false"),
            "mitigations": v.get("mitigations", ""), "potential_impacts": v.get("potential_impacts", ""),
            "third_party_tools": v.get("third_party", ""), "mitigation_control": v.get("mitigation_control", ""),
            "responsibility": v.get("responsibility", ""), "security_override_guidance": v.get("sec_override", ""),
            "ia_controls": "", "check_content_ref": {"href": "", "name": v.get("check_ref", "M")},
            "legacy_ids": v.get("legacy", []), "ccis": v.get("ccis", []),
            "group_tree": [{"id": v["vid"], "title": v["group_title"], "description": "<GroupDescription></GroupDescription>"}],
            "createdAt": now, "updatedAt": now, "STIGUuid": stig_uuid,
            "status": CKLB_STATUS[v["status"]], "overrides": {}, "comments": v["comments"],
            "finding_details": v["finding_details"],
        })
    doc = {
        "title": f"{stig['benchmark_id']} - {asset['HOST_NAME']}", "id": cid,
        "stigs": [{
            "stig_name": stig["title"], "display_name": stig["title"].replace(" Security Technical Implementation Guide", ""),
            "stig_id": stig["benchmark_id"], "release_info": stig["releaseinfo"], "version": stig["version"],
            "uuid": stig_uuid, "reference_identifier": "", "size": len(rules), "rules": rules,
        }],
        "active": False, "mode": 1, "has_path": True,
        "target_data": {
            "target_type": "Computing", "host_name": asset["HOST_NAME"], "ip_address": "", "mac_address": "",
            "fqdn": "", "comments": asset["TARGET_COMMENT"], "role": asset["ROLE"], "is_web_database": False,
            "technology_area": asset["TECH_AREA"], "web_db_site": "", "web_db_instance": "",
            "classification": None,
        },
        "cklb_version": "1.0",
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--disa")
    ap.add_argument("--plan")
    ap.add_argument("--host-name", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--stem", default="checklist")
    ap.add_argument("--runner-arch", default=platform.machine(), help="architecture OpenSCAP ran on (default: this host)")
    ap.add_argument("--formats", default="ckl,cklb", help="comma-separated: ckl, cklb")
    a = ap.parse_args()

    # Python's default SIGTERM/SIGHUP handling exits without unwinding, so a
    # termination between the two publishing renames would skip cleanup and
    # leave one final checklist for store_artifacts. Raise instead.
    def terminate(signum, _frame):
        raise SystemExit(128 + signum)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, terminate)

    # Never leave a previous run's checklist behind for this run to "publish".
    meta_path = f"{a.out_dir}/{a.stem}-meta.json"
    for path in [f"{a.out_dir}/{a.stem}.{e}{p}" for e in ("ckl", "cklb") for p in ("", ".partial")] + [meta_path, meta_path + ".partial"]:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass

    results_sha = None

    def emit(meta, rc):
        """Write the meta (staged, then renamed) and print it."""
        meta = {**meta, "results_sha256": results_sha}
        with open(meta_path + ".partial", "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=1, default=list)
        os.replace(meta_path + ".partial", meta_path)
        print(json.dumps(meta, indent=1, default=list))
        return rc

    # Everything that can fail runs under one handler, so a crash (truncated
    # results.xml, malformed DISA file, writer error, termination) still
    # leaves a fresh "failed" meta with the reason (D8), never no meta.
    try:
        with open(a.results, "rb") as f:
            results_sha = hashlib.sha256(f.read()).hexdigest()

        # Only known tokens; an empty or unknown selection is a config error, not
        # a silently empty "generated" checklist (D8).
        formats = list(dict.fromkeys(t.strip().lower() for t in a.formats.split(",") if t.strip()))
        if not formats or set(formats) - {"ckl", "cklb"}:
            return emit({"outcome": "failed", "reason": f"checklist_formats {a.formats!r}: use one or both of ckl, cklb"}, 1)
        # HOST_NAME / host_name must be non-empty (STIG Manager rejects it):
        # control characters dropped, capped at 255.
        host_name = re.sub(r"[\x00-\x1f\x7f]", "", a.host_name).strip()[:255]
        if not host_name:
            return emit({"outcome": "failed", "reason": "the checklist asset name is empty"}, 1)

        res = parse_results(a.results)
        # Gate on the evaluated profile, not on SV references: SSG reuses rules
        # across profiles, so e.g. RHEL 9 CIS L1 selects 160 rules that carry
        # DISA references and would otherwise yield a partial "STIG" checklist.
        if not re.search(r"_profile_stig(_gui)?$", res["profile_id"]):
            return emit({"outcome": "skipped", "reason": f"profile {res['profile_id']} is not a DISA STIG profile"}, 0)
        plan = {}
        if a.plan:
            for line in open(a.plan, encoding="utf-8"):
                k, sep, v = line.rstrip("\n").partition("=")
                if sep:
                    plan[k] = v
        disa = parse_disa(a.disa) if a.disa else None
        if disa:
            # The file must be the STIG this content implements; one shared
            # V-ID (the mapping gate below) doesn't prove that.
            key = res["benchmark_id"].replace("xccdf_org.ssgproject.content_benchmark_", "")
            expected = SSG_STIG_IDS.get(key, (None,))[0] or TARGET_STIG.get(plan.get("target_base", ""))
            if expected is None:
                return emit({"outcome": "failed", "reason": f"can't tell which DISA STIG {res['benchmark_id']} implements, "
                             f"so the DISA file {disa['benchmark_id']} can't be checked"}, 1)
            if disa["benchmark_id"] != expected:
                return emit({"outcome": "failed", "reason": f"the DISA file is {disa['benchmark_id']}, but this scan's "
                             f"content implements {expected}"}, 1)
        stig, vulns = build_model(res, disa, plan, a.runner_arch)
        # A STIG-named profile still proves nothing about the mapping: content
        # whose references moved to another URL (or a custom datastream without
        # them) would yield an empty "checklist" that row-count checks can't
        # catch. Require at least one selected rule mapped to a DISA V-ID.
        if not stig["mapped_vids"]:
            if disa:
                # The user's DISA file shares no V-ID with the scan: wrong STIG.
                return emit({"outcome": "failed", "reason": f"no selected rule maps to a V-ID in {stig['filename']}"}, 1)
            return emit({"outcome": "skipped", "reason": f"profile {res['profile_id']} has no selected rule "
                         f"with a DISA reference ({HREF_RULE} SV-..._rule)"}, 0)
        asset = {
            "ROLE": "None", "ASSET_TYPE": "Computing", "MARKING": "CUI", "HOST_NAME": host_name,
            "TARGET_COMMENT": "Container image " + target_ref(plan)
                              + (f" [{plan['image_platform']}]" if plan.get("image_platform") else ""),
            "TECH_AREA": "", "TARGET_KEY": "", "WEB_OR_DATABASE": "false",
        }
        now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        # Stage every requested format and the meta, then publish them in one
        # handler, the meta last: a failure or termination anywhere before the
        # meta is in place removes every final file, so no checklist is ever
        # left for store_artifacts without its "generated" meta (D8).
        final = {ext: f"{a.out_dir}/{a.stem}.{ext}" for ext in formats}
        staged = {ext: path + ".partial" for ext, path in final.items()}
        writers = {"ckl": lambda p: write_ckl(p, asset, stig, vulns), "cklb": lambda p: write_cklb(p, asset, stig, vulns, now)}
        counts = collections.Counter(v["status"] for v in vulns)
        na = collections.Counter(v["na_category"] for v in vulns if v["status"] == "Not_Applicable")
        try:
            for ext in formats:
                writers[ext](staged[ext])
            meta = {"outcome": "generated", "stig": {k: stig[k] for k in ("benchmark_id", "version", "releaseinfo")},
                    "formats": {ext: hashlib.sha256(open(staged[ext], "rb").read()).hexdigest() for ext in formats},
                    "vulns": len(vulns), "status": counts, "na_by_reason": na,
                    "ssg_vids_not_in_disa": stig["unmatched_ssg_vids"], "unpaired_refs": stig["unpaired_refs"],
                    "results_sha256": results_sha}
            with open(meta_path + ".partial", "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=1, default=list)
            for ext in formats:
                os.replace(staged[ext], final[ext])
            os.replace(meta_path + ".partial", meta_path)
        except BaseException:
            for path in (*staged.values(), *final.values(), meta_path + ".partial", meta_path):
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
            raise
        print(json.dumps(meta, indent=1, default=list))
    except BaseException as e:
        try:
            emit({"outcome": "failed", "reason": f"{type(e).__name__}: {e}"[:500]}, 1)
        except Exception:
            pass  # best effort; summarize fails a missing meta anyway
        raise


if __name__ == "__main__":
    sys.exit(main())
