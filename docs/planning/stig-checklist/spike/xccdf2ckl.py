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
import html
import json
import os
import platform
import re
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
            "svs": {re.match(r"SV-(\d+)", v).group(1): v for h, v in refs if h == HREF_RULE and re.match(r"SV-\d+", v)},
            "vids": [v for h, v in refs if h == HREF_VULN],
            "stig_id": ref(lambda h, v: "unix-linux" in h),
            "srg": ref(lambda h, v: v.startswith("SRG-")),
            "cce": next((text_of(i) for i in r.findall(X12 + "ident") if "cce" in (i.get("system") or "")), None),
            "platform_levels": chain_platforms(r),
        }

    tr = next(root.iter(X12 + "TestResult"))
    true_platforms = {p.get("idref") for p in tr.findall(X12 + "platform")}
    results = {}
    for rr in tr.findall(X12 + "rule-result"):
        results[rr.get("idref")] = (rr.findtext(X12 + "result") or "").strip()
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
HOST_TERMS = re.compile(r"^(system_with_kernel|machine|not_container|not_bootc_and_not_container|bootc|grub2|uefi|not_osbuild|.*kernel.*)$")
GUI_PACKAGES = {"gdm", "gnome-shell", "dconf", "xorg-x11-server-common", "xwayland"}


def gate_terms(gates):
    terms = []
    for g in gates:
        g = g.lstrip("#")
        terms += [g] if g == "not_bootc_and_not_container" else g.split("_and_")
    return terms


def classify_na(gates):
    """One category per unmet level. Host wins: every arch-gated and most
    package-gated host rules in SSG are also kernel-gated, and a rule that
    *requires* a package (audit, aide, openssh-server) is kernel-gated, so it
    never lands in "package absent"."""
    terms = gate_terms(gates)
    if not terms:
        return "check"
    if any(HOST_TERMS.match(t) for t in terms):
        return "host"
    pk = [t[len("package_"):] for t in terms if t.startswith("package_")]
    if pk and len(pk) == len(terms):
        return ("gui:" if set(pk) & GUI_PACKAGES else "package:") + ",".join(pk)
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
    "gui": (
        "Not Applicable. No graphical user interface is installed in the image ({pkgs} not "
        "installed; OpenSCAP platform check {gates} was false). DISA: \"If the system does not "
        "have any graphical user interface installed, this requirement is Not Applicable.\""
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


ARCH_ALIASES = {"x86_64": "amd64", "aarch64": "arm64"}


def norm_arch(a):
    return ARCH_ALIASES.get(a, a) if a else None


def has_arch_gate(rule):
    return any(t.endswith("_arch") for level in rule["platform_levels"] for t in gate_terms(level))


def build_model(res, disa, plan, runner_arch=None):
    # OpenSCAP's architecture platforms read the scanning host's /proc, not
    # the target. Trust an architecture verdict only when the target's
    # platform is known (image mode records it) and matches the runner.
    target_arch = norm_arch((plan.get("image_platform") or "").partition("/")[2] or None)
    runner_arch = norm_arch(runner_arch)
    arch_ok = target_arch is not None and target_arch == runner_arch
    by_vid = collections.defaultdict(list)
    for rid, result in res["results"].items():
        r = res["rules"].get(rid)
        if result == "notselected" or not r:
            continue
        for vid in r["vids"]:
            by_vid[vid].append(rid)

    prov = []
    if plan:
        prov.append(f"Scanner: {plan.get('scanner_repo_digests') or plan.get('scanner')}; "
                    f"datastream {plan.get('datastream')} sha256 {plan.get('datastream_sha256')}")
        prov.append(f"Target: {plan.get('image_repo_digests') or plan.get('image') or plan.get('rootfs_path')}")
    prov.append(f"Content: {res['benchmark_id']} {res['benchmark_version']}, profile {res['profile_id']}; "
                f"scan {res['start']} .. {res['end']} ({res['test_system']})")
    prov_txt = "\n".join(prov)

    def vuln_from_ssg(vid, rids):
        details, comments, ruleids = [], [], set()
        na_cats = set()
        for rid in sorted(rids):
            r, result = res["rules"][rid], res["results"][rid]
            if vid[2:] in r["svs"]:
                ruleids.add(r["svs"][vid[2:]])
            line = f"{rid.replace('xccdf_org.ssgproject.content_rule_', '')}: {result}"
            cat = None
            if result == "notapplicable":
                gates = unmet_gates(r, res["true_platforms"])
                cat = classify_na(gates)
                na_cats.add((cat, tuple(gates)))
                if gates:
                    line += f" (platform not met: {', '.join(g.lstrip('#') for g in gates)})"
            # Flag only where an architecture gate decided the outcome: the rule
            # was evaluated past it, or it is the gate that made the rule N/A.
            if not arch_ok and has_arch_gate(r) and (cat is None or cat == "arch"):
                line += f" [architecture gate evaluated on the scanning host ({runner_arch}); target architecture {target_arch or 'unknown'}]"
            details.append(line)
        status = aggregate([(rid, res["results"][rid]) for rid in rids])
        if status == "Not_Applicable" and not arch_ok and any(c == "arch" for c, _ in na_cats):
            status = "Not_Reviewed"
            comments = [f"Not reviewed: this N/A rests on a CPU-architecture check that OpenSCAP evaluated against "
                        f"the scanning host ({runner_arch}), and the target's architecture is "
                        f"{target_arch or 'unknown'}. Verify applicability manually."]
        elif status == "Not_Applicable":
            comments = [justification(c, list(g)) for c, g in sorted(na_cats)]
        head = f"Automated result from OpenSCAP ({len(rids)} SSG rule{'s' if len(rids) > 1 else ''}):"
        return status, head + "\n" + "\n".join(details) + "\n\n" + prov_txt, "\n".join(dict.fromkeys(comments)), ruleids

    vulns = []
    if disa:
        stig = {k: disa[k] for k in ("benchmark_id", "title", "description", "version", "releaseinfo")}
        rel = re.search(r"Release: *(\d+)", disa["releaseinfo"]).group(1)
        stig["filename"] = f"U_{disa['benchmark_id']}_V{disa['version']}R{rel}_Manual-xccdf.xml"
        seen = set()
        for g in disa["groups"]:
            rids = by_vid.get(g["vid"], [])
            seen.add(g["vid"])
            if rids:
                status, detail, comment, ssg_rule_ids = vuln_from_ssg(g["vid"], rids)
                if g["rule_id"] not in ssg_rule_ids:
                    detail += (f"\n\nNote: the scanner content maps this check to {', '.join(sorted(ssg_rule_ids))}; "
                               f"this checklist's STIG release has {g['rule_id']}. Verify the check still applies.")
            else:
                status, detail, comment = "Not_Reviewed", "", "No automated check for this requirement in the scanner content; manual review required."
            vulns.append({**g, "status": status, "finding_details": detail, "comments": comment})
        stig["unmatched_ssg_vids"] = sorted(set(by_vid) - seen)
    else:
        key = res["benchmark_id"].replace("xccdf_org.ssgproject.content_benchmark_", "")
        bid, title = SSG_STIG_IDS.get(key, (key + "_STIG", res["profile_title"]))
        ver, rel = res["disa_version"] or ("0", "0")
        stig = {"benchmark_id": bid, "title": title, "description": res["profile_title"], "version": ver,
                "releaseinfo": f"Release: {rel} Benchmark Date: unknown (derived from {res['benchmark_id']} {res['benchmark_version']})",
                "filename": f"{res['benchmark_id']}-{res['profile_id']}.xml", "unmatched_ssg_vids": []}
        for vid in sorted(by_vid, key=lambda v: int(v[2:])):
            rids = by_vid[vid]
            first = res["rules"][sorted(rids)[0]]
            sev = max((res["rules"][r]["severity"] for r in rids), key=lambda s: {"high": 3, "medium": 2, "low": 1}.get(s, 0))
            status, detail, comment, ssg_rule_ids = vuln_from_ssg(vid, rids)
            vulns.append({
                "vid": vid, "group_title": first["srg"] or "", "rule_id": sorted(ssg_rule_ids)[0], "severity": sev,
                "weight": "10.0", "rule_ver": first["stig_id"] or "", "rule_title": first["title"],
                "discussion": first["description"], "check_content": "Automated OpenSCAP check: " + ", ".join(sorted(rids)),
                "check_ref": "M", "fix_text": "", "ccis": [], "legacy": [], "documentable": "false",
                "status": status, "finding_details": detail, "comments": comment,
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
    a = ap.parse_args()

    # Never leave a previous run's checklist behind for this run to "publish".
    for ext in ("ckl", "cklb"):
        try:
            os.remove(f"{a.out_dir}/{a.stem}.{ext}")
        except FileNotFoundError:
            pass

    res = parse_results(a.results)
    # Gate on the evaluated profile, not on SV references: SSG reuses rules
    # across profiles, so e.g. RHEL 9 CIS L1 selects 160 rules that carry
    # DISA references and would otherwise yield a partial "STIG" checklist.
    if not re.search(r"_profile_stig(_gui)?$", res["profile_id"]):
        print(json.dumps({"outcome": "skipped", "reason": f"profile {res['profile_id']} is not a DISA STIG profile"}))
        return 0
    plan = {}
    if a.plan:
        for line in open(a.plan, encoding="utf-8"):
            k, sep, v = line.rstrip("\n").partition("=")
            if sep:
                plan[k] = v
    disa = parse_disa(a.disa) if a.disa else None
    stig, vulns = build_model(res, disa, plan, a.runner_arch)
    asset = {
        "ROLE": "None", "ASSET_TYPE": "Computing", "MARKING": "CUI", "HOST_NAME": a.host_name,
        "TARGET_COMMENT": "Container image " + (plan.get("image_repo_digests") or plan.get("image") or ""),
        "TECH_AREA": "", "TARGET_KEY": "", "WEB_OR_DATABASE": "false",
    }
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    write_ckl(f"{a.out_dir}/{a.stem}.ckl", asset, stig, vulns)
    write_cklb(f"{a.out_dir}/{a.stem}.cklb", asset, stig, vulns, now)
    counts = collections.Counter(v["status"] for v in vulns)
    na = collections.Counter()
    for v in vulns:
        if v["status"] == "Not_Applicable":
            na[v["comments"].split(":")[0]] += 1
    print(json.dumps({"stig": {k: stig[k] for k in ("benchmark_id", "version", "releaseinfo")},
                      "vulns": len(vulns), "status": counts, "na_by_reason": na,
                      "ssg_vids_not_in_disa": stig["unmatched_ssg_vids"]}, indent=1, default=list))


if __name__ == "__main__":
    sys.exit(main())
