"""Which DISA release does a pinned STIG or Chainguard GPOS SRG profile match?

    fingerprint-stig.py <results.xml> '<DISA manual xccdf glob>' [--allow-unmapped rule[,rule...]]

Takes a results.xml from a scan of one accepted STIG profile, not the
datastream: OpenSCAP's own selection (every rule-result other than
notselected) already resolves profile extends, Rule/Group selected defaults
and requires/conflicts (4 of the RHEL 8/9 stig profile's explicit selects are
deselected by conflicts). Selection doesn't depend on the target, so a scan of
any image with the datastream and profile will do. Run it once per accepted
profile; every run must name the same release.

Exits 0 only when exactly one release contains every selected SV id, every
selected rule without a DISA reference is in --allow-unmapped (the known
helper rules, e.g. enable_authselect on RHEL 8/9), no rule (deselected ones
included) has an unpaired or malformed V-ID/SV reference (the generator drops
those, plan D3, so they would vanish from a checklist labeled verified), and
every selected
rule-result has a Rule definition and every Rule a rule-result. Anything else is
not a verified match.
"""

import argparse
import glob
import hashlib
import os
import re
from pathlib import Path
import io
import sys
import xml.etree.ElementTree as ET

X = "{http://checklists.nist.gov/xccdf/1.2}"
HREF = "https://www.cyber.mil/stigs/srg-stig-tools/"
HREF_VULN = HREF.rstrip("/") + "#vulnerability_id"
RULE = "xccdf_org.ssgproject.content_rule_"
SV_RE = re.compile(r"SV-([0-9]+)r[0-9]+_rule")

ap = argparse.ArgumentParser()
ap.add_argument("results")
ap.add_argument("pattern")
ap.add_argument("--allow-unmapped", default="", help="comma-separated short rule ids known to have no DISA reference")
a = ap.parse_args()

root = ET.parse(a.results).getroot()
trs = list(root.iter(X + "TestResult"))
if len(trs) != 1:
    sys.exit(f"{a.results}: {len(trs)} TestResult elements; pass the results.xml of one scan of the STIG profile")
tr = trs[0]
benches = list(root.iter(X + "Benchmark"))
if len(benches) != 1 or not any(t is tr for t in benches[0].iter(X + "TestResult")):
    sys.exit(f"{a.results}: needs exactly one Benchmark containing its TestResult")
bench = benches[0]
profiles = tr.findall(X + "profile")
if len(profiles) != 1 or not profiles[0].get("idref"):
    sys.exit(f"{a.results}: the TestResult names {len(profiles)} evaluated profiles; expected exactly one")
pid = profiles[0].get("idref")
prof = next(p for p in bench.iter(X + "Profile") if p.get("id") == pid)
if any(len(rr.findall(X + "result")) != 1 for rr in tr.findall(X + "rule-result")):
    sys.exit(f"{a.results}: a rule-result without exactly one result element; not a verifiable results.xml")
sel = {
    rr.get("idref")
    for rr in tr.findall(X + "rule-result")
    if (rr.findtext(X + "result") or "").strip() != "notselected"
}
rule_ids = [r.get("id") for r in bench.iter(X + "Rule")]
if len(set(rule_ids)) != len(rule_ids):
    sys.exit(f"{a.results}: a Rule id is defined more than once; not a verifiable results.xml")
rules = {r.get("id"): r for r in bench.iter(X + "Rule")}
undefined = sorted(rid for rid in sel if rid not in rules)
# And the other way: OpenSCAP writes a rule-result for every Rule, notselected
# included, so a Rule without one means a truncated selection.
unresulted = sorted(set(rules) - {rr.get("idref") for rr in tr.findall(X + "rule-result")})
vendor = bench.get("id") == "xccdf_org.open-scap.sce-community-content_benchmark_all"

def references(rule, href):
    if vendor and href == HREF:
        rid = rule.get("id", "")
        prefix = "xccdf_mil.disa.stig_rule_"
        value = rid[len(prefix):] if rid.startswith(prefix) else ""
        if not SV_RE.fullmatch(value):
            sys.exit("invalid Chainguard GPOS Rule id: " + rid)
        return {value}
    return {(x.text or "").strip() for x in rule.findall(X + "reference") if x.get("href") == href}

svs_of = {
    rid: references(rules[rid], HREF)
    for rid in sel
    if rid in rules
}
svs = set().union(*svs_of.values())
unmapped = sorted(rid.replace(RULE, "") for rid, s in svs_of.items() if not s)
# The generator's pairing (D3): only a whole V-<digits> or
# SV-<digits>r<digits>_rule counts, and with any V-ID reference on a rule, only
# V-n/SV-n pairs of the same number become rows.
# Every rule, deselected ones included: their references drive the
# generator's "deselected" wording.
unpaired = []
for rid in rules:
    refs = references(rules[rid], HREF_VULN)
    rule_svs = references(rules[rid], HREF)
    vids = {v[2:] for v in refs if re.fullmatch(r"V-[0-9]+", v)}
    malformed = sorted(v for v in refs if not re.fullmatch(r"V-[0-9]+", v)) + sorted(
        sv for sv in rule_svs if not SV_RE.fullmatch(sv)
    )
    nums = {SV_RE.fullmatch(sv).group(1) for sv in rule_svs if SV_RE.fullmatch(sv)}
    if malformed or (refs and vids != nums):
        unpaired.append(
            f"{rid.replace(RULE, '')}: V-{sorted(vids - nums)} SV-{sorted(nums - vids)} malformed {malformed}"
        )
allowed = {r.strip() for r in a.allow_unmapped.split(",") if r.strip()}
label = re.search(
    r"V[0-9]+R[0-9]+",
    " ".join("".join(el.itertext()) for tag in ("title", "description") for el in prof.findall(X + tag)),
)
print(
    os.path.basename(a.results),
    pid.split("_profile_")[-1],
    "profile label",
    label.group(0) if label else "?",
    "selected rules",
    len(sel),
    "SV ids",
    len(svs),
    "unmapped",
    unmapped,
)
# What the release table records for this profile: every Rule's selection and
# DISA references, one "rule<TAB>S|N<TAB>SV refs<TAB>V-ID refs" line per Rule
# (the generator's selection_fingerprint()); it rejects a results.xml with
# anything else.
fp_lines = []
for rid in sorted(rules):
    sv_refs = sorted(references(rules[rid], HREF))
    v_refs = sorted(references(rules[rid], HREF_VULN))
    fp_lines.append(f"{rid}\t{'S' if rid in sel else 'N'}\t{' '.join(sv_refs)}\t{' '.join(v_refs)}")
vids = set()
for rid in sel & set(rules):
    nums = {SV_RE.fullmatch(x).group(1) for x in svs_of[rid] if SV_RE.fullmatch(x)}
    refs = references(rules[rid], HREF_VULN)
    (
        vids.update(v for v in refs if re.fullmatch(r"V-[0-9]+", v) and v[2:] in nums)
        if refs
        else vids.update("V-" + n for n in nums)
    )
print("  mapped V-IDs", len(vids))
print("  selection", len(sel & set(rules)), "sha256", hashlib.sha256("\n".join(fp_lines).encode()).hexdigest())
full = []
for f in sorted(glob.glob(a.pattern)):
    droot = ET.parse(f).getroot()
    dns = (
        droot.tag[: droot.tag.index("}") + 1] if droot.tag.startswith("{") else ""
    )  # 1.1 or 1.2, as the generator accepts
    ids = {r.get("id") for r in droot.iter(dns + "Rule")}
    print(
        f"  {os.path.basename(f):50s} DISA rules {len(ids):4d}  SSG SV ids found {len(svs & ids):4d}  revision/unknown {len(svs - ids):4d}  DISA rules with no SSG {len(ids - svs):3d}"
    )
    if svs and svs <= ids:
        full.append(os.path.basename(f))
problems = [f"unpaired V-ID/SV references: {unpaired}"] if unpaired else []
if undefined:
    problems.append(f"{len(undefined)} selected rule-results with no Rule definition: {undefined[:5]}")
if unresulted:
    problems.append(f"{len(unresulted)} Rules with no rule-result: {unresulted[:5]}")
if set(unmapped) - allowed:
    problems.append(f"selected rules without a DISA reference: {sorted(set(unmapped) - allowed)}")
if len(full) != 1:
    problems.append(
        f"{len(full)} releases contain every selected SV id: {full}"
        if full
        else "no release contains every selected SV id"
    )
if problems:
    print("NOT VERIFIED: " + "; ".join(problems))
    sys.exit(1)
# The table entry records this release info verbatim (the checklist's releaseinfo).
m = ET.parse(sorted(f for f in glob.glob(a.pattern) if os.path.basename(f) == full[0])[0]).getroot()
mns = m.tag[: m.tag.index("}") + 1] if m.tag.startswith("{") else ""
print(
    f"MATCH: {full[0]} ({next((''.join(x.itertext()) for x in m.iter(mns + 'plain-text') if x.get('id') == 'release-info'), '?')})"
)

if vendor:
    script = Path(__file__).resolve().parents[1] / "src/scripts/checklist.sh"
    code = script.read_text().split("<<'PY_CHECKLIST'\n", 1)[1].split("\nPY_CHECKLIST\n", 1)[0]
    gen = {"__name__": "fingerprint"}
    exec(compile(code, str(script), "exec"), gen)
    res = gen["parse_results"](io.BytesIO(Path(a.results).read_bytes()))
    print("  vendor evidence sha256", gen["vendor_evidence_fingerprint"](res))
    print("  DISA XCCDF sha256", hashlib.sha256(Path(sorted(f for f in glob.glob(a.pattern) if os.path.basename(f) == full[0])[0]).read_bytes()).hexdigest())
