#!/bin/bash
# Parse the OpenSCAP results.xml produced by scan.sh, write a
# human-readable summary and a machine-readable provenance.json, apply the
# optional ignore-list, and enforce two independent gates:
#
#   * fail_on_finding — non-ignored fail, error, and unknown results.
#   * require_evaluated_rules — at least one rule evaluated to pass,
#     fail, fixed, or informational. An all-notapplicable scan usually
#     means mis-dispatch (wrong target_base, a scanner missing the probe
#     family the datastream needs, an unreadable package DB). It is not
#     evidence of compliance and fails closed unless the caller opts out.

set -euo pipefail

subst() {
    if command -v circleci >/dev/null 2>&1; then
        printf '%s' "$1" | circleci env subst
    else
        printf '%s\n' "$1"
    fi
}

# CircleCI serializes boolean orb parameters as 1/0 in run-step
# environments, while direct/local callers naturally use true/false.
# `exit` inside $(...) would only leave the subshell, so signal failure
# with a return and let the caller abort the script.
normalize_bool() {
    local name="$1"
    local value="$2"
    case "${value}" in
        true|1) printf 'true' ;;
        false|0) printf 'false' ;;
        *)
            echo "ERROR: ${name} must be 'true', 'false', '1', or '0'; got '${value}'." >&2
            return 2 ;;
    esac
}

OUTPUT_DIR="$(subst "${PARAM_OUTPUT_DIR:-build/stig}")"
CHECKLIST="$(subst "${PARAM_CHECKLIST:-none}")"
case "${CHECKLIST}" in
    auto|require|none) ;;
    *) echo "ERROR: checklist must be auto, require, or none." >&2; exit 2 ;;
esac
IGNORE_FINDINGS="$(subst "${PARAM_IGNORE_FINDINGS:-}")"
if ! FAIL_ON_FINDING="$(normalize_bool "fail_on_finding" "${PARAM_FAIL_ON_FINDING:-false}")"; then
    exit 2
fi
if ! REQUIRE_EVALUATED_RULES="$(normalize_bool "require_evaluated_rules" "${PARAM_REQUIRE_EVALUATED_RULES:-true}")"; then
    exit 2
fi
if ! DEFER_GATE="$(normalize_bool "defer_gate" "${PARAM_DEFER_GATE:-false}")"; then
    exit 2
fi

RESULTS="${OUTPUT_DIR}/results.xml"
SUMMARY="${OUTPUT_DIR}/summary.txt"
PLAN="${OUTPUT_DIR}/scan-plan.env"
PROVENANCE="${OUTPUT_DIR}/provenance.json"
if [ "${DEFER_GATE}" = "true" ]; then
    # A retry that fails before deciding policy cannot reuse an old verdict.
    rm -f -- "${SUMMARY}.exit-code"
fi

if [ ! -f "${RESULTS}" ]; then
    echo "ERROR: ${RESULTS} not found — did the scan step run?" >&2
    exit 2
fi

# The Python block hands its gate counts to the shell in a private file,
# never at a fixed name in output_dir.
GATE_FILE="$(mktemp -t stig-gate.XXXXXX)"
trap 'rm -f -- "${GATE_FILE}"' EXIT

python3 - "$RESULTS" "$SUMMARY" "${IGNORE_FINDINGS}" "${PLAN}" \
    "${FAIL_ON_FINDING}" "${REQUIRE_EVALUATED_RULES}" "${PROVENANCE}" "${CHECKLIST}" "${GATE_FILE}" <<'PY'
import hashlib
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter

results_path, summary_path, ignore_csv, plan_path, fail_on_finding, require_evaluated, provenance_path = sys.argv[1:8]
checklist_mode = sys.argv[8]
gate_path = sys.argv[9]

def local(tag):
    return tag.rsplit("}", 1)[-1]

def child_text(el, name):
    for c in el:
        if local(c.tag) == name:
            return " ".join(" ".join(c.itertext()).split())
    return ""

def short_id(rule_id):
    m = re.search(r"(SV-\d+r\d+)", rule_id)
    if m:
        return m.group(1)
    return rule_id.split("content_rule_")[-1] if "content_rule_" in rule_id else rule_id

def normalize(token):
    return token.strip().lower()

# fail / fixed / informational mean a check ran. error and unknown did
# not produce a compliance answer; notapplicable and notchecked did not
# either. Ignored fails still count as evaluated: a triaged baseline is
# not the same thing as a scan that never applied.
EVALUATED_RESULTS = {"pass", "fail", "fixed", "informational"}
GATED_RESULTS = ("fail", "error", "unknown")

ignores = {normalize(t) for t in ignore_csv.split(",") if t.strip()}

with open(results_path, "rb") as fh:
    results_bytes = fh.read()
results_sha = hashlib.sha256(results_bytes).hexdigest()
root = ET.fromstring(results_bytes)

titles = {}
severities = {}
rule_idents = {}
rule_aliases = {}
for el in root.iter():
    if local(el.tag) != "Rule":
        continue
    rid = el.get("id", "")
    if not rid:
        continue
    titles[rid] = child_text(el, "title")
    sev = el.get("severity")
    if sev:
        severities[rid] = sev
    # Harvest <ident> AND <reference> children from the Rule
    # definition. CCEs live in <ident>; SV-* DISA STIG IDs and
    # NIST / STIG-group / SRG / RHEL-* identifiers live in
    # <reference> alongside their authority URLs. An ignore-list
    # entry that uses any of these would silently miss if we only
    # looked at <ident> on <rule-result>.
    idents_for_rule = []
    aliases_for_rule = []
    for c in el:
        tag = local(c.tag)
        if tag not in ("ident", "reference"):
            continue
        text = " ".join(" ".join(c.itertext()).split())
        if not text:
            continue
        if tag == "ident":
            idents_for_rule.append(text)
        else:
            aliases_for_rule.append(text)
        # Normalize SV-XXrYY out of values like
        # "SV-258134r1155620_rule" so a user can ignore by the short
        # DISA id either with or without the _rule suffix.
        m = re.search(r"(SV-\d+r\d+)", text)
        if m:
            aliases_for_rule.append(m.group(1))
    if idents_for_rule:
        rule_idents[rid] = idents_for_rule
    if aliases_for_rule:
        rule_aliases[rid] = aliases_for_rule

counts = Counter()
gated = {name: [] for name in GATED_RESULTS}
notchecked_rules = []
evaluated = 0
rule_results = 0

for el in root.iter():
    if local(el.tag) != "rule-result":
        continue
    result = child_text(el, "result")
    if not result:
        continue

    rule_results += 1
    if result in EVALUATED_RESULTS:
        evaluated += 1

    rid = el.get("idref", "")
    sev = el.get("severity") or severities.get(rid, "unknown")
    # Union idents from the rule-result (where some scanners replicate
    # them) AND from the Rule definition keyed by idref (the canonical
    # location for CCE / CCI / SV identifiers in OpenSCAP output).
    idents = list(rule_idents.get(rid, []))
    seen = set(idents)
    for c in el:
        if local(c.tag) == "ident":
            text = " ".join(" ".join(c.itertext()).split())
            if text and text not in seen:
                idents.append(text)
                seen.add(text)

    matchable = {normalize(short_id(rid)), normalize(rid)}
    matchable.update(normalize(i) for i in idents)
    matchable.update(normalize(a) for a in rule_aliases.get(rid, []))
    is_ignored = bool(result in GATED_RESULTS and (ignores & matchable))

    if is_ignored:
        counts["ignored"] += 1
    else:
        counts[result] += 1

    record = {
        "result": result,
        "rule_short": short_id(rid),
        "rule_full": rid,
        "severity": sev,
        "idents": [i for i in idents if i],
        "title": titles.get(rid, ""),
        "ignored": is_ignored,
    }
    if result in GATED_RESULTS:
        gated[result].append(record)
    elif result == "notchecked":
        notchecked_rules.append(record)

plan = {}
duplicate_plan_keys = set()
if os.path.isfile(plan_path):
    with open(plan_path, encoding="utf-8") as plan_file:
        for line in plan_file:
            k, sep, v = line.rstrip("\n").partition("=")
            if sep:
                if k in plan:
                    duplicate_plan_keys.add(k)
                plan[k] = v

actionable = [rec for name in GATED_RESULTS for rec in gated[name] if not rec["ignored"]]
hollow = rule_results > 0 and evaluated == 0

# --- provenance: scan-plan.env (what ran) + results.xml (what it read) ---
def csv_list(value):
    return [v for v in (value or "").split(",") if v]

def opt(value):
    return value if value else None

bench_version = bench_update = None
for c in root:
    if local(c.tag) == "version":
        bench_version = (c.text or "").strip() or None
        bench_update = c.get("update")
        break
test_result = next((el for el in root.iter() if local(el.tag) == "TestResult"), None)
openscap_version = start_time = end_time = None
profile_id = plan.get("profile") or None
if test_result is not None:
    system = test_result.get("test-system", "")
    if system.startswith("cpe:/a:redhat:openscap:"):
        openscap_version = system.rsplit(":", 1)[-1] or None
    start_time = test_result.get("start-time")
    end_time = test_result.get("end-time")
    for c in test_result:
        if local(c.tag) == "profile" and c.get("idref"):
            profile_id = c.get("idref")
profile_title = None
for el in root.iter():
    if local(el.tag) == "Profile" and el.get("id") == profile_id:
        profile_title = child_text(el, "title") or None
        break
# External and shadowing profiles take their identity from the scan's exact,
# hash-bound tailoring snapshot, never a same-named stock Profile definition.
tailoring_keys = ("tailoring_file", "tailoring_sha256", "tailoring_profile", "tailoring_meta_sha256", "tailoring_evaluated_sha256")
if any(plan.get(key) for key in tailoring_keys):
    # Stock standalone summaries retain legacy appended-field behavior.
    # Hash-bound tailoring identity requires one unambiguous scan plan.
    if duplicate_plan_keys:
        raise ValueError("the scan plan repeats " + ", ".join(sorted(duplicate_plan_keys)))
    if not all(plan.get(key) for key in tailoring_keys):
        raise ValueError("the scan plan has incomplete tailoring provenance")
    if plan.get("results_sha256") != results_sha:
        raise ValueError("tailored results hash differs from the scan plan")
    for key in ("tailoring_sha256", "tailoring_meta_sha256", "tailoring_evaluated_sha256", "datastream_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", plan.get(key, "")):
            raise ValueError("invalid or missing tailoring provenance hash: " + key)
    with open(os.path.join(os.path.dirname(plan_path), "tailoring-meta.json"), "rb") as fh:
        tailoring_raw = fh.read((16 << 20) + 1)
    if len(tailoring_raw) > 16 << 20 or hashlib.sha256(tailoring_raw).hexdigest() != plan.get("tailoring_meta_sha256"):
        raise ValueError("tailoring metadata hash/size differs from the scan plan")
    def unique_tailoring(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("tailoring metadata repeats " + key)
            result[key] = value
        return result
    tailoring_identity = json.loads(tailoring_raw, object_pairs_hook=unique_tailoring)
    if (not isinstance(tailoring_identity, dict) or tailoring_identity.get("schema") != "stig-scanner-orb/tailoring/v1"
            or tailoring_identity.get("profile_id") != profile_id
            or profile_id != plan.get("tailoring_profile")
            or profile_id != plan.get("profile")
            or tailoring_identity.get("sha256") != plan.get("tailoring_sha256")
            or tailoring_identity.get("evaluated_sha256") != plan.get("tailoring_evaluated_sha256")
            or tailoring_identity.get("datastream_sha256") != plan.get("datastream_sha256")
            or not isinstance(tailoring_identity.get("profile_title"), str)
            or not tailoring_identity["profile_title"]):
        raise ValueError("tailoring metadata identity differs from the scan plan/results")
    profile_title = tailoring_identity["profile_title"]
# Only ComplianceAsCode-built benchmarks carry an SSG release number; the
# Wolfi GPOS datastream, for one, is not SSG content.
ssg_version = bench_version if bench_update and "ComplianceAsCode" in bench_update else None

donor = None
if plan.get("donor_used_for"):
    donor = {
        "image": plan.get("donor_image"),
        "image_id": opt(plan.get("donor_image_id")),
        "repo_digests": csv_list(plan.get("donor_repo_digests")),
        "platform": opt(plan.get("donor_platform")),
        "used_for": csv_list(plan.get("donor_used_for")),
    }
provenance = {
    "schema": "stig-scanner-orb/provenance/v1",
    "target": {
        "image": opt(plan.get("image")),
        "image_id": opt(plan.get("image_id")),
        "repo_digests": csv_list(plan.get("image_repo_digests")),
        "platform": opt(plan.get("image_platform")),
        "rootfs_path": opt(plan.get("rootfs_path")),
        # Distroless dpkg layout: "synthesized" (status file built from
        # status.d/ in the scratch copy) or "missing" (not built, for the
        # recorded reason; dpkg probes can't see packages).
        "dpkg_status": {
            "state": plan["dpkg_status"],
            "packages": int(plan["dpkg_status_packages"]) if plan.get("dpkg_status_packages", "").isdigit() else None,
            "source": plan.get("dpkg_status_source", "/var/lib/dpkg/status.d") or None,
            "reason": plan.get("dpkg_status_reason") or None,
        } if plan.get("dpkg_status") else None,
        "rpm_status": {
            "state": plan["rpm_status"],
            "packages": int(plan["rpm_status_packages"]) if plan.get("rpm_status_packages", "").isdigit() else None,
            "reason": plan.get("rpm_status_reason") or None,
        } if plan.get("rpm_status") else None,
    },
    "target_base": {
        "requested": opt(plan.get("target_base_requested")),
        "resolved": opt(plan.get("target_base")),
        "resolved_from": opt(plan.get("target_base_source")),
    },
    "profile": {"id": profile_id, "title": profile_title},
    "tailoring": {
        "path": plan.get("tailoring_file"),
        "sha256": plan.get("tailoring_sha256"),
        "profile_id": plan.get("tailoring_profile"),
        "profile_title": profile_title,
        "metadata_sha256": plan.get("tailoring_meta_sha256"),
        "evaluated_sha256": plan.get("tailoring_evaluated_sha256"),
    } if plan.get("tailoring_file") else None,
    "scanner": {
        "image": opt(plan.get("scanner")),
        "image_id": opt(plan.get("scanner_image_id")),
        "repo_digests": csv_list(plan.get("scanner_repo_digests")),
        "platform": opt(plan.get("scanner_platform")),
        "openscap_version": openscap_version,
    },
    "donor": donor,
    "datastream": {
        "name": opt(plan.get("datastream")),
        "source": opt(plan.get("datastream_source")),
        "sha256": opt(plan.get("datastream_sha256")),
        "benchmark_id": root.get("id") if local(root.tag) == "Benchmark" else None,
        "benchmark_version": bench_version,
        "ssg_version": ssg_version,
    },
    "scan": {"start_time": start_time, "end_time": end_time},
}

# A generated meta vouches for exactly this results.xml and every listed file.
# A stale or malformed meta never suppresses the ordinary scan summary.
checklist = None
checklist_failed = False
try:
    with open(os.path.join(os.path.dirname(results_path), "checklist-meta.json"), encoding="utf-8") as fh:
        meta = json.loads(fh.read((1 << 20) + 1))
    if not isinstance(meta, dict) or meta.get("results_sha256") != results_sha:
        raise ValueError("checklist meta is invalid or belongs to another results.xml")
    if meta.get("outcome") not in ("generated", "skipped", "failed"):
        raise ValueError("checklist meta has no valid outcome")
    checklist = meta
    if meta["outcome"] == "generated":
        formats = meta.get("formats")
        if not isinstance(formats, dict) or not formats or set(formats) - {"ckl", "cklb"}:
            raise ValueError("generated checklist meta has no valid formats")
        for ext, expected in formats.items():
            path = os.path.join(os.path.dirname(results_path), "checklist." + ext)
            if os.path.islink(path) or not os.path.isfile(path):
                raise ValueError(f"checklist.{ext} is missing or is not a regular file")
            with open(path, "rb") as fh:
                digest = hashlib.file_digest(fh, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else hashlib.sha256(fh.read()).hexdigest()
            if digest != expected:
                raise ValueError(f"checklist.{ext} does not match its recorded sha256")
except (OSError, ValueError, TypeError) as exc:
    # none reports matching meta only, preserving command-only callers.
    if checklist_mode != "none" or checklist is not None:
        checklist = {"outcome": "failed", "reason": str(exc), "results_sha256": results_sha}
if checklist_mode != "none":
    checklist_failed = checklist is None or checklist["outcome"] == "failed" or (
        checklist_mode == "require" and checklist["outcome"] != "generated")
provenance["checklist"] = checklist
provenance["scan"]["results_sha256"] = results_sha

lines = ["STIG scan summary", ""]
if checklist is not None:
    lines.append("Checklist:")
    lines.append(f"  mode: {checklist_mode}")
    lines.append(f"  outcome: {checklist['outcome']}")
    if checklist.get("reason"):
        lines.append(f"  reason: {checklist['reason']}")
    if checklist.get("outcome") == "generated":
        for key in ("host_name", "content_kind", "vendor_reference", "release_source", "bundle", "revision_drift", "skeleton_completeness", "skeleton_sha256", "skeleton_source_sha256", "skeleton_path", "skeleton_member", "unmatched_ssg_vids", "stig", "formats", "vulns", "status", "answers", "na_by_reason", "not_reviewed_by_reason", "unpaired_refs"):
            lines.append(f"  {key}: {json.dumps(checklist.get(key), sort_keys=True)}")
        if checklist.get("skeleton_completeness") == "internal":
            lines.append("  warning: unknown DISA release; skeleton completeness establishes self-consistency only. Compare its source hash with DISA's published file.")
        drift = checklist.get("revision_drift", {})
        if drift:
            lines.append(f"  revision comparison: {drift.get('unchanged_check', 0)} row(s) have unchanged check text; "
                         f"{drift.get('check_changed', 0)} have changed checks; "
                         f"{drift.get('unverified_revision', 0)} cannot be verified.")
        mismatches = checklist.get("not_reviewed_by_reason", {}).get("revision_mismatch", 0)
        if mismatches:
            lines.append(f"  warning: {mismatches} row(s) use a different Rule ID revision; automated evidence is retained, but their verdict is Not_Reviewed.")
    if checklist_failed:
        lines.append("  checklist policy failed — failing the build.")
    lines.append("")
if plan:
    if "image" in plan:
        lines.append(f"  target-image:   {plan['image']}")
    elif "rootfs_path" in plan:
        lines.append(f"  target-rootfs:  {plan['rootfs_path']}")
    lines.append(f"  target-base:    {plan.get('target_base', '')}")
    lines.append(f"  scanner:        {plan.get('scanner', '')}")
    lines.append(f"  datastream:     {plan.get('datastream', '')}")
    lines.append(f"  profile:        {plan.get('profile', '')}")
    lines.append("")

def digest_line(digests, image_id, fallback, platform=None):
    if digests:
        line = ", ".join(digests)
    else:
        line = f"{fallback} (image id {image_id})" if image_id else fallback
    # A multi-platform index digest names every platform at once; the
    # platform says which of its manifests ran.
    return f"{line} [{platform}]" if platform else line

if plan:
    t, sc, ds, tb = provenance["target"], provenance["scanner"], provenance["datastream"], provenance["target_base"]
    lines.append("Provenance:")
    if t["image"]:
        lines.append(f"  target-digest:     {digest_line(t['repo_digests'], t['image_id'], 'none, not pulled from a registry', t['platform'])}")
    lines.append(f"  target-base:       {tb['resolved'] or ''} (requested {tb['requested'] or ''}, from {tb['resolved_from'] or ''})")
    lines.append(f"  scanner-digest:    {digest_line(sc['repo_digests'], sc['image_id'], 'none', sc['platform'])}")
    lines.append(f"  openscap:          {sc['openscap_version'] or 'unknown'}")
    if donor:
        lines.append(f"  donor-digest:      {digest_line(donor['repo_digests'], donor['image_id'], 'none', donor['platform'])} (used for {', '.join(donor['used_for'])})")
    if t["dpkg_status"] and t["dpkg_status"]["state"] == "synthesized":
        lines.append(f"  dpkg-status:       synthesized from /var/lib/dpkg/status.d ({t['dpkg_status']['packages']} packages) in the scratch rootfs copy")
    if provenance["tailoring"]:
        tailoring = provenance["tailoring"]
        lines.append(f"  tailoring-file:    {tailoring['path']}")
        lines.append(f"  tailoring-sha256:  {tailoring['sha256']}")
        lines.append(f"  tailoring-eval-sha256: {tailoring['evaluated_sha256']}")
        lines.append(f"  tailored-profile:  {tailoring['profile_id']}")
    lines.append(f"  datastream-source: {ds['source'] or ''}")
    lines.append(f"  datastream-sha256: {ds['sha256'] or 'unavailable'}")
    bench = f"{ds['benchmark_id'] or 'unknown'} {ds['benchmark_version'] or ''}".rstrip()
    lines.append(f"  benchmark:         {bench}")
    lines.append(f"  ssg-version:       {ds['ssg_version'] or 'n/a (not ComplianceAsCode content)'}")
    if profile_title:
        lines.append(f"  profile-title:     {profile_title}")
    lines.append(f"  scan-time:         {start_time or ''} .. {end_time or ''}")
    lines.append("")

lines.append(f"  fail-on-finding: {fail_on_finding}")
lines.append(f"  require-evaluated-rules: {require_evaluated}")
lines.append("")
lines.append(f"Evaluated rules: {evaluated}")

if provenance["target"]["dpkg_status"] and provenance["target"]["dpkg_status"]["state"] == "missing":
    reason = provenance["target"]["dpkg_status"]["reason"]
    lines.append("")
    lines.append(
        "WARNING: the target has no usable /var/lib/dpkg/status"
        + (f" ({reason})" if reason else "")
        + ". OpenSCAP's dpkg probe reads only the status file, so package rules "
        "may error or evaluate false; package absence cannot be verified. See README, "
        "Distroless images."
    )

if provenance["target"]["rpm_status"]:
    inventory = provenance["target"]["rpm_status"]
    lines.append("")
    if inventory["state"] == "missing":
        lines.append(
            "WARNING: RPM inventory is unavailable"
            + (f" ({inventory['reason']})" if inventory["reason"] else "")
            + "; package absence and applicability cannot be verified."
        )
    else:
        lines.append(f"RPM inventory: {inventory['state']} ({inventory['packages']} packages)")

if rule_results == 0:
    lines.append("")
    lines.append("ERROR: results.xml contains no rule-result elements.")
elif hollow:
    lines.append("")
    lines.append(
        "WARNING: hollow scan — 0 rules evaluated to pass or fail. "
        "This result is not evidence of compliance."
    )
    if require_evaluated == "true":
        lines.append("require_evaluated_rules=true — failing the build.")
    else:
        lines.append(
            "require_evaluated_rules=false — this job is allowed to pass, "
            "and it is still not evidence of compliance."
        )

ungated_errors = [rec for rec in gated["error"] if not rec["ignored"]]
ungated_unknown = [rec for rec in gated["unknown"] if not rec["ignored"]]
if ungated_errors or ungated_unknown:
    lines.append("")
    if fail_on_finding == "true":
        lines.append(
            f"WARNING: {len(ungated_errors)} error and {len(ungated_unknown)} unknown "
            "result(s) count toward fail_on_finding."
        )
    else:
        lines.append(
            f"WARNING: {len(ungated_errors)} error and {len(ungated_unknown)} unknown "
            "result(s) are present. fail_on_finding=false, so they do not fail the job."
        )

lines.append("")
lines.append("Rule results:")
always = ("pass", "fail", "error", "unknown", "notapplicable", "notchecked")
for k in always:
    lines.append(f"  {k:<15} {counts[k]}")
for k in ("ignored", "notselected", "informational", "fixed"):
    if counts[k]:
        lines.append(f"  {k:<15} {counts[k]}")
shown = set(always) | {"ignored", "notselected", "informational", "fixed"}
for k, v in sorted((k, v) for k, v in counts.items() if k not in shown):
    lines.append(f"  {k:<15} {v}")

def render_group(title, rows):
    if not rows:
        return
    actionable_n = sum(1 for rec in rows if not rec["ignored"])
    ignored_n = sum(1 for rec in rows if rec["ignored"])
    lines.append("")
    lines.append(f"{title} ({actionable_n} actionable, {ignored_n} ignored):")
    for rec in rows:
        marker = "[IGNORED] " if rec["ignored"] else ""
        idents = ", ".join(rec["idents"])
        suffix = f"({rec['severity']}{', ' + idents if idents else ''})"
        lines.append(f"  - {marker}{rec['rule_short']} {suffix}")
        if rec["title"]:
            lines.append(f"      {rec['title']}")

if not any(gated.values()):
    lines.append("")
    lines.append("No fail, error, or unknown results.")
else:
    render_group("Fail", gated["fail"])
    render_group("Error", gated["error"])
    render_group("Unknown", gated["unknown"])

if notchecked_rules:
    lines.append("")
    lines.append(
        f"Notchecked ({len(notchecked_rules)}): no automated result. "
        "fail_on_finding does not count these. A scan whose rules never "
        "reach pass or fail still fails when require_evaluated_rules=true."
    )
    for rec in notchecked_rules:
        lines.append(f"  - {rec['rule_short']} ({rec['severity']})")
        if rec["title"]:
            lines.append(f"      {rec['title']}")

text = "\n".join(lines) + "\n"
print(text, end="")
with open(summary_path, "w", encoding="utf-8") as fh:
    fh.write(text)
with open(provenance_path, "w", encoding="utf-8") as fh:
    json.dump(provenance, fh, indent=2)
    fh.write("\n")

# The shell enforces the exit code from these counts so the policy lives
# in one place. Missing file is a hard error, not a pass.
with open(gate_path, "w", encoding="utf-8") as fh:
    fh.write(f"actionable={len(actionable)}\n")
    fh.write(f"evaluated={evaluated}\n")
    fh.write(f"rule_results={rule_results}\n")
    fh.write(f"checklist_failed={int(checklist_failed)}\n")
PY

if [ ! -s "${GATE_FILE}" ]; then
    echo "ERROR: summarize did not produce a gate file." >&2
    exit 2
fi

ACTIONABLE=""
EVALUATED=""
RULE_RESULTS=""
CHECKLIST_FAILED=""
while IFS='=' read -r key value; do
    case "${key}" in
        actionable) ACTIONABLE="${value}" ;;
        evaluated) EVALUATED="${value}" ;;
        rule_results) RULE_RESULTS="${value}" ;;
        checklist_failed) CHECKLIST_FAILED="${value}" ;;
    esac
done < "${GATE_FILE}"

for pair in "actionable:${ACTIONABLE}" "evaluated:${EVALUATED}" "rule_results:${RULE_RESULTS}" "checklist_failed:${CHECKLIST_FAILED}"; do
    name="${pair%%:*}"
    value="${pair#*:}"
    case "${value}" in
        ''|*[!0-9]*)
            echo "ERROR: gate file ${name} is not an integer: '${value}'." >&2
            exit 2 ;;
    esac
done

echo
if [ "${RULE_RESULTS}" -eq 0 ]; then
    echo "ERROR: results.xml contains no rule-result elements." >&2
    exit 2
fi

failed=0
if [ "${CHECKLIST_FAILED}" -ne 0 ]; then
    echo "ERROR: checklist=${CHECKLIST} policy failed; see Checklist in summary.txt." >&2
    failed=1
fi
if [ "${EVALUATED}" -eq 0 ] && [ "${REQUIRE_EVALUATED_RULES}" = "true" ]; then
    echo "ERROR: require_evaluated_rules=true and 0 rules evaluated to pass or fail — failing the build." >&2
    echo "       That is not evidence of compliance. It usually means the scan was" >&2
    echo "       mis-dispatched: check target_base, the scanner image (RPM targets need" >&2
    echo "       rpm probes), and that the target's package database is readable." >&2
    echo "       If this profile genuinely has no rule that applies to this image, set" >&2
    echo "       require_evaluated_rules=false on this job to record the baseline on purpose." >&2
    failed=1
fi
if [ "${ACTIONABLE}" -gt 0 ] && [ "${FAIL_ON_FINDING}" = "true" ]; then
    echo "ERROR: fail_on_finding=true and ${ACTIONABLE} actionable result(s) (fail, error, or unknown) — failing the build." >&2
    failed=1
fi
if [ "${failed}" -ne 0 ]; then
    if [ "${DEFER_GATE}" = "true" ]; then
        (set -o noclobber; printf '1\n' > "${SUMMARY}.exit-code")
        echo "==> Policy failure recorded; the scan job enforces it after artifact upload."
        exit 0
    fi
    exit 1
fi
if [ "${DEFER_GATE}" = "true" ]; then
    (set -o noclobber; printf '0\n' > "${SUMMARY}.exit-code")
fi
echo "==> summarize complete (actionable: ${ACTIONABLE}, evaluated: ${EVALUATED}, fail_on_finding=${FAIL_ON_FINDING}, require_evaluated_rules=${REQUIRE_EVALUATED_RULES})"
