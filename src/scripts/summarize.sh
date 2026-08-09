#!/usr/bin/env bash
# Parse the OpenSCAP results.xml produced by scan.sh, write a
# human-readable summary, apply the optional ignore-list, and
# enforce the optional fail-on-finding gate.

set -euo pipefail

subst() {
    if command -v circleci >/dev/null 2>&1; then
        circleci env subst "$1"
    else
        echo "$1"
    fi
}

OUTPUT_DIR="$(subst "${PARAM_OUTPUT_DIR:-build/stig}")"
IGNORE_FINDINGS="$(subst "${PARAM_IGNORE_FINDINGS:-}")"
FAIL_ON_FINDING="${PARAM_FAIL_ON_FINDING:-false}"

case "${FAIL_ON_FINDING}" in
    true|false) ;;
    *)
        echo "ERROR: fail-on-finding must be 'true' or 'false', got '${FAIL_ON_FINDING}'." >&2
        exit 2 ;;
esac

RESULTS="${OUTPUT_DIR}/results.xml"
SUMMARY="${OUTPUT_DIR}/summary.txt"
PLAN="${OUTPUT_DIR}/scan-plan.env"

if [ ! -f "${RESULTS}" ]; then
    echo "ERROR: ${RESULTS} not found — did the scan step run?" >&2
    exit 2
fi

python3 - "$RESULTS" "$SUMMARY" "${IGNORE_FINDINGS}" "${PLAN}" <<'PY'
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter

results_path, summary_path, ignore_csv, plan_path = sys.argv[1:5]

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

ignores = {normalize(t) for t in ignore_csv.split(",") if t.strip()}

root = ET.parse(results_path).getroot()

titles = {}
severities = {}
rule_idents = {}
rule_aliases = {}
for el in root.iter():
    if local(el.tag) == "Rule":
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
ignored_count = 0
failures = []

for el in root.iter():
    if local(el.tag) != "rule-result":
        continue
    result = child_text(el, "result")
    if not result:
        continue

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
    is_ignored = bool(ignores & matchable)

    if result == "fail" and is_ignored:
        ignored_count += 1
        counts["ignored"] += 1
    else:
        counts[result] += 1

    if result == "fail":
        failures.append({
            "rule_short": short_id(rid),
            "rule_full": rid,
            "severity": sev,
            "idents": [i for i in idents if i],
            "title": titles.get(rid, ""),
            "ignored": is_ignored,
        })

plan = {}
if os.path.isfile(plan_path):
    with open(plan_path, encoding="utf-8") as plan_file:
        for line in plan_file:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                plan[k] = v

primary = ("pass", "fail", "ignored", "notapplicable", "notchecked", "error", "unknown", "notselected", "informational", "fixed")
lines = []
lines.append("STIG scan summary")
lines.append("")
if plan:
    if "image" in plan:
        lines.append(f"  target-image:   {plan['image']}")
    elif "rootfs_path" in plan:
        lines.append(f"  target-rootfs:  {plan['rootfs_path']}")
    lines.append(f"  target-base:    {plan.get('target_base','')}")
    lines.append(f"  scanner:        {plan.get('scanner','')}")
    lines.append(f"  datastream:     {plan.get('datastream','')}")
    lines.append(f"  profile:        {plan.get('profile','')}")
    lines.append("")

lines.append("Rule results:")
for k in primary:
    if counts[k]:
        lines.append(f"  {k:<15} {counts[k]}")

other = sorted((k, v) for k, v in counts.items() if k not in primary)
for k, v in other:
    lines.append(f"  {k:<15} {v}")

actionable_failures = [f for f in failures if not f["ignored"]]

lines.append("")
if not failures:
    lines.append("No failing rules.")
elif not actionable_failures:
    lines.append(f"All {len(failures)} failure(s) are on the ignore list — gate would pass.")
    lines.append("Ignored failures (still recorded for audit):")
    for f in failures:
        lines.append(f"  - {f['rule_short']} ({f['severity']})")
        if f["title"]:
            lines.append(f"      {f['title']}")
else:
    lines.append(f"Failures ({len(actionable_failures)} actionable, {ignored_count} ignored):")
    for f in failures:
        marker = "[IGNORED] " if f["ignored"] else ""
        idents = ", ".join(f["idents"])
        suffix = f"({f['severity']}{', ' + idents if idents else ''})"
        lines.append(f"  - {marker}{f['rule_short']} {suffix}")
        if f["title"]:
            lines.append(f"      {f['title']}")

text = "\n".join(lines) + "\n"
print(text, end="")
with open(summary_path, "w", encoding="utf-8") as fh:
    fh.write(text)

# Stash the actionable count for the gate.
with open(summary_path + ".gate", "w", encoding="utf-8") as fh:
    fh.write(str(len(actionable_failures)))
PY

ACTIONABLE="$(cat "${SUMMARY}.gate" 2>/dev/null || echo 0)"
rm -f "${SUMMARY}.gate"

echo
if [ "${ACTIONABLE}" -gt 0 ] && [ "${FAIL_ON_FINDING}" = "true" ]; then
    echo "==> fail-on-finding=true and ${ACTIONABLE} actionable failure(s) present — failing the build."
    exit 1
fi
echo "==> summarize complete (actionable failures: ${ACTIONABLE}, gate ${FAIL_ON_FINDING})"
