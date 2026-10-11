#!/usr/bin/env bash
# Parse the OpenSCAP results.xml produced by scan.sh, write a
# human-readable summary, apply the optional ignore-list, and enforce
# two independent gates:
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
        circleci env subst "$1"
    else
        echo "$1"
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
IGNORE_FINDINGS="$(subst "${PARAM_IGNORE_FINDINGS:-}")"
if ! FAIL_ON_FINDING="$(normalize_bool "fail-on-finding" "${PARAM_FAIL_ON_FINDING:-false}")"; then
    exit 2
fi
if ! REQUIRE_EVALUATED_RULES="$(normalize_bool "require-evaluated-rules" "${PARAM_REQUIRE_EVALUATED_RULES:-true}")"; then
    exit 2
fi

RESULTS="${OUTPUT_DIR}/results.xml"
SUMMARY="${OUTPUT_DIR}/summary.txt"
PLAN="${OUTPUT_DIR}/scan-plan.env"

if [ ! -f "${RESULTS}" ]; then
    echo "ERROR: ${RESULTS} not found — did the scan step run?" >&2
    exit 2
fi

python3 - "$RESULTS" "$SUMMARY" "${IGNORE_FINDINGS}" "${PLAN}" \
    "${FAIL_ON_FINDING}" "${REQUIRE_EVALUATED_RULES}" <<'PY'
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter

results_path, summary_path, ignore_csv, plan_path, fail_on_finding, require_evaluated = sys.argv[1:7]

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

root = ET.parse(results_path).getroot()

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
if os.path.isfile(plan_path):
    with open(plan_path, encoding="utf-8") as plan_file:
        for line in plan_file:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                plan[k] = v

actionable = [rec for name in GATED_RESULTS for rec in gated[name] if not rec["ignored"]]
hollow = rule_results > 0 and evaluated == 0

lines = ["STIG scan summary", ""]
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

lines.append(f"  fail-on-finding: {fail_on_finding}")
lines.append(f"  require-evaluated-rules: {require_evaluated}")
lines.append("")
lines.append(f"Evaluated rules: {evaluated}")

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

# The shell enforces the exit code from these counts so the policy lives
# in one place. Missing file is a hard error, not a pass.
with open(summary_path + ".gate", "w", encoding="utf-8") as fh:
    fh.write(f"actionable={len(actionable)}\n")
    fh.write(f"evaluated={evaluated}\n")
    fh.write(f"rule_results={rule_results}\n")
PY

GATE_FILE="${SUMMARY}.gate"
if [ ! -f "${GATE_FILE}" ]; then
    echo "ERROR: summarize did not produce a gate file." >&2
    exit 2
fi

ACTIONABLE=""
EVALUATED=""
RULE_RESULTS=""
while IFS='=' read -r key value; do
    case "${key}" in
        actionable) ACTIONABLE="${value}" ;;
        evaluated) EVALUATED="${value}" ;;
        rule_results) RULE_RESULTS="${value}" ;;
    esac
done < "${GATE_FILE}"
rm -f "${GATE_FILE}"

for pair in "actionable:${ACTIONABLE}" "evaluated:${EVALUATED}" "rule_results:${RULE_RESULTS}"; do
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
if [ "${EVALUATED}" -eq 0 ] && [ "${REQUIRE_EVALUATED_RULES}" = "true" ]; then
    echo "==> require_evaluated_rules=true and 0 rules evaluated to pass or fail — failing the build."
    echo "    That is not evidence of compliance. It usually means the scan was"
    echo "    mis-dispatched: check target_base, the scanner image (RPM targets need"
    echo "    rpm probes), and that the target's package database is readable."
    echo "    If this profile genuinely has no rule that applies to this image, set"
    echo "    require_evaluated_rules=false on this job to record the baseline on purpose."
    failed=1
fi
if [ "${ACTIONABLE}" -gt 0 ] && [ "${FAIL_ON_FINDING}" = "true" ]; then
    echo "==> fail-on-finding=true and ${ACTIONABLE} actionable result(s) (fail, error, or unknown) — failing the build."
    failed=1
fi
if [ "${failed}" -ne 0 ]; then
    exit 1
fi
echo "==> summarize complete (actionable: ${ACTIONABLE}, evaluated: ${EVALUATED}, fail-on-finding ${FAIL_ON_FINDING}, require-evaluated-rules ${REQUIRE_EVALUATED_RULES})"
