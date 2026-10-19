#!/usr/bin/env bash
# Fixture tests for summarize.sh gates. No docker, no scanner images.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUMMARIZE="${ROOT}/src/scripts/summarize.sh"
failures=0

fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

# run_case NAME EXPECTED_RC
# Remaining args are env assignments KEY=VALUE. results.xml is stdin.
run_case() {
    local name="$1"
    local expected="$2"
    shift 2
    local dir rc
    dir="$(mktemp -d)"
    cat > "${dir}/results.xml"
    set +e
    (
        cd "${dir}"
        export PARAM_OUTPUT_DIR="${dir}"
        export PARAM_FAIL_ON="${PARAM_FAIL_ON-never}"
        export PARAM_FAIL_ON_SCAN_ERROR="${PARAM_FAIL_ON_SCAN_ERROR-true}"
        export PARAM_REQUIRE_EVALUATED_RULES="${PARAM_REQUIRE_EVALUATED_RULES-true}"
        export PARAM_IGNORE_FINDINGS="${PARAM_IGNORE_FINDINGS-}"
        # shellcheck disable=SC2086
        env "$@" bash "${SUMMARIZE}" > "${dir}/stdout.txt" 2> "${dir}/stderr.txt"
    )
    rc=$?
    set -e
    if [ "${rc}" -ne "${expected}" ]; then
        fail "${name}: expected exit ${expected}, got ${rc}"
        echo "----- stdout -----" >&2
        cat "${dir}/stdout.txt" >&2 || true
        echo "----- stderr -----" >&2
        cat "${dir}/stderr.txt" >&2 || true
    fi
    # Expose the latest summary to assertions via a global path.
    LAST_DIR="${dir}"
}

assert_grep() {
    local name="$1"
    local pattern="$2"
    if ! grep -q "${pattern}" "${LAST_DIR}/summary.txt"; then
        fail "${name}: summary missing /${pattern}/"
        cat "${LAST_DIR}/summary.txt" >&2 || true
    fi
}

# assert_log NAME STREAM TEXT: the latest run's stdout or stderr contains TEXT.
# Messages name parameters exactly as the YAML does, never hyphenated.
assert_log() {
    local name="$1"
    local stream="$2"
    local text="$3"
    if ! grep -qF -- "${text}" "${LAST_DIR}/${stream}.txt"; then
        fail "${name}: ${stream} missing '${text}'"
        cat "${LAST_DIR}/${stream}.txt" >&2 || true
    fi
}

assert_not_grep() {
    local name="$1"
    local pattern="$2"
    if [ -f "${LAST_DIR}/summary.txt" ] && grep -q "${pattern}" "${LAST_DIR}/summary.txt"; then
        fail "${name}: summary unexpectedly matched /${pattern}/"
        cat "${LAST_DIR}/summary.txt" >&2 || true
    fi
}

xml_header='<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">'

# --- hollow notapplicable scan fails even with the finding gate off ---
run_case "hollow default" 1 <<EOF
${xml_header}
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_sshd"><result>notapplicable</result></rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_auditd"><result>notapplicable</result></rule-result>
  </TestResult>
</Benchmark>
EOF
assert_grep "hollow default" "not evidence of compliance"
assert_grep "hollow default" "require_evaluated_rules=true"
assert_log "hollow default" stderr "ERROR: require_evaluated_rules=true and 0 rules evaluated"
pass_count="$(awk '/^  pass / {print $2}' "${LAST_DIR}/summary.txt")"
if [ "${pass_count}" != "0" ]; then
    fail "hollow default: expected pass count 0, got '${pass_count}'"
fi

# --- explicit opt-out records the baseline and says it is not compliance ---
run_case "hollow allowed" 0 PARAM_REQUIRE_EVALUATED_RULES=false <<EOF
${xml_header}
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_sshd"><result>notapplicable</result></rule-result>
  </TestResult>
</Benchmark>
EOF
assert_grep "hollow allowed" "not evidence of compliance"
assert_grep "hollow allowed" "require_evaluated_rules=false"

# CircleCI serializes boolean false as 0.
run_case "hollow allowed via 0" 0 PARAM_REQUIRE_EVALUATED_RULES=0 <<EOF
${xml_header}
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_sshd"><result>notapplicable</result></rule-result>
  </TestResult>
</Benchmark>
EOF
assert_grep "hollow allowed via 0" "require_evaluated_rules=false"

# CircleCI serializes boolean true as 1.
run_case "hollow rejected via 1" 1 PARAM_REQUIRE_EVALUATED_RULES=1 <<EOF
${xml_header}
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_sshd"><result>notapplicable</result></rule-result>
  </TestResult>
</Benchmark>
EOF

# --- notchecked-only is unevaluated ---
run_case "notchecked only" 1 <<EOF
${xml_header}
  <Rule id="xccdf_org.ssgproject.content_rule_manual_review" severity="medium">
    <title>Manual review</title>
  </Rule>
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_manual_review" severity="medium">
      <result>notchecked</result>
    </rule-result>
  </TestResult>
</Benchmark>
EOF
assert_grep "notchecked only" "manual_review"
assert_grep "notchecked only" "not evidence of compliance"

# --- error counts toward the scan-quality gate, and is listed, even with
# the compliance gate off ---
run_case "error gated" 1 PARAM_FAIL_ON=never <<EOF
${xml_header}
  <Rule id="xccdf_org.ssgproject.content_rule_rpm_probe" severity="high">
    <title>RPM probe</title>
  </Rule>
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_file_ok" severity="low">
      <result>pass</result>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_rpm_probe" severity="high">
      <result>error</result>
    </rule-result>
  </TestResult>
</Benchmark>
EOF
assert_grep "error gated" "rpm_probe"
assert_grep "error gated" "scan-quality-gate: failed"
assert_grep "error gated" "compliance-gate: disabled"
assert_not_grep "error gated" "not evidence of compliance"

# Quality opt-out: errors stay visible and do not fail a scan that did
# evaluate rules, even with the compliance gate on.
run_case "error ungated" 0 PARAM_FAIL_ON=info PARAM_FAIL_ON_SCAN_ERROR=0 <<EOF
${xml_header}
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_file_ok"><result>pass</result></rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_rpm_probe"><result>error</result></rule-result>
  </TestResult>
</Benchmark>
EOF
assert_grep "error ungated" "fail_on_scan_error=false — these scan-quality issues do not fail the job"
assert_grep "error ungated" "rpm_probe"

# --- unknown counts toward the scan-quality gate ---
run_case "unknown gated" 1 PARAM_FAIL_ON=never <<EOF
${xml_header}
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_file_ok"><result>pass</result></rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_mystery"><result>unknown</result></rule-result>
  </TestResult>
</Benchmark>
EOF
assert_grep "unknown gated" "mystery"

# --- all-error scan is hollow, so it fails even with both other gates off ---
run_case "errors only" 1 PARAM_FAIL_ON=never PARAM_FAIL_ON_SCAN_ERROR=false <<EOF
${xml_header}
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_rpm_probe"><result>error</result></rule-result>
  </TestResult>
</Benchmark>
EOF
assert_grep "errors only" "not evidence of compliance"

# --- ignored fails are evaluated, so a triaged baseline is not hollow ---
run_case "ignored baseline" 0 \
    PARAM_FAIL_ON=info \
    PARAM_IGNORE_FINDINGS="SV-1000r1,SV-2000r2" <<EOF
${xml_header}
  <Rule id="xccdf_org.ssgproject.content_rule_alpha" severity="high">
    <title>Alpha</title>
    <reference href="https://www.cyber.mil">SV-1000r1_rule</reference>
  </Rule>
  <Rule id="xccdf_org.ssgproject.content_rule_beta" severity="medium">
    <title>Beta</title>
    <reference href="https://www.cyber.mil">SV-2000r2_rule</reference>
  </Rule>
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_alpha" severity="high"><result>fail</result></rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_beta" severity="medium"><result>fail</result></rule-result>
  </TestResult>
</Benchmark>
EOF
assert_not_grep "ignored baseline" "not evidence of compliance"
assert_grep "ignored baseline" "\\[IGNORED\\]"

# A shared reference token waives every rule that cites it. Pass rule keeps
# the scan evaluated; both fails are ignored so the finding gate passes.
run_case "shared reference ignore" 0 \
    PARAM_FAIL_ON=info \
    PARAM_IGNORE_FINDINGS="AC-2" <<EOF
${xml_header}
  <Rule id="xccdf_org.ssgproject.content_rule_alpha" severity="high">
    <title>Alpha</title>
    <reference href="https://csrc.nist.gov">AC-2</reference>
  </Rule>
  <Rule id="xccdf_org.ssgproject.content_rule_beta" severity="medium">
    <title>Beta</title>
    <reference href="https://csrc.nist.gov">AC-2</reference>
  </Rule>
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_ok"><result>pass</result></rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_alpha"><result>fail</result></rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_beta"><result>fail</result></rule-result>
  </TestResult>
</Benchmark>
EOF
assert_grep "shared reference ignore" "\\[IGNORED\\] alpha"
assert_grep "shared reference ignore" "\\[IGNORED\\] beta"

# --- a real pass is not hollow and does not trip a gate that is off ---
run_case "pass only" 0 <<EOF
${xml_header}
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_file_ok"><result>pass</result></rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_sshd"><result>notapplicable</result></rule-result>
  </TestResult>
</Benchmark>
EOF
assert_not_grep "pass only" "not evidence of compliance"

# --- fail still fails the finding gate ---
run_case "fail gated" 1 PARAM_FAIL_ON=info <<EOF
${xml_header}
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_telnet"><result>fail</result></rule-result>
  </TestResult>
</Benchmark>
EOF
assert_grep "fail gated" "telnet"
assert_grep "fail gated" "^  fail-on: info$"
assert_log "fail gated" stderr "ERROR: fail_on=info and 1 non-ignored fail result(s) at info severity or above"

# --- fail_on is a severity threshold: one fail on each of a low, a
# medium, and a high rule ---
threshold_xml="${xml_header}
  <Rule id=\"xccdf_org.ssgproject.content_rule_cat3\" severity=\"low\"><title>Cat III</title></Rule>
  <Rule id=\"xccdf_org.ssgproject.content_rule_cat2\" severity=\"medium\"><title>Cat II</title></Rule>
  <Rule id=\"xccdf_org.ssgproject.content_rule_cat1\" severity=\"high\"><title>Cat I</title></Rule>
  <TestResult>
    <rule-result idref=\"xccdf_org.ssgproject.content_rule_cat3\" severity=\"low\"><result>fail</result></rule-result>
    <rule-result idref=\"xccdf_org.ssgproject.content_rule_cat2\" severity=\"medium\"><result>fail</result></rule-result>
    <rule-result idref=\"xccdf_org.ssgproject.content_rule_cat1\" severity=\"high\"><result>fail</result></rule-result>
  </TestResult>
</Benchmark>"
for level_count in info:3 low:3 medium:2 high:1; do
    level="${level_count%%:*}"
    count="${level_count#*:}"
    run_case "threshold ${level}" 1 PARAM_FAIL_ON="${level}" <<< "${threshold_xml}"
    assert_log "threshold ${level}" stderr "ERROR: fail_on=${level} and ${count} non-ignored fail result(s)"
done
run_case "threshold never" 0 PARAM_FAIL_ON=never <<< "${threshold_xml}"
assert_grep "threshold never" "^  fail-on: never$"

# Ignoring the only fail at or above the threshold passes the gate, even
# with lower-severity fails left; they stay listed.
run_case "threshold high ignored" 0 \
    PARAM_FAIL_ON=high \
    PARAM_IGNORE_FINDINGS="cat1" <<< "${threshold_xml}"
assert_grep "threshold high ignored" "\\[IGNORED\\] cat1"
assert_grep "threshold high ignored" "  - cat2 (medium)"
assert_grep "threshold high ignored" "  - cat3 (low)"

# An error below the fail_on threshold still fails the scan-quality gate:
# fail_on counts only fail results.
run_case "error below threshold" 1 PARAM_FAIL_ON=high <<EOF
${xml_header}
  <Rule id="xccdf_org.ssgproject.content_rule_rpm_probe" severity="low"><title>RPM probe</title></Rule>
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_file_ok"><result>pass</result></rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_rpm_probe" severity="low"><result>error</result></rule-result>
  </TestResult>
</Benchmark>
EOF
assert_grep "error below threshold" "scan-quality-gate: failed"
assert_grep "error below threshold" "compliance-gate: passed"
assert_grep "error below threshold" "rpm_probe"

# The ignore-list waives fail results only; an ignored error still fails.
run_case "ignored error" 1 PARAM_FAIL_ON=info PARAM_IGNORE_FINDINGS="rpm_probe" <<EOF
${xml_header}
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_file_ok"><result>pass</result></rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_rpm_probe"><result>error</result></rule-result>
  </TestResult>
</Benchmark>
EOF
assert_grep "ignored error" "ignore_findings does not waive scan-quality issues"
assert_not_grep "ignored error" "\\[IGNORED\\] rpm_probe"

# --- bad fail_on value; the old boolean form is rejected too ---
for value in true yes HIGH; do
    run_case "bad fail_on ${value}" 2 PARAM_FAIL_ON="${value}" <<< "${threshold_xml}"
    assert_log "bad fail_on ${value}" stderr "ERROR: fail_on must be high, medium, low, info, or never; got '${value}'."
done

# --- empty results are a broken scan, not a hollow opt-out ---
run_case "no rule results" 2 PARAM_REQUIRE_EVALUATED_RULES=false <<EOF
${xml_header}
  <TestResult></TestResult>
</Benchmark>
EOF

# --- bad boolean ---
run_case "bad bool" 2 PARAM_REQUIRE_EVALUATED_RULES=yes <<EOF
${xml_header}
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_file_ok"><result>pass</result></rule-result>
  </TestResult>
</Benchmark>
EOF
assert_log "bad bool" stderr "ERROR: require_evaluated_rules must be 'true', 'false', '1', or '0'; got 'yes'."

# --- the gate counts never pass through a fixed name in output_dir ---
# A summary.txt.gate left in output_dir (here a symlink) must not be
# written through: the counts go through a private mktemp file.
dir="$(mktemp -d)"
cat > "${dir}/results.xml" <<EOF
${xml_header}
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_file_ok"><result>pass</result></rule-result>
  </TestResult>
</Benchmark>
EOF
printf 'untouched\n' > "${dir}/outside"
ln -s "${dir}/outside" "${dir}/summary.txt.gate"
set +e
PARAM_OUTPUT_DIR="${dir}" bash "${SUMMARIZE}" > /dev/null 2>&1
rc=$?
set -e
if [ "${rc}" -ne 0 ]; then
    fail "private gate file: expected exit 0, got ${rc}"
fi
if [ "$(cat "${dir}/outside")" != "untouched" ]; then
    fail "private gate file: summarize wrote its gate counts through ${dir}/summary.txt.gate"
fi

# --- missing results.xml ---
dir="$(mktemp -d)"
set +e
PARAM_OUTPUT_DIR="${dir}" bash "${SUMMARIZE}" > /dev/null 2>&1
rc=$?
set -e
if [ "${rc}" -ne 2 ]; then
    fail "missing results: expected exit 2, got ${rc}"
fi

if [ "${failures}" -ne 0 ]; then
    echo "${failures} fixture test(s) failed." >&2
    exit 1
fi
echo "summarize gate fixtures passed"
python3 "${ROOT}/tests/scan_quality_test.py"
