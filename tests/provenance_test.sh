#!/usr/bin/env bash
# Fixture tests for the provenance block in summary.txt and provenance.json.
# No docker, no scanner images: a hand-written scan-plan.env + results.xml.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUMMARIZE="${ROOT}/src/scripts/summarize.sh"
failures=0

fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

# check_json NAME DIR PY_EXPR — PY_EXPR is evaluated with `p` bound to the
# parsed provenance.json and must be truthy.
check_json() {
    local name="$1" dir="$2" expr="$3"
    if ! python3 -c '
import json, sys
p = json.load(open(sys.argv[1]))
sys.exit(0 if eval(sys.argv[2]) else 1)
' "${dir}/provenance.json" "${expr}"; then
        fail "${name}: provenance.json failed: ${expr}"
    fi
}

check_summary() {
    local name="$1" dir="$2" pattern="$3"
    if ! grep -qF -- "${pattern}" "${dir}/summary.txt"; then
        fail "${name}: summary.txt missing '${pattern}'"
    fi
}

summarize() {
    PARAM_OUTPUT_DIR="$1" PARAM_FAIL_ON_FINDING=false PARAM_REQUIRE_EVALUATED_RULES=true \
        bash "${SUMMARIZE}" > "$1/stdout.txt" 2>&1
}

ssg_results() {
    cat <<'EOF'
<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.ssgproject.content_benchmark_RHEL-9">
  <version update="https://github.com/ComplianceAsCode/content/releases/latest">0.1.82</version>
  <Profile id="xccdf_org.ssgproject.content_profile_stig">
    <title>DISA STIG for Red Hat Enterprise Linux 9</title>
  </Profile>
  <TestResult id="t" start-time="2026-10-11T15:00:00+00:00" end-time="2026-10-11T15:00:05+00:00" test-system="cpe:/a:redhat:openscap:1.3.6">
    <profile idref="xccdf_org.ssgproject.content_profile_stig"/>
    <rule-result idref="xccdf_org.ssgproject.content_rule_ok"><result>pass</result></rule-result>
  </TestResult>
</Benchmark>
EOF
}

# --- image mode, donated datastream, SSG content --------------------------
dir="$(mktemp -d)"
ssg_results > "${dir}/results.xml"
cat > "${dir}/scan-plan.env" <<'EOF'
target_base=rhel9
target_base_requested=auto
target_base_source=os-release
scanner=quay.io/compliance-operator/openscap-ocp:1.3.6@sha256:4c49e8c1af801051d9dbe5d33e371440948cbffce1dbc4379daf909b1288869a
scanner_image_id=sha256:416667d6f36890b06dad73de18821bf1dc3a9a1d6b3f5f7804193f92ec752fba
scanner_repo_digests=quay.io/compliance-operator/openscap-ocp@sha256:4c49e8c1af801051d9dbe5d33e371440948cbffce1dbc4379daf909b1288869a
scanner_platform=linux/amd64
datastream=ssg-rhel9-ds.xml
datastream_source=donated
datastream_sha256=27fc84bb2ea29619a944d5a75b361961e1ac7a8dadd48f4165f00d106b0ef944
donor_image=cgr.dev/chainguard/openscap:latest-dev@sha256:f5e08bc14cc659268a7807d7ec573ff3cc56b62b9358313db8df76909018b55e
donor_image_id=sha256:dbdc45439109a94e109e880a1f537160f54ecd10facae6abfd66d5b95ae20f27
donor_repo_digests=cgr.dev/chainguard/openscap@sha256:f5e08bc14cc659268a7807d7ec573ff3cc56b62b9358313db8df76909018b55e
donor_platform=linux/amd64
donor_used_for=extraction,datastream
profile=xccdf_org.ssgproject.content_profile_stig
family=rpm
image=registry.access.redhat.com/ubi9/ubi-minimal:latest
image_id=sha256:2029c54baa5a52b4ed6a134ea6280ec6c15f79bdcbbc69e947d4c397e646d875
image_repo_digests=registry.access.redhat.com/ubi9/ubi-minimal@sha256:5ed244b62bbf4095080144d9d35eb8fcd3d39a9801f94aadd63b9d10978a01ae
image_platform=linux/arm64
EOF
summarize "${dir}" || fail "donated: summarize exited $?"
check_json donated "${dir}" 'p["checklist"] is None and len(p["scan"]["results_sha256"]) == 64'
check_json donated "${dir}" 'p["schema"] == "stig-scanner-orb/provenance/v1"'
check_json donated "${dir}" 'p["target"]["repo_digests"] == ["registry.access.redhat.com/ubi9/ubi-minimal@sha256:5ed244b62bbf4095080144d9d35eb8fcd3d39a9801f94aadd63b9d10978a01ae"]'
check_json donated "${dir}" 'p["target"]["rootfs_path"] is None'
check_json donated "${dir}" 'p["target_base"] == {"requested": "auto", "resolved": "rhel9", "resolved_from": "os-release"}'
check_json donated "${dir}" 'p["profile"] == {"id": "xccdf_org.ssgproject.content_profile_stig", "title": "DISA STIG for Red Hat Enterprise Linux 9"}'
check_json donated "${dir}" 'p["scanner"]["openscap_version"] == "1.3.6"'
check_json donated "${dir}" 'p["donor"]["used_for"] == ["extraction", "datastream"]'
check_json donated "${dir}" 'p["datastream"]["source"] == "donated" and len(p["datastream"]["sha256"]) == 64'
check_json donated "${dir}" 'p["datastream"]["ssg_version"] == "0.1.82" and p["datastream"]["benchmark_version"] == "0.1.82"'
check_json donated "${dir}" 'p["scan"]["start_time"] == "2026-10-11T15:00:00+00:00"'
check_json donated "${dir}" 'p["target"]["platform"] == "linux/arm64" and p["scanner"]["platform"] == "linux/amd64" and p["donor"]["platform"] == "linux/amd64"'
check_summary donated "${dir}" "ubi9/ubi-minimal@sha256:5ed244b62bbf4095080144d9d35eb8fcd3d39a9801f94aadd63b9d10978a01ae [linux/arm64]"
check_summary donated "${dir}" "openscap-ocp@sha256:4c49e8c1af801051d9dbe5d33e371440948cbffce1dbc4379daf909b1288869a [linux/amd64]"
check_summary donated "${dir}" "  target-digest:     registry.access.redhat.com/ubi9/ubi-minimal@sha256:5ed244b6"
check_summary donated "${dir}" "  target-base:       rhel9 (requested auto, from os-release)"
check_summary donated "${dir}" "  donor-digest:      cgr.dev/chainguard/openscap@sha256:f5e08bc1"
check_summary donated "${dir}" "  datastream-sha256: 27fc84bb2ea29619a944d5a75b361961e1ac7a8dadd48f4165f00d106b0ef944"
check_summary donated "${dir}" "  ssg-version:       0.1.82"
# The pre-existing header lines that smoke jobs grep must not move.
check_summary donated "${dir}" "  target-base:    rhel9"

# --- locally built target, bundled non-SSG datastream, no donor ----------
dir="$(mktemp -d)"
cat > "${dir}/results.xml" <<'EOF'
<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.open-scap.sce-community-content_benchmark_all">
  <version>3.2.17</version>
  <TestResult id="t" test-system="cpe:/a:redhat:openscap:1.4.4">
    <profile idref="xccdf_basic_profile_.check"/>
    <rule-result idref="r1"><result>pass</result></rule-result>
  </TestResult>
</Benchmark>
EOF
cat > "${dir}/scan-plan.env" <<'EOF'
target_base=wolfi
target_base_requested=wolfi
target_base_source=parameter
scanner=cgr.dev/chainguard/openscap:latest-dev@sha256:f5e08bc14cc659268a7807d7ec573ff3cc56b62b9358313db8df76909018b55e
scanner_image_id=sha256:dbdc45439109a94e109e880a1f537160f54ecd10facae6abfd66d5b95ae20f27
scanner_repo_digests=cgr.dev/chainguard/openscap@sha256:f5e08bc14cc659268a7807d7ec573ff3cc56b62b9358313db8df76909018b55e
datastream=ssg-chainguard-gpos-ds.xml
datastream_source=bundled
datastream_sha256=
profile=xccdf_basic_profile_.check
family=apk
image=localhost/myapp:dev
image_id=sha256:1111111111111111111111111111111111111111111111111111111111111111
image_repo_digests=
EOF
summarize "${dir}" || fail "local: summarize exited $?"
check_json local "${dir}" 'p["target"]["repo_digests"] == [] and p["target"]["image_id"].startswith("sha256:1111")'
check_json local "${dir}" 'p["donor"] is None'
check_json local "${dir}" 'p["target"]["dpkg_status"] is None'
check_json local "${dir}" 'p["target"]["platform"] is None and p["scanner"]["platform"] is None'
check_json local "${dir}" 'p["datastream"]["ssg_version"] is None and p["datastream"]["benchmark_version"] == "3.2.17"'
check_json local "${dir}" 'p["datastream"]["sha256"] is None'
check_json local "${dir}" 'p["profile"]["title"] is None'
check_summary local "${dir}" "  target-digest:     none, not pulled from a registry (image id sha256:1111"
check_summary local "${dir}" "  datastream-sha256: unavailable"
check_summary local "${dir}" "  ssg-version:       n/a (not ComplianceAsCode content)"

# --- distroless dpkg layout: synthesized (image mode) / missing (rootfs) --
dir="$(mktemp -d)"
ssg_results > "${dir}/results.xml"
printf '%s\n' "target_base=debian12" "scanner=s" "datastream=ssg-debian12-ds.xml" \
    "profile=xccdf_org.ssgproject.content_profile_stig" "family=dpkg" \
    "dpkg_status=synthesized" "dpkg_status_packages=11" "image=gcr.io/distroless/cc-debian12:latest" \
    "donor_image=d" "donor_image_id=sha256:2222" "donor_used_for=extraction,dpkg-status" \
    > "${dir}/scan-plan.env"
summarize "${dir}" || fail "dpkg-synth: summarize exited $?"
check_json dpkg-synth "${dir}" 'p["donor"]["used_for"] == ["extraction", "dpkg-status"]'
check_summary dpkg-synth "${dir}" "(used for extraction, dpkg-status)"
check_json dpkg-synth "${dir}" 'p["target"]["dpkg_status"] == {"state": "synthesized", "packages": 11, "source": "/var/lib/dpkg/status.d", "reason": None}'
check_summary dpkg-synth "${dir}" "  dpkg-status:       synthesized from /var/lib/dpkg/status.d (11 packages)"
if grep -q "^WARNING: the target has no usable /var/lib/dpkg/status" "${dir}/summary.txt"; then
    fail "dpkg-synth: must not warn when the status file was synthesized"
fi

dir="$(mktemp -d)"
ssg_results > "${dir}/results.xml"
printf '%s\n' "target_base=debian12" "scanner=s" "datastream=ssg-debian12-ds.xml" \
    "profile=xccdf_org.ssgproject.content_profile_stig" "family=dpkg" \
    "dpkg_status=missing" "dpkg_status_packages=" \
    "dpkg_status_reason=the orb does not modify a rootfs_path tree" "rootfs_path=/tmp/rootfs" \
    > "${dir}/scan-plan.env"
summarize "${dir}" || fail "dpkg-missing: summarize exited $?"
check_json dpkg-missing "${dir}" 'p["target"]["dpkg_status"]["state"] == "missing" and p["target"]["dpkg_status"]["packages"] is None'
check_json dpkg-missing "${dir}" 'p["target"]["dpkg_status"]["reason"] == "the orb does not modify a rootfs_path tree"'
check_summary dpkg-missing "${dir}" "WARNING: the target has no usable /var/lib/dpkg/status"
check_summary dpkg-missing "${dir}" "no usable /var/lib/dpkg/status (the orb does not modify a rootfs_path tree)"

# Image mode whose status.d/ had nothing to build from: same warning.
dir="$(mktemp -d)"
ssg_results > "${dir}/results.xml"
printf '%s\n' "target_base=debian12" "scanner=s" "datastream=ssg-debian12-ds.xml" \
    "profile=xccdf_org.ssgproject.content_profile_stig" "family=dpkg" \
    "dpkg_status=missing" "dpkg_status_packages=" \
    "dpkg_status_reason=status.d/ holds no package stanzas" "image=example/empty-status-d:1" \
    > "${dir}/scan-plan.env"
summarize "${dir}" || fail "dpkg-empty: summarize exited $?"
check_json dpkg-empty "${dir}" 'p["target"]["dpkg_status"] == {"state": "missing", "packages": None, "source": "/var/lib/dpkg/status.d", "reason": "status.d/ holds no package stanzas"}'
check_summary dpkg-empty "${dir}" "no usable /var/lib/dpkg/status (status.d/ holds no package stanzas)"

# Plain absence is not evidence that the distroless fragment layout exists.
printf '%s\n' "dpkg_status_source=" "dpkg_status_reason=package database absent" >> "${dir}/scan-plan.env"
summarize "${dir}" || fail "dpkg-absent: summarize exited $?"
check_json dpkg-absent "${dir}" 'p["target"]["dpkg_status"]["source"] is None'
check_summary dpkg-absent "${dir}" "package absence cannot be verified"

# --- no scan-plan.env: provenance.json still written from results.xml ----
dir="$(mktemp -d)"
ssg_results > "${dir}/results.xml"
summarize "${dir}" || fail "no-plan: summarize exited $?"
check_json no-plan "${dir}" 'p["datastream"]["ssg_version"] == "0.1.82" and p["scanner"]["image"] is None'
if grep -q "^Provenance:" "${dir}/summary.txt"; then
    fail "no-plan: summary.txt should omit the provenance block without a scan plan"
fi

if [ "${failures}" -ne 0 ]; then
    echo "${failures} provenance check(s) failed." >&2
    exit 1
fi
echo "provenance fixtures passed"
