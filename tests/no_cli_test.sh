#!/usr/bin/env bash
#
# Runs the command scripts the way the GitHub Actions run them: with no
# circleci CLI on the PATH, and with inputs CircleCI never checked, since
# every action input is a plain string. It checks that:
#
#   - without the CLI, values reach the scripts as they are: "$NAME" is not
#     expanded, and a value starting with "-" is not taken for an option
#   - target_base, checklist and checklist_default_answers, enums CircleCI
#     checks before a step runs, are checked by the scripts before any work
#     starts (an image pull, or touching an earlier run's checklist output),
#     and every value the enum allows still passes
#   - summarize takes the booleans as true or false (or CircleCI's 1 or 0)
#     and refuses anything else, as it does fail_on and checklist
#   - a staging step of generate_checklist, run through actions/run_script.sh,
#     hands the bundled DISA data's path on to later steps through GITHUB_ENV
#
# Run from a checkout:
#   bash <this file>

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="${ROOT}/src/scripts"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# The PATH the scripts run with: links to just the tools they need, and a
# stand-in docker that records its arguments. CircleCI's images have the
# circleci CLI in /bin and /usr/bin, so the system directories can't be on it.
TOOLS="${WORK}/tools"
mkdir -p "${TOOLS}"
for tool in awk basename bash cat chmod cp dirname env grep head id mkdir mktemp mv python3 \
        readlink realpath rm sed sort stat tail touch tr uname wc; do
    if ! path="$(command -v "${tool}")"; then
        echo "FAIL: ${tool} is required to run these tests"
        exit 1
    fi
    ln -s "${path}" "${TOOLS}/${tool}"
done
cat > "${TOOLS}/docker" <<EOF
#!${TOOLS}/bash
printf '%s\n' "\$*" >> "${WORK}/docker-calls"
exit 0
EOF
chmod +x "${TOOLS}/docker"

FAILURES=0
RC=0
OUTPUT=""

# run SCRIPT [VAR=value ...]: runs a script from src/scripts from ${WORK}/run
# with the PATH above, a fresh BASH_ENV and the given parameters. Sets RC
# and OUTPUT.
run() {
    local script="$1"
    shift
    rm -f "${WORK}/docker-calls"
    : > "${WORK}/bash-env"
    mkdir -p "${WORK}/run"
    OUTPUT="$(cd "${WORK}/run" && env -i HOME="${WORK}" PATH="${TOOLS}" TMPDIR="${WORK}/tmp" \
        BASH_ENV="${WORK}/bash-env" "$@" "${TOOLS}/bash" "${SCRIPTS}/${script}" < /dev/null 2>&1)"
    RC=$?
}

check() {
    local description="$1"
    shift
    if "$@"; then
        printf 'ok: %s\n' "${description}"
    else
        printf 'FAIL: %s\n' "${description}"
        printf '    | %s\n' "${OUTPUT}"
        FAILURES=$((FAILURES + 1))
    fi
}
rc_is() { [ "${RC}" -eq "$1" ]; }
output_has() { grep -qF -- "$1" <<< "${OUTPUT}"; }
output_lacks() { ! grep -qF -- "$1" <<< "${OUTPUT}"; }
docker_did_not_run() { [ ! -e "${WORK}/docker-calls" ]; }
docker_calls_are() { [ "$(cat "${WORK}/docker-calls" 2> /dev/null)" = "$(printf '%s\n' "$@")" ]; }

mkdir -p "${WORK}/tmp"
check "the scripts run with no circleci CLI on the PATH" \
    env PATH="${TOOLS}" "${TOOLS}/bash" -c '! command -v circleci'

# ---------------------------------------------------------------- load_image
# shellcheck disable=SC2016 # $HOME is part of the value, not an expansion
run load-image.sh PARAM_IMAGE_TARBALL='$HOME/image.tar'
check "load_image: a missing tarball fails" rc_is 2
# shellcheck disable=SC2016 # the value is passed as it is
check "load_image: naming the value as it is, \$HOME not expanded" \
    output_has "ERROR: image_tarball '\$HOME/image.tar' not found."
mkdir -p "${WORK}/run" && : > "${WORK}/run/-image.tar"
run load-image.sh PARAM_IMAGE_TARBALL='-image.tar'
check "load_image: loads a tarball whose name starts with -" rc_is 0
check "load_image: passing the name to docker load as it is" docker_calls_are "load -i -image.tar" "images"
run load-image.sh PARAM_IMAGE_TARBALL=''
check "load_image: does nothing without a tarball" rc_is 0
check "load_image: not even run docker" docker_did_not_run

# ---------------------------------------------------------------------- scan
for value in rhel7 RHEL9 "wolfi " "" yes; do
    run scan.sh PARAM_IMAGE=cgr.dev/chainguard/static:latest PARAM_TARGET_BASE="${value}" \
        PARAM_OUTPUT_DIR="${WORK}/out"
    # An empty target_base reads as the default, auto, as in CircleCI.
    if [ -z "${value}" ]; then
        check "scan: an empty target_base is auto" output_lacks "ERROR: target_base must be"
        continue
    fi
    check "scan: target_base '${value}' fails" rc_is 2
    check "scan: saying what target_base takes" \
        output_has "ERROR: target_base must be auto, wolfi, debian12, ubuntu2204, rhel8, rhel9, rhel10 or fedora, not '${value}'."
    check "scan: before docker runs" docker_did_not_run
done
for value in auto wolfi debian12 ubuntu2204 rhel8 rhel9 rhel10 fedora; do
    run scan.sh PARAM_ROOTFS_PATH="${WORK}/no-such-tree" PARAM_TARGET_BASE="${value}" PARAM_OUTPUT_DIR="${WORK}/out"
    check "scan: target_base ${value} passes the check" output_has "ERROR: rootfs_path '${WORK}/no-such-tree' is not a directory."
done
# shellcheck disable=SC2016 # $HOME is part of the value, not an expansion
run scan.sh PARAM_IMAGE=myapp:latest PARAM_DATASTREAM_NAME='$HOME/ds.xml' PARAM_OUTPUT_DIR="${WORK}/out"
# shellcheck disable=SC2016 # the value is passed as it is
check "scan: takes values as they are, \$HOME not expanded" \
    output_has "ERROR: datastream_name must be a filename, not a path: '\$HOME/ds.xml'."

# -------------------------------------------------------- generate_checklist
# An earlier run's checklist output, which a refused step must not touch.
seed_output() {
    rm -rf "${WORK}/out" && mkdir -p "${WORK}/out"
    printf '{"outcome": "generated"}\n' > "${WORK}/out/checklist-meta.json"
    printf 'earlier checklist\n' > "${WORK}/out/checklist.ckl"
}
for case in "PARAM_CHECKLIST=yes|ERROR: checklist must be auto, require or none, not 'yes'." \
        "PARAM_CHECKLIST=Auto|ERROR: checklist must be auto, require or none, not 'Auto'." \
        "PARAM_CHECKLIST_DEFAULT_ANSWERS=all|ERROR: checklist_default_answers must be none or container-host, not 'all'."; do
    seed_output
    run checklist-packed.sh PARAM_OUTPUT_DIR="${WORK}/out" "${case%%|*}"
    check "generate_checklist: ${case%%|*} fails" rc_is 2
    check "generate_checklist: saying what it takes" output_has "${case#*|}"
    check "generate_checklist: leaving an earlier run's output alone" \
        grep -qx '{"outcome": "generated"}' "${WORK}/out/checklist-meta.json"
done
for case in PARAM_CHECKLIST=auto PARAM_CHECKLIST=require PARAM_CHECKLIST=none \
        PARAM_CHECKLIST_DEFAULT_ANSWERS=none PARAM_CHECKLIST_DEFAULT_ANSWERS=container-host; do
    seed_output
    run checklist-packed.sh PARAM_OUTPUT_DIR="${WORK}/out" "${case}"
    # With no results.xml, generation records its failure for summarize.
    check "generate_checklist: ${case} passes the check" output_lacks "ERROR: checklist"
    check "generate_checklist: ${case} reaches generation" \
        grep -q '"outcome": "failed"' "${WORK}/out/checklist-meta.json"
    check "generate_checklist: which removes the earlier checklist" test ! -e "${WORK}/out/checklist.ckl"
done

# ------------------------------------------------------------------ summarize
rm -rf "${WORK}/out" && mkdir -p "${WORK}/out"
for case in "PARAM_DEFER_GATE=yes|defer_gate" "PARAM_FAIL_ON_SCAN_ERROR=on|fail_on_scan_error" \
        "PARAM_REQUIRE_EVALUATED_RULES=False|require_evaluated_rules" "PARAM_FAIL_ON=critical|fail_on" \
        "PARAM_CHECKLIST=yes|checklist"; do
    run summarize.sh PARAM_OUTPUT_DIR="${WORK}/out" "${case%%|*}"
    check "summarize: ${case%%|*} fails" rc_is 2
    check "summarize: naming ${case#*|}" output_has "ERROR: ${case#*|} must be"
done
for case in PARAM_DEFER_GATE=true PARAM_DEFER_GATE=1 PARAM_FAIL_ON_SCAN_ERROR=false \
        PARAM_FAIL_ON_SCAN_ERROR=0 PARAM_REQUIRE_EVALUATED_RULES=true PARAM_FAIL_ON=medium; do
    run summarize.sh PARAM_OUTPUT_DIR="${WORK}/out" "${case}"
    # With no results.xml to read, summarize stops after its checks.
    check "summarize: ${case} passes the checks" output_lacks " must be "
done

# -------------------------------------------- generate_checklist's staging
GITHUB_FILES="${WORK}/github"
mkdir -p "${GITHUB_FILES}"
: > "${GITHUB_FILES}/env"
: > "${GITHUB_FILES}/path"
OUTPUT="$(cd "${WORK}/run" && env -i HOME="${WORK}" PATH="${TOOLS}" TMPDIR="${WORK}/tmp" \
    GITHUB_ENV="${GITHUB_FILES}/env" GITHUB_PATH="${GITHUB_FILES}/path" PARAM_CHECKLIST=auto \
    "${TOOLS}/bash" "${ROOT}/actions/run_script.sh" "${SCRIPTS}/stig-data/rhel9.sh" 2>&1)"
RC=$?
staged="$(awk '/^STIG_DATA_RHEL9<</ { getline; print; exit }' "${GITHUB_FILES}/env")"
check "staging: succeeds through run_script.sh" rc_is 0
check "staging: passes the bundle's path on through GITHUB_ENV" test -n "${staged}"
check "staging: to a file in TMPDIR" test -s "${staged:-/nonexistent}"
check "staging: that is the bundle" grep -q '^/Td6WFoAAAT' "${staged:-/nonexistent}"

if [ "${FAILURES}" -gt 0 ]; then
    echo "${FAILURES} failure(s)"
    exit 1
fi
echo "All no-CLI script tests passed."
