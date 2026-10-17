#!/usr/bin/env bash
# Pre-create output_dir so store_artifacts has a path to upload even when
# the scan fails early. In rootfs_path mode scan.sh creates it instead,
# after checking that it doesn't overlap the scanned tree, which must not
# be written to.
set -euo pipefail

# --- env-substitution shim: works in CircleCI and locally -----------------
subst() {
    if command -v circleci >/dev/null 2>&1; then
        printf '%s' "$1" | circleci env subst
    else
        printf '%s\n' "$1"
    fi
}

OUTPUT_DIR="$(subst "${PARAM_OUTPUT_DIR:-build/stig}")"
ROOTFS_PATH="$(subst "${PARAM_ROOTFS_PATH:-}")"

# Answers are read later by checklist; protect them before any output cleanup.
CHECKLIST_ANSWERS="$(subst "${PARAM_CHECKLIST_ANSWERS:-}")"
if [ -n "${CHECKLIST_ANSWERS}" ]; then
    python3 - "${CHECKLIST_ANSWERS}" "${OUTPUT_DIR}" <<'PY_ANSWER_INPUT'
import os
import sys
source, out = map(os.path.realpath, sys.argv[1:])
names = ["results.xml", "report.html", "scan-plan.env", "summary.txt", "provenance.json",
         "tailoring-meta.json", "summary.txt.exit-code", "checklist-meta.json", "checklist-meta.json.partial",
         "checklist.ckl", "checklist.cklb", "checklist.ckl.partial", "checklist.cklb.partial"]
collision = os.path.commonpath((source, out)) == out
for name in names:
    try:
        collision = os.path.samefile(sys.argv[1], os.path.join(sys.argv[2], name)) or collision
    except FileNotFoundError:
        pass
if collision:
    sys.exit("ERROR: checklist_answers must be outside output_dir and cannot alias generated outputs")
PY_ANSWER_INPUT
fi

if [ -z "${ROOTFS_PATH}" ]; then
    mkdir -p "${OUTPUT_DIR}"
    # Invalidate meta first, even if later cleanup is interrupted.
    rm -f -- "${OUTPUT_DIR}/checklist-meta.json"
    rm -f -- "${OUTPUT_DIR}/summary.txt.exit-code"
    rm -f -- "${OUTPUT_DIR}/checklist.ckl" "${OUTPUT_DIR}/checklist.cklb" \
        "${OUTPUT_DIR}/checklist.ckl.partial" "${OUTPUT_DIR}/checklist.cklb.partial" \
        "${OUTPUT_DIR}/checklist-meta.json.partial"
fi
