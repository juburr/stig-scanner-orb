#!/usr/bin/env bash
# Finish the scan job after validated checklists and ordinary evidence upload.
set -euo pipefail
subst() {
    if command -v circleci >/dev/null 2>&1; then
        circleci env subst "$1"
    else
        printf '%s\n' "$1"
    fi
}
OUTPUT_DIR="$(subst "${PARAM_OUTPUT_DIR:-build/stig}")"
ROOTFS_PATH="$(subst "${PARAM_ROOTFS_PATH:-}")"
if [ -n "${ROOTFS_PATH}" ]; then
    if ! python3 - "${OUTPUT_DIR}" "${ROOTFS_PATH}" <<'PY'
import os
import sys
out, tree = (os.path.realpath(p) for p in sys.argv[1:])
sys.exit(1 if os.path.commonpath((out, tree)) in (out, tree) else 0)
PY
    then
        echo "ERROR: cannot enforce a gate inside an overlapping rootfs_path." >&2
        exit 2
    fi
fi
GATE_FILE="${OUTPUT_DIR}/summary.txt.exit-code"
if [ ! -f "${GATE_FILE}" ] || [ -L "${GATE_FILE}" ]; then
    echo "ERROR: summarize did not record a deferred policy result." >&2
    exit 2
fi
GATE_EXIT="$(cat -- "${GATE_FILE}")"
rm -f -- "${GATE_FILE}"
case "${GATE_EXIT}" in
    0) echo "==> Summarized scan policies passed." ;;
    1) echo "==> Summarized scan policies failed; see summary.txt."; exit 1 ;;
    *) echo "ERROR: invalid deferred policy result." >&2; exit 2 ;;
esac
