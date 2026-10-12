#!/usr/bin/env bash
# Pre-create output_dir so store_artifacts has a path to upload even when
# the scan fails early. In rootfs_path mode scan.sh creates it instead,
# after checking that it doesn't overlap the scanned tree, which must not
# be written to.
set -euo pipefail

# --- env-substitution shim: works in CircleCI and locally -----------------
subst() {
    if command -v circleci >/dev/null 2>&1; then
        circleci env subst "$1"
    else
        echo "$1"
    fi
}

OUTPUT_DIR="$(subst "${PARAM_OUTPUT_DIR:-build/stig}")"
ROOTFS_PATH="$(subst "${PARAM_ROOTFS_PATH:-}")"

if [ -z "${ROOTFS_PATH}" ]; then
    mkdir -p "${OUTPUT_DIR}"
fi
