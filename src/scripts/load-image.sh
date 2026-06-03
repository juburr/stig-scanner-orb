#!/usr/bin/env bash
# Optional helper: docker load an image tarball into the local daemon
# so the scan step can find it. Useful when the previous job in the
# workflow built the image and persisted the tar via store/attach
# workspace.

set -euo pipefail

subst() {
    if command -v circleci >/dev/null 2>&1; then
        circleci env subst "$1"
    else
        echo "$1"
    fi
}

TARBALL="$(subst "${PARAM_IMAGE_TARBALL:-}")"

if [ -z "${TARBALL}" ]; then
    echo "load-image: no image-tarball set, nothing to do."
    exit 0
fi

if [ ! -f "${TARBALL}" ]; then
    echo "ERROR: image-tarball '${TARBALL}' not found." >&2
    exit 2
fi

echo "==> docker load -i ${TARBALL}"
docker load -i "${TARBALL}"
docker images
