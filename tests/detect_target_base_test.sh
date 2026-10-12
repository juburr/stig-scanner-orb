#!/usr/bin/env bash
# target_base: auto resolution against synthetic rootfs trees. No docker:
# a stub `docker` on PATH fails the first image call, which happens only
# after detection has printed its result, so each case stops right there.
# A pass-through `circleci env subst` stub keeps scan.sh's subst() from
# depending on whatever circleci binary the host has, and a no-op `sleep`
# skips the pull-retry backoff the failing stub would otherwise trigger.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCAN="${ROOT}/src/scripts/scan.sh"
failures=0

fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

stub="$(mktemp -d)"
printf '#!/bin/sh\nexit 1\n' > "${stub}/docker"
printf '#!/bin/sh\nexit 0\n' > "${stub}/sleep"
# shellcheck disable=SC2016  # $1..$3 belong to the generated stub
printf '#!/bin/sh\n[ "$1 $2" = "env subst" ] && printf "%%s\\n" "$3"\n' > "${stub}/circleci"
chmod +x "${stub}/docker" "${stub}/circleci" "${stub}/sleep"

# expect NAME WANT ROOTFS — WANT is "<base> (from <source>)" or "ERROR".
expect() {
    local name="$1" want="$2" rootfs="$3" out
    out="$(PATH="${stub}:${PATH}" PARAM_ROOTFS_PATH="${rootfs}" PARAM_TARGET_BASE=auto \
        PARAM_OUTPUT_DIR="$(mktemp -d)" bash "${SCAN}" 2>&1 || true)"
    if [ "${want}" = "ERROR" ]; then
        case "${out}" in
            *"could not auto-detect a supported target-base"*) ;;
            *) fail "${name}: expected a detection error, got: ${out}" ;;
        esac
    else
        case "${out}" in
            *"auto-detected target-base: ${want}"*) ;;
            *) fail "${name}: expected '${want}', got: $(printf '%s' "${out}" | head -3)" ;;
        esac
    fi
}

mk() {
    local d
    d="$(mktemp -d)"
    for path in "$@"; do
        case "${path}" in
            */) mkdir -p "${d}/${path}" ;;
            *) mkdir -p "$(dirname "${d}/${path}")"; : > "${d}/${path}" ;;
        esac
    done
    printf '%s' "${d}"
}

# os-release is authoritative when present.
r="$(mk etc/)"; printf 'ID=debian\nVERSION_ID="12"\n' > "${r}/etc/os-release"
expect "debian os-release" "debian12 (from os-release)" "${r}"
r="$(mk etc/)"; printf 'ID="rhel"\nVERSION_ID="9.4"\n' > "${r}/etc/os-release"
expect "rhel os-release" "rhel9 (from os-release)" "${r}"
r="$(mk etc/ var/lib/dpkg/status)"; printf 'ID=ubuntu\nVERSION_ID="24.04"\n' > "${r}/etc/os-release"
expect "unsupported os-release beats package-db" "ERROR" "${r}"

# No os-release: filesystem-shape fallbacks.
expect "apk db" "wolfi (from package-db)" "$(mk lib/apk/db/)"
expect "rpm db" "rhel9 (from package-db)" "$(mk var/lib/rpm/)"
expect "dpkg status" "debian12 (from package-db)" "$(mk var/lib/dpkg/status)"
expect "distroless status.d" "debian12 (from package-db)" "$(mk var/lib/dpkg/status.d/libc6)"
expect "nothing recognizable" "ERROR" "$(mk usr/bin/)"

# Hints are only trusted if they resolve inside the rootfs: an absolute
# symlink would otherwise be tested against this host's filesystem.
r="$(mk var/lib/dpkg/)"; ln -s /etc "${r}/var/lib/dpkg/status.d"
expect "status.d symlinked out of the rootfs" "ERROR" "${r}"
r="$(mk var/lib/)"; ln -s /var/lib/dpkg "${r}/var/lib/dpkg"
expect "dpkg dir symlinked out of the rootfs" "ERROR" "${r}"
r="$(mk var/lib/)"; ln -s /etc "${r}/var/lib/rpm"
expect "rpm db symlinked out of the rootfs" "ERROR" "${r}"
r="$(mk var/lib/dpkg/ usr/share/dpkg/status.d/libc6)"; ln -s ../../../usr/share/dpkg/status.d "${r}/var/lib/dpkg/status.d"
expect "relative symlink inside the rootfs" "debian12 (from package-db)" "${r}"

if [ "${failures}" -ne 0 ]; then
    echo "${failures} detection case(s) failed." >&2
    exit 1
fi
echo "target_base detection cases passed"
