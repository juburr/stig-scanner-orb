#!/usr/bin/env bash
# Every `docker run` in the orb's scripts must use --network none: the
# README promises security teams that a scan's only network traffic is the
# Docker daemon's image pulls.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
failures=0
runs=0

while IFS= read -r hit; do
    runs=$((runs + 1))
    case "${hit}" in
        *"--network none"*) ;;
        *)
            echo "FAIL: docker run without --network none: ${hit}" >&2
            failures=$((failures + 1)) ;;
    esac
done < <(grep -nE '(^|[^[:alnum:]_])docker run( |$)' "${ROOT}"/src/scripts/*.sh | grep -vE ':[[:space:]]*#')

if [ "${runs}" -eq 0 ]; then
    echo "FAIL: found no docker run invocations; the pattern is stale" >&2
    exit 1
fi

# A rootfs_path holding a Unix socket (a live filesystem, e.g. one with
# /run/docker.sock) must be refused before any container sees it. No
# docker: the stub fails any call, and the socket check runs before one.
# The no-op sleep skips the pull-retry backoff after the stub fails.
stub="$(mktemp -d)"
printf '#!/bin/sh\nexit 1\n' > "${stub}/docker"
printf '#!/bin/sh\nexit 0\n' > "${stub}/sleep"
# shellcheck disable=SC2016  # $1..$3 belong to the generated stub
printf '#!/bin/sh\n[ "$1 $2" = "env subst" ] && printf "%%s\\n" "$3"\n' > "${stub}/circleci"
chmod +x "${stub}/docker" "${stub}/circleci" "${stub}/sleep"
tree="$(mktemp -d)"
mkdir -p "${tree}/etc" "${tree}/run"
printf 'ID=debian\nVERSION_ID="12"\n' > "${tree}/etc/os-release"
# scan_rootfs [ROOTFS [OUTPUT_DIR]]
scan_rootfs() {
    PATH="${stub}:${PATH}" PARAM_ROOTFS_PATH="${1:-${tree}}" PARAM_TARGET_BASE=auto \
        PARAM_OUTPUT_DIR="${2:-$(mktemp -d)}" bash "${ROOT}/src/scripts/scan.sh" 2>&1
}
# refused NAME WANT ROOTFS [OUTPUT_DIR]: scan.sh must exit 2 with WANT.
refused() {
    local name="$1" want="$2" rc=0 out
    shift 2
    out="$(scan_rootfs "$@")" || rc=$?
    case "${rc}:${out}" in
        "2:"*"${want}"*) ;;
        *)
            echo "FAIL: ${name}: expected exit 2 with '${want}', got exit ${rc}: ${out}" >&2
            failures=$((failures + 1)) ;;
    esac
}
out="$(scan_rootfs || true)"
case "${out}" in
    *"contains a Unix socket"*)
        echo "FAIL: a socket-free rootfs_path was refused: ${out}" >&2
        failures=$((failures + 1)) ;;
esac
# The output dir must not overlap the scanned tree in either direction:
# the scanner mounts it read-write.
refused "output = rootfs" "overlaps rootfs-path" "${tree}" "${tree}"
refused "output inside rootfs" "overlaps rootfs-path" "${tree}" "${tree}/run"
refused "rootfs inside output" "overlaps rootfs-path" "${tree}" "$(dirname "${tree}")"

# Bind relative to the directory: socket paths are length-limited.
(cd "${tree}/run" && python3 -c 'import socket; socket.socket(socket.AF_UNIX).bind("docker.sock")')
real="$(cd "${tree}" && pwd -P)"
refused "socket in tree" "contains a Unix socket: ${real}/run/docker.sock"
# A symlinked rootfs_path is checked where it points (find alone would
# not descend into a symlink given as its starting point).
link="$(mktemp -d)/rootfs"
ln -s "${tree}" "${link}"
refused "symlinked rootfs_path" "contains a Unix socket: ${real}/run/docker.sock" "${link}"
# proc/ and sys/ of an arbitrary tree are ordinary directories.
other="$(mktemp -d)"
mkdir -p "${other}/etc" "${other}/proc"
cp "${tree}/etc/os-release" "${other}/etc/"
(cd "${other}/proc" && python3 -c 'import socket; socket.socket(socket.AF_UNIX).bind("docker.sock")')
refused "socket under proc/" "contains a Unix socket: $(cd "${other}" && pwd -P)/proc/docker.sock" "${other}"

if [ "${failures}" -ne 0 ]; then
    exit 1
fi
echo "container isolation ok: ${runs} docker run invocation(s), all --network none; socket-bearing or overlapping rootfs_path refused"
