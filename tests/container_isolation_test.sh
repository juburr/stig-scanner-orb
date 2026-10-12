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

# output-dir belongs to the caller (it may be shared, hold sockets, or
# contain the scratch rootfs); no container may mount it. The scanner
# writes to a private staging dir that the host copies out of.
if grep -nE 'OUTPUT_DIR(_ABS)?\}?"?:/' "${ROOT}"/src/scripts/*.sh; then
    echo "FAIL: a container mounts output-dir (see above)" >&2
    failures=$((failures + 1))
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
    *"contains a socket, FIFO or device node"*)
        echo "FAIL: a socket-free rootfs_path was refused: ${out}" >&2
        failures=$((failures + 1)) ;;
esac
# The output dir must not overlap the scanned tree in either direction:
# the scanner mounts it read-write.
refused "output = rootfs" "overlaps rootfs-path" "${tree}" "${tree}"
refused "output inside rootfs" "overlaps rootfs-path" "${tree}" "${tree}/run"
refused "rootfs inside output" "overlaps rootfs-path" "${tree}" "$(dirname "${tree}")"
# Refused before output-dir is created: nothing may be written into the tree.
refused "new output dir inside rootfs" "overlaps rootfs-path" "${tree}" "${tree}/new/reports"
if [ -e "${tree}/new" ]; then
    echo "FAIL: a refused scan created ${tree}/new inside the scanned tree" >&2
    failures=$((failures + 1))
fi
# ".." after a not-yet-existing component still lands in the tree.
sibling="$(mktemp -d)"
refused "dot-dot into rootfs" "overlaps rootfs-path" "${tree}" \
    "${sibling}/new/../../$(basename "${tree}")/reports"
if [ -e "${tree}/reports" ]; then
    echo "FAIL: a refused scan created ${tree}/reports inside the scanned tree" >&2
    failures=$((failures + 1))
fi

# Bind relative to the directory: socket paths are length-limited.
(cd "${tree}/run" && python3 -c 'import socket; socket.socket(socket.AF_UNIX).bind("docker.sock")')
real="$(cd "${tree}" && pwd -P)"
refused "socket in tree" "contains a socket, FIFO or device node: ${real}/run/docker.sock"
# A symlinked rootfs_path is checked where it points (find alone would
# not descend into a symlink given as its starting point).
link="$(mktemp -d)/rootfs"
ln -s "${tree}" "${link}"
refused "symlinked rootfs_path" "contains a socket, FIFO or device node: ${real}/run/docker.sock" "${link}"
# proc/ and sys/ of an arbitrary tree are ordinary directories.
other="$(mktemp -d)"
mkdir -p "${other}/etc" "${other}/proc"
cp "${tree}/etc/os-release" "${other}/etc/"
(cd "${other}/proc" && python3 -c 'import socket; socket.socket(socket.AF_UNIX).bind("docker.sock")')
refused "socket under proc/" "contains a socket, FIFO or device node: $(cd "${other}" && pwd -P)/proc/docker.sock" "${other}"
# A named pipe is an IPC channel through a read-only mount just the same.
fifo="$(mktemp -d)"
mkdir -p "${fifo}/etc" "${fifo}/run"
cp "${tree}/etc/os-release" "${fifo}/etc/"
mkfifo "${fifo}/run/initctl"
refused "fifo in tree" "contains a socket, FIFO or device node: $(cd "${fifo}" && pwd -P)/run/initctl" "${fifo}"
# Device nodes too: ro is not nodev. mknod needs root; cimg images have
# passwordless sudo, and the case is skipped where neither works.
devt="$(mktemp -d)"
mkdir -p "${devt}/etc" "${devt}/dev"
cp "${tree}/etc/os-release" "${devt}/etc/"
if mknod "${devt}/dev/null" c 1 3 2>/dev/null || sudo -n mknod "${devt}/dev/null" c 1 3 2>/dev/null; then
    refused "device node in tree" "contains a socket, FIFO or device node: $(cd "${devt}" && pwd -P)/dev/null" "${devt}"
else
    echo "note: skipped the device-node case (mknod needs root)"
fi
# TMPDIR inside the tree: refused before any mktemp writes into it.
mkdir -p "${tree}/tmp"
outside="$(mktemp -d)"
TMPDIR="${tree}/tmp" refused "TMPDIR inside rootfs" "TMPDIR ('${tree}/tmp') is inside rootfs-path" \
    "${tree}" "${outside}"
if [ -n "$(ls -A "${tree}/tmp")" ]; then
    echo "FAIL: a refused scan created files under ${tree}/tmp" >&2
    failures=$((failures + 1))
fi

if [ "${failures}" -ne 0 ]; then
    exit 1
fi
echo "container isolation ok: ${runs} docker run invocation(s), all --network none; socket/FIFO/device-bearing or overlapping rootfs_path refused"
