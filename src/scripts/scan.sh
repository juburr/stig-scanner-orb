#!/usr/bin/env bash
# Run an OpenSCAP STIG scan against a container image or extracted rootfs.
#
# Flow:
#   1. Validate inputs (exactly one of image / rootfs-path).
#   2. If image mode: docker create + docker export the target rootfs to
#      a host temp dir.
#   3. Resolve target-base → (scanner-image, datastream, profile-id) by
#      auto-detection from /etc/os-release if needed.
#   3b. For dpkg-family targets laid out like Google distroless (per-
#      package stanzas in /var/lib/dpkg/status.d/, no status file),
#      synthesize /var/lib/dpkg/status in the extracted scratch copy.
#   4. Pull the resolved scanner image (cacheable).
#   5. For RPM-family targets, copy the datastream out of the Chainguard
#      openscap image (which bundles all major datastreams) into a private
#      per-scan snapshot dir (a datastream_path file is snapshotted the
#      same way). The compliance-operator scanner that ships rpm probes
#      doesn't bundle SCAP content, so we donate it from Chainguard.
#   6. Run oscap-chroot inside the scanner against the extracted rootfs,
#      writing report.html + results.xml to the output dir.
#   7. Record what produced them in scan-plan.env: image references and
#      the digests actually used, the datastream and its sha256.

set -euo pipefail

# --- env-substitution shim: works in CircleCI and locally -----------------
subst() {
    if command -v circleci >/dev/null 2>&1; then
        circleci env subst -- "$1"
    else
        echo "$1"
    fi
}

# --- pinned default images -----------------------------------------------
# Every default image is pinned by digest, so one orb release always runs
# the same OpenSCAP build against the same SCAP content. Docker resolves the
# digest and ignores the tag; the tag is kept only to show what was pinned.
# scanner_image / donor_image still override these. To move them, follow
# "Updating the pinned images" in the README.
#
# Chainguard openscap, -dev variant (the extraction/donation helpers need a
# shell). Multi-arch index digest: linux/amd64 + linux/arm64.
DEFAULT_CHAINGUARD_IMAGE="cgr.dev/chainguard/openscap:latest-dev@sha256:f5e08bc14cc659268a7807d7ec573ff3cc56b62b9358313db8df76909018b55e"
# compliance-operator openscap-ocp: OpenSCAP 1.3.6, the build its :latest tag
# also points to. linux/amd64 only.
DEFAULT_RPM_SCANNER_IMAGE="quay.io/compliance-operator/openscap-ocp:1.3.6@sha256:4c49e8c1af801051d9dbe5d33e371440948cbffce1dbc4379daf909b1288869a"

IMAGE="$(subst "${PARAM_IMAGE:-}")"
ROOTFS_PATH="$(subst "${PARAM_ROOTFS_PATH:-}")"
TARGET_BASE="$(subst "${PARAM_TARGET_BASE:-auto}")"
SCANNER_IMAGE_OVERRIDE="$(subst "${PARAM_SCANNER_IMAGE:-}")"
DATASTREAM_NAME_OVERRIDE="$(subst "${PARAM_DATASTREAM_NAME:-}")"
DATASTREAM_PATH_OVERRIDE="$(subst "${PARAM_DATASTREAM_PATH:-}")"
PROFILE_ID_OVERRIDE="$(subst "${PARAM_PROFILE_ID:-}")"
TAILORING_FILE="$(subst "${PARAM_TAILORING_FILE:-}")"
OUTPUT_DIR="$(subst "${PARAM_OUTPUT_DIR:-build/stig}")"
DONOR_IMAGE="$(subst "${PARAM_DONOR_IMAGE:-}")"
[ -n "${DONOR_IMAGE}" ] || DONOR_IMAGE="${DEFAULT_CHAINGUARD_IMAGE}"

# A datastream name is appended to paths in both the donor and scanner
# containers.  Keep it a filename: accepting path separators would let a
# typo select unrelated content (or write outside /out during donation).
if [ -n "${DATASTREAM_NAME_OVERRIDE}" ]; then
    case "${DATASTREAM_NAME_OVERRIDE}" in
        */*|*\\*|.|..)
            echo "ERROR: datastream-name must be a filename, not a path: '${DATASTREAM_NAME_OVERRIDE}'." >&2
            exit 2 ;;
    esac
fi

if [ -n "${TAILORING_FILE}" ] && [ -z "${PROFILE_ID_OVERRIDE}" ]; then
    echo "ERROR: tailoring_file requires an explicit profile_id naming a profile in that file." >&2
    exit 2
fi
# scan-plan.env is line-oriented; never let these inputs inject another key.
case "${TAILORING_FILE}${PROFILE_ID_OVERRIDE}" in
    *$'\n'*|*$'\r'*) echo "ERROR: tailoring_file and profile_id cannot contain newlines." >&2; exit 2 ;;
esac

# --- 1. validate input shape ---------------------------------------------
if [ -n "${IMAGE}" ] && [ -n "${ROOTFS_PATH}" ]; then
    echo "ERROR: specify exactly one of 'image' or 'rootfs-path'." >&2
    exit 2
fi
if [ -z "${IMAGE}" ] && [ -z "${ROOTFS_PATH}" ]; then
    echo "ERROR: must specify either 'image' (an image tag in the local docker daemon) or 'rootfs-path' (a directory on disk)." >&2
    exit 2
fi

# paths_overlap A B: true if A and B (physical paths) are the same
# directory or one contains the other.
paths_overlap() {
    case "${1%/}/" in "${2%/}/"*) return 0 ;; esac
    case "${2%/}/" in "${1%/}/"*) return 0 ;; esac
    return 1
}

# phys_path PATH: the physical absolute path PATH names, which need not
# exist yet. Walks it a component at a time from /: existing directories
# are resolved with pwd -P, and "." / ".." are applied to that physical
# path, which is what mkdir -p does with the directories it creates.
phys_path() {
    local p="$1" cur="/" rest comp
    case "${p}" in /*) ;; *) p="${PWD}/${p}" ;; esac
    rest="${p#/}/"
    while [ -n "${rest}" ]; do
        comp="${rest%%/*}"
        rest="${rest#*/}"
        case "${comp}" in
            ""|.) ;;
            ..) cur="${cur%/*}"; [ -n "${cur}" ] || cur="/" ;;
            *)
                if [ -d "${cur%/}/${comp}" ]; then
                    cur="$(cd "${cur%/}/${comp}" && pwd -P)"
                else
                    cur="${cur%/}/${comp}"
                fi ;;
        esac
    done
    printf '%s\n' "${cur}"
}

# In rootfs_path mode the reports stay out of the scanned tree, and the
# tree out of the reports dir, so the orb doesn't write into the caller's
# tree. Checked before output-dir is created, so a refused scan hasn't
# already made a directory inside the tree. The comparison is by physical
# path: a bind-mount alias of the tree that the caller set up themselves
# is not detected (the scanner never sees output-dir either way).
if [ -n "${ROOTFS_PATH}" ] && [ -d "${ROOTFS_PATH}" ] \
        && paths_overlap "$(phys_path "${OUTPUT_DIR}")" "$(cd "${ROOTFS_PATH}" && pwd -P)"; then
    echo "ERROR: output-dir '${OUTPUT_DIR}' overlaps rootfs-path '${ROOTFS_PATH}'." >&2
    echo "       Keep the output dir outside the scanned tree (and vice versa)." >&2
    exit 2
fi

# This must follow the physical overlap check: never clean the caller's tree.
rm -f -- "${OUTPUT_DIR}/checklist-meta.json"
rm -f -- "${OUTPUT_DIR}/summary.txt.exit-code"
rm -f -- "${OUTPUT_DIR}/tailoring-meta.json"
rm -f -- "${OUTPUT_DIR}/checklist.ckl" "${OUTPUT_DIR}/checklist.cklb" \
    "${OUTPUT_DIR}/checklist.ckl.partial" "${OUTPUT_DIR}/checklist.cklb.partial" \
    "${OUTPUT_DIR}/checklist-meta.json.partial"
mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR_ABS="$(cd "${OUTPUT_DIR}" && pwd)"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

# --- image helpers ---------------------------------------------------------
# docker pull with retries. Registries and their token endpoints have
# transient timeouts that docker itself does not retry (it retries layer
# downloads only); a CI run once failed on a single cgr.dev token timeout.
pull_image() {
    local ref="$1" attempt
    for attempt in 1 2 3; do
        if docker pull "${ref}" >/dev/null; then
            return 0
        fi
        if [ "${attempt}" -lt 3 ]; then
            echo "    pull of ${ref} failed (attempt ${attempt}/3); retrying in $((attempt * 10))s" >&2
            sleep "$((attempt * 10))"
        fi
    done
    return 1
}
# Pull REF unless the local daemon already has it. For a digest-pinned ref
# a local copy is by definition the right content; a tag-only override is
# used as found locally, and the recorded image id says which one that was.
ensure_image() {
    local ref="$1" what="$2"
    if ! docker image inspect "${ref}" >/dev/null 2>&1; then
        echo "==> Pulling ${what}: ${ref}"
        if ! pull_image "${ref}"; then
            echo "ERROR: could not pull ${what} '${ref}' after 3 attempts." >&2
            exit 2
        fi
    fi
}
# Local image id. Store-dependent: the config digest on Docker's classic
# image store, the manifest/index digest on the containerd store. Every
# container below runs from this id, so the recorded id is the image that
# actually ran even if a tag moves mid-scan.
image_id() {
    docker image inspect --format '{{.Id}}' "$1"
}
# Registry digests (repo@sha256:...) the local image is known by, comma-
# separated. Empty for an image that never came from a registry (built or
# loaded locally). Always pass the image id captured by image_id, never the
# tag: a tag can be repointed by another pull between the two inspects, and
# the digests must describe the image that actually runs.
image_repo_digests() {
    docker image inspect --format '{{join .RepoDigests ","}}' "$1"
}
# Platform (os/arch[/variant]) of the local image, by captured id. A repo
# digest of a multi-platform index names the whole index; the index plus
# this platform identifies the one manifest (and binaries) that ran.
image_platform() {
    docker image inspect --format '{{.Os}}/{{.Architecture}}{{if .Variant}}/{{.Variant}}{{end}}' "$1"
}

# Every container this script starts runs with --network none: extraction,
# datastream donation, hashing and oscap-chroot all work on local files.
# The only network traffic in a scan is the Docker daemon's image pulls
# (README: "Info for security teams"). tests/container_isolation_test.sh
# enforces this.

DONOR_ID=""
DONOR_REPO_DIGESTS=""
DONOR_PLATFORM=""
DONOR_USED_FOR=""
resolve_donor() {
    if [ -z "${DONOR_ID}" ]; then
        ensure_image "${DONOR_IMAGE}" "helper image"
        DONOR_ID="$(image_id "${DONOR_IMAGE}")"
        DONOR_REPO_DIGESTS="$(image_repo_digests "${DONOR_ID}")"
        DONOR_PLATFORM="$(image_platform "${DONOR_ID}")"
    fi
    DONOR_USED_FOR="${DONOR_USED_FOR:+${DONOR_USED_FOR},}$1"
}

# has_nested_mounts DIR: 0 if a mount point sits strictly below DIR, 1 if
# none does, 2 if that can't be determined (no readable
# /proc/self/mountinfo, e.g. a non-Linux host, or awk failed). The kernel
# octal-escapes space, tab, newline and backslash in mount points (\040
# \011 \012 \134); decode every \ooo. DIR goes in via ENVIRON, not awk -v,
# which would interpret backslashes in it.
has_nested_mounts() {
    [ -r /proc/self/mountinfo ] || return 2
    STIG_MOUNT_ROOT="${1%/}/" awk '
        function unoct(s,   out, i, c) {
            out = ""
            while ((i = index(s, "\\")) > 0) {
                c = substr(s, i + 1, 3)
                if (c ~ /^[0-7][0-7][0-7]$/) {
                    out = out substr(s, 1, i - 1) sprintf("%c", substr(c, 1, 1) * 64 + substr(c, 2, 1) * 8 + substr(c, 3, 1))
                    s = substr(s, i + 4)
                } else {
                    out = out substr(s, 1, i)
                    s = substr(s, i + 1)
                }
            }
            return out s
        }
        BEGIN { root = ENVIRON["STIG_MOUNT_ROOT"] }
        { mp = unoct($5); m = (mp == "/") ? "/" : mp "/" }
        index(m, root) == 1 && m != root { found = 1; exit }
        END { exit !found }
    ' /proc/self/mountinfo
}

# --- 2. extract target rootfs (if image mode) ----------------------------
ROOTFS_DIR=""
CLEANUP_ROOTFS=0
CID=""
DATASTREAM_SNAP_DIR=""
TAILORING_SNAP_DIR=""
OUT_STAGE_DIR=""
ROOTFS_MOUNT=()
TARGET_IMAGE_ID=""
TARGET_REPO_DIGESTS=""
TARGET_PLATFORM=""

# Single cleanup trap, installed BEFORE any resource is created so an
# early failure (failed pull / create / export) can't leak the mktemp'd
# rootfs dir, the datastream snapshot, or a dangling create-only container.
cleanup() {
    if [ -n "${CID}" ]; then
        docker rm -f "${CID}" >/dev/null 2>&1 || true
    fi
    if [ -n "${DATASTREAM_SNAP_DIR}" ]; then
        rm -rf "${DATASTREAM_SNAP_DIR}" 2>/dev/null || true
        if [ -e "${DATASTREAM_SNAP_DIR}" ]; then
            echo "WARNING: could not remove the datastream snapshot ${DATASTREAM_SNAP_DIR}; remove it manually." >&2
        fi
    fi
    if [ -n "${TAILORING_SNAP_DIR}" ]; then
        rm -rf -- "${TAILORING_SNAP_DIR}" 2>/dev/null || true
    fi
    if [ -n "${OUT_STAGE_DIR}" ]; then
        rm -rf "${OUT_STAGE_DIR}" 2>/dev/null || true
        if [ -e "${OUT_STAGE_DIR}" ]; then
            echo "WARNING: could not remove the scanner output staging dir ${OUT_STAGE_DIR}; remove it manually." >&2
        fi
    fi
    if [ "${CLEANUP_ROOTFS}" = "1" ] && [ -n "${ROOTFS_DIR}" ] && [ -d "${ROOTFS_DIR}" ]; then
        # The extracted rootfs carries the image's original UIDs/GIDs, so
        # it likely contains root-owned files in restrictive directories
        # the host runner can't rm. Use the donor image (already pulled,
        # parameterizable for air-gap) as a root-privileged rm helper; the
        # host then only has to drop an empty directory.
        if [ -n "${DONOR_ID}" ]; then
            docker run --rm --network none -u 0:0 \
                -v "${ROOTFS_DIR}:/cleanup" \
                --entrypoint sh \
                "${DONOR_ID}" -c \
                'rm -rf /cleanup/* /cleanup/.[!.]* /cleanup/..?* 2>/dev/null || true' \
                >/dev/null 2>&1 || true
        fi
        rmdir "${ROOTFS_DIR}" 2>/dev/null || true
        if [ -e "${ROOTFS_DIR}" ]; then
            echo "WARNING: could not remove the scratch rootfs ${ROOTFS_DIR} (it holds root-owned files); remove it with root privileges." >&2
        fi
    fi
}
trap cleanup EXIT

if [ -n "${IMAGE}" ]; then
    if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
        echo "==> Image '${IMAGE}' not in local daemon, pulling..."
        if ! pull_image "${IMAGE}"; then
            echo "ERROR: image '${IMAGE}' not in local daemon and pull failed (3 attempts)." >&2
            echo "       Either pre-load it via image-tarball or ensure the tag is pullable." >&2
            exit 2
        fi
    fi
    TARGET_IMAGE_ID="$(image_id "${IMAGE}")"
    TARGET_REPO_DIGESTS="$(image_repo_digests "${TARGET_IMAGE_ID}")"
    TARGET_PLATFORM="$(image_platform "${TARGET_IMAGE_ID}")"
    # Pull the donor image first — we use it as a root-privileged tar
    # host so the extracted rootfs preserves the original numeric UID/
    # GID from the image. Host-side `tar -xf` running as the runner
    # cannot restore those, which silently changes ownership and breaks
    # ownership-based STIG rules (e.g. "/etc/shadow must be owned by
    # root"). The donor image is parameterized via PARAM_DONOR_IMAGE so
    # air-gap consumers point it at their mirror.
    resolve_donor extraction

    ROOTFS_DIR="$(mktemp -d -t stig-rootfs.XXXXXX)"
    CLEANUP_ROOTFS=1
    echo "==> Extracting rootfs of ${IMAGE} to ${ROOTFS_DIR} (preserving UID/GID)"
    # --entrypoint is overridden so `docker create` succeeds even on
    # images that ship no default CMD/ENTRYPOINT (e.g. cgr.dev/chainguard
    # /static). The container is never started, so the value is
    # cosmetic; we just need create to succeed so we can export it.
    CID="$(docker create --entrypoint /placeholder "${TARGET_IMAGE_ID}")"
    # Pipe the export tar into a docker container running as root, which
    # runs `tar -xf --numeric-owner` so the extracted tree carries the
    # image's original numeric UIDs/GIDs (not the runner's). tar restores
    # ownership by default when extracting as root, so --numeric-owner is
    # sufficient; we deliberately do NOT pass GNU tar's --same-owner here
    # because the donor image ships busybox tar, which rejects that flag
    # and would abort the extraction (and thus every image-mode scan).
    # --exclude='dev/*' skips device nodes (mknod can fail in some
    # rootless setups; SCAP probes don't read device nodes anyway).
    docker export "${CID}" | docker run --rm -i --network none -u 0:0 \
        -v "${ROOTFS_DIR}:/target" \
        --entrypoint tar \
        "${DONOR_ID}" \
        -C /target -xf - --numeric-owner --exclude='dev/*'
    # Container consumed; drop it now and clear CID so the EXIT trap
    # doesn't try to remove it again. The rootfs cleanup stays armed.
    docker rm "${CID}" >/dev/null 2>&1 || true
    CID=""
else
    if [ ! -d "${ROOTFS_PATH}" ]; then
        echo "ERROR: rootfs-path '${ROOTFS_PATH}' is not a directory." >&2
        exit 2
    fi
    # Physical path: a symlinked rootfs_path (e.g. /tmp/rootfs -> /) is
    # what Docker bind-mounts, so it is what must be checked; find would
    # not descend into a symlink given as its starting point.
    ROOTFS_DIR="$(cd "${ROOTFS_PATH}" && pwd -P)"
    # Scratch dirs (scanner output staging, datastream snapshot) come from
    # mktemp under TMPDIR; one inside the tree would write into it.
    case "$(phys_path "${TMPDIR:-/tmp}")/" in
        "${ROOTFS_DIR%/}/"*)
            echo "ERROR: TMPDIR ('${TMPDIR:-/tmp}') is inside rootfs-path '${ROOTFS_PATH}'; set TMPDIR outside the scanned tree." >&2
            exit 2 ;;
    esac
    # -v SRC:DST:ro makes mounts nested in SRC read-only only on kernels
    # >= 5.12 (best effort); on older ones they stay writable. If the tree
    # has nested mounts (a mounted VM disk with its own /boot or /var),
    # require a recursively read-only bind, which errors where unsupported.
    # Where it can't be told (rc 2), assume nested mounts: the explicit
    # form still works on any current Docker and fails closed elsewhere.
    nested_rc=0
    has_nested_mounts "${ROOTFS_DIR}" || nested_rc=$?
    if [ "${nested_rc}" -ne 1 ]; then
        case "${ROOTFS_DIR}" in
            *,*)
                echo "ERROR: rootfs-path '${ROOTFS_PATH}' may have nested mounts and has a comma in its path, which --mount can't express." >&2
                exit 2 ;;
        esac
        if [ "${nested_rc}" -eq 0 ]; then
            echo "==> rootfs-path has nested mounts; requiring a recursively read-only bind (Docker 25+, kernel 5.12+)"
        else
            echo "==> can't read /proc/self/mountinfo to look for nested mounts; requiring a recursively read-only bind (Docker 25+, kernel 5.12+)"
        fi
        ROOTFS_MOUNT=( --mount "type=bind,source=${ROOTFS_DIR},target=/target,readonly,bind-propagation=rprivate,bind-recursive=readonly" )
    else
        ROOTFS_MOUNT=( -v "${ROOTFS_DIR}:/target:ro" )
    fi
    # The scanner gets this tree bind-mounted read-only, and a read-only
    # mount still lets a process connect to a Unix socket inside it. A
    # live filesystem (rootfs_path: /, or a tree with /run bound into it)
    # can hold the Docker socket, which would hand the scanner the daemon.
    # Extracted image trees never contain sockets (tar skips them), so
    # refuse any, anywhere in the tree (proc/ and sys/ included: in an
    # arbitrary directory they are ordinary subtrees). Named pipes are an
    # IPC channel the same way, and device nodes too: ro is not nodev, and
    # Docker's default device rules allow ptys and the console (a live
    # tree with /dev/pts bound in). Image mode never extracts dev/ either.
    find_rc=0
    sock="$(find "${ROOTFS_DIR}" \( -type s -o -type p -o -type c -o -type b \) -print -quit 2>/dev/null)" || find_rc=$?
    if [ -z "${sock}" ] && [ "${find_rc}" -ne 0 ]; then
        # The runner couldn't read the whole tree (e.g. root-owned 0700
        # directories in a mounted VM disk), but the root scanner can, so
        # an empty result proves nothing. Repeat the check as root in the
        # helper image -- never in the scanner image the check protects --
        # and fail closed if that can't complete either. Plain POSIX find
        # options only, so any helper with a find works.
        echo "==> rootfs-path is not fully readable by this user; checking it for sockets, FIFOs and devices as root in the helper image"
        resolve_donor rootfs-check
        find_rc=0
        sock="$(docker run --rm --network none -u 0:0 "${ROOTFS_MOUNT[@]}" \
            --entrypoint find "${DONOR_ID}" /target \( -type s -o -type p -o -type c -o -type b \) -print)" || find_rc=$?
        sock="${sock%%$'\n'*}"
        if [ -z "${sock}" ] && [ "${find_rc}" -ne 0 ]; then
            echo "ERROR: could not check rootfs-path '${ROOTFS_PATH}' for sockets/FIFOs/devices as root" >&2
            echo "       (find in the helper image exited ${find_rc}; the helper image needs find)." >&2
            exit 2
        fi
        sock="${sock:+${ROOTFS_DIR%/}${sock#/target}}"
    fi
    if [ -n "${sock}" ]; then
        echo "ERROR: rootfs-path '${ROOTFS_PATH}' contains a socket, FIFO or device node: ${sock}" >&2
        echo "       Point rootfs-path at an offline extracted tree, not a live filesystem, and" >&2
        echo "       extract it without dev/ (tar --exclude='dev/*'); the scanner could use such a" >&2
        echo "       node through its read-only mount." >&2
        exit 2
    fi
fi

# --- 3. resolve target-base → (scanner, datastream, profile, family) -----
# Parse a single field out of an os-release-format file as DATA — never
# `source` it. The file is from the target image and could contain
# arbitrary shell if an attacker controls the build, which would execute
# on the CI host before the scanner container even starts.
parse_os_release_field() {
    local file="$1" key="$2"
    awk -F= -v k="${key}" '
        # match only KEY=value at line start; ignore blank/comment lines.
        $1 == k {
            v = substr($0, length(k) + 2)
            # strip optional surrounding double or single quotes
            if (v ~ /^".*"$/ || v ~ /^\047.*\047$/) {
                v = substr(v, 2, length(v) - 2)
            }
            print v
            exit
        }
    ' "${file}" 2>/dev/null
}
# Prints "<target_base> <source>", source being os-release or package-db
# (the filesystem-shape fallback).
# rootfs_has TEST ROOTFS_REAL PATH: PATH satisfies the file test
# once every symlink in it is resolved, and it resolves inside ROOTFS_REAL
# (the rootfs's physical path). Without the containment check an absolute
# symlink in the image (e.g. var/lib/dpkg/status.d -> /etc) would be
# tested against the CI host's filesystem.
rootfs_has() {
    local real
    real="$(readlink -f "$3" 2>/dev/null || true)"
    case "${real}" in
        "$2/"*) test "$1" "${real}" ;;
        *) return 1 ;;
    esac
}

detect_target_base() {
    local rootfs="$1"
    local id="" version_id="" has_osr=0 os_release=""
    local rootfs_real candidate candidate_real
    # A regular-file check on the leaf component alone isn't enough: any
    # *parent* directory (etc, usr, usr/lib) can itself be an absolute
    # symlink (e.g. rootfs/usr -> /usr) that redirects the whole path onto
    # the host filesystem while the leaf still looks like an ordinary
    # file. Canonicalize each candidate with the parent shell's own
    # symlink resolution (readlink -f) and only trust it if the result is
    # still inside the extracted rootfs.
    rootfs_real="$(cd "${rootfs}" && pwd -P)"
    # Strip a trailing slash so the "${rootfs_real}/"* containment pattern
    # below stays a single separator when rootfs_real is itself "/" (e.g.
    # rootfs-path: / to scan a mounted disk at the filesystem root) —
    # otherwise it would require a doubled "//" prefix that no real path
    # under /etc or /usr/lib ever has, rejecting every candidate.
    rootfs_real="${rootfs_real%/}"
    for candidate in "${rootfs}/etc/os-release" "${rootfs}/usr/lib/os-release"; do
        if [ -e "${candidate}" ] || [ -L "${candidate}" ]; then
            has_osr=1
        fi
        candidate_real="$(readlink -f "${candidate}" 2>/dev/null || true)"
        case "${candidate_real}" in
            "${rootfs_real}/"*)
                [ -z "${os_release}" ] && [ -f "${candidate_real}" ] && os_release="${candidate}"
                ;;
        esac
    done
    if [ -n "${os_release}" ]; then
        id="$(parse_os_release_field "${os_release}" ID)"
        version_id="$(parse_os_release_field "${os_release}" VERSION_ID)"
    fi
    case "${id}" in
        wolfi|chainguard) echo "wolfi os-release"; return ;;
        rhel)
            case "${version_id}" in
                10|10.*) echo "rhel10 os-release"; return ;;
                9|9.*)   echo "rhel9 os-release"; return ;;
                8|8.*)   echo "rhel8 os-release"; return ;;
            esac ;;
        rocky|almalinux|ol|oracle)
            case "${version_id}" in
                10|10.*) echo "rhel10 os-release"; return ;;
                9|9.*)   echo "rhel9 os-release"; return ;;
                8|8.*)   echo "rhel8 os-release"; return ;;
            esac ;;
        fedora) echo "fedora os-release"; return ;;
        debian)
            case "${version_id}" in
                12|12.*) echo "debian12 os-release"; return ;;
            esac ;;
        ubuntu)
            case "${version_id}" in
                22.04|22.04.*) echo "ubuntu2204 os-release"; return ;;
            esac ;;
    esac
    # If os-release was present but didn't match a supported entry,
    # treat that as authoritative — DO NOT fall through to filesystem
    # hints. Falling through would silently misclassify e.g. ubuntu
    # 24.04 as debian12 (because dpkg-status is present) and run the
    # wrong datastream / profile, producing misleading evidence.
    if [ "${has_osr}" = "1" ]; then
        # Surface the offending values via the function's stderr so the
        # caller can quote them in the user-facing error.
        printf 'unsupported os-release: ID=%q VERSION_ID=%q\n' "${id}" "${version_id}" >&2
        return 1
    fi
    # No os-release at all (e.g. distroless): use filesystem-shape hints
    # as the only available signal. A consumer who lands here on a
    # supported-but-unrecognized image should set target-base explicitly.
    # Each hint must resolve inside the rootfs, like os-release above.
    if rootfs_has -d "${rootfs_real}" "${rootfs}/lib/apk/db" \
            || rootfs_has -f "${rootfs_real}" "${rootfs}/sbin/apk"; then
        echo "wolfi package-db"; return
    fi
    if rootfs_has -d "${rootfs_real}" "${rootfs}/var/lib/rpm"; then
        echo "rhel9 package-db"; return
    fi
    # dpkg: a status file, or the distroless per-package status.d/ layout
    # (which step 3b turns into a status file in image mode).
    if rootfs_has -f "${rootfs_real}" "${rootfs}/var/lib/dpkg/status" \
            || rootfs_has -d "${rootfs_real}" "${rootfs}/var/lib/dpkg/status.d"; then
        echo "debian12 package-db"; return
    fi
    return 1
}

TARGET_BASE_REQUESTED="${TARGET_BASE}"
TARGET_BASE_SOURCE="parameter"
if [ "${TARGET_BASE}" = "auto" ]; then
    if ! detected="$(detect_target_base "${ROOTFS_DIR}")"; then
        echo "ERROR: could not auto-detect a supported target-base from the rootfs." >&2
        echo "       Either /etc/os-release is missing and no recognized package DB" >&2
        echo "       is present, or os-release names an OS/version this orb does not" >&2
        echo "       ship a default for. Set 'target-base' explicitly to one of:" >&2
        echo "         wolfi, debian12, ubuntu2204, rhel8, rhel9, rhel10, fedora" >&2
        exit 2
    fi
    TARGET_BASE="${detected% *}"
    TARGET_BASE_SOURCE="${detected#* }"
    echo "==> auto-detected target-base: ${TARGET_BASE} (from ${TARGET_BASE_SOURCE})"
fi

case "${TARGET_BASE}" in
    wolfi)
        SCANNER="${DEFAULT_CHAINGUARD_IMAGE}"
        DATASTREAM="ssg-chainguard-gpos-ds.xml"
        PROFILE="xccdf_basic_profile_.check"
        FAMILY="apk" ;;
    debian12)
        # No DISA STIG exists for Debian. CIS Level 1 Server (CIS Debian 12
        # Benchmark v1.1.0) is the most widely used benchmark with automated
        # content and evaluates ~7x the rules of the legacy ANSSI DAT-NT28
        # profile this used before 2.0. Known SSG 0.1.82 defect: its CIS
        # banner rules pass stock Debian banners on host trees
        # (ComplianceAsCode#15150; notapplicable in containers). See README.
        SCANNER="${DEFAULT_CHAINGUARD_IMAGE}"
        DATASTREAM="ssg-debian12-ds.xml"
        PROFILE="xccdf_org.ssgproject.content_profile_cis_level1_server"
        FAMILY="dpkg" ;;
    ubuntu2204)
        SCANNER="${DEFAULT_CHAINGUARD_IMAGE}"
        DATASTREAM="ssg-ubuntu2204-ds.xml"
        PROFILE="xccdf_org.ssgproject.content_profile_stig"
        FAMILY="dpkg" ;;
    rhel8)
        SCANNER="${DEFAULT_RPM_SCANNER_IMAGE}"
        DATASTREAM="ssg-rhel8-ds.xml"
        PROFILE="xccdf_org.ssgproject.content_profile_stig"
        FAMILY="rpm" ;;
    rhel9)
        SCANNER="${DEFAULT_RPM_SCANNER_IMAGE}"
        DATASTREAM="ssg-rhel9-ds.xml"
        PROFILE="xccdf_org.ssgproject.content_profile_stig"
        FAMILY="rpm" ;;
    rhel10)
        SCANNER="${DEFAULT_RPM_SCANNER_IMAGE}"
        DATASTREAM="ssg-rhel10-ds.xml"
        PROFILE="xccdf_org.ssgproject.content_profile_stig"
        FAMILY="rpm" ;;
    fedora)
        SCANNER="${DEFAULT_RPM_SCANNER_IMAGE}"
        DATASTREAM="ssg-fedora-ds.xml"
        PROFILE="xccdf_org.ssgproject.content_profile_standard"
        FAMILY="rpm" ;;
    *)
        echo "ERROR: unknown target-base '${TARGET_BASE}'." >&2
        exit 2 ;;
esac

[ -n "${SCANNER_IMAGE_OVERRIDE}" ] && SCANNER="${SCANNER_IMAGE_OVERRIDE}"
[ -n "${DATASTREAM_NAME_OVERRIDE}" ] && DATASTREAM="${DATASTREAM_NAME_OVERRIDE}"
[ -n "${PROFILE_ID_OVERRIDE}" ] && PROFILE="${PROFILE_ID_OVERRIDE}"
# A consumer-supplied file is what gets evaluated, whatever the default
# name for this target was; record its real name.
[ -n "${DATASTREAM_PATH_OVERRIDE}" ] && DATASTREAM="$(basename "${DATASTREAM_PATH_OVERRIDE}")"

echo "==> Scan plan"
echo "    target-base:   ${TARGET_BASE}"
echo "    scanner:       ${SCANNER}"
echo "    datastream:    ${DATASTREAM}"
echo "    profile:       ${PROFILE}"
echo "    output:        ${OUTPUT_DIR_ABS}"

# --- 3b. dpkg inventory availability and distroless synthesis ---------------------------------
# OpenSCAP's dpkginfo probe reads only <root>/var/lib/dpkg/status. Google
# distroless images record their packages as one stanza per file under
# /var/lib/dpkg/status.d/ (plus *.md5sums) and ship no status file, so every
# dpkg-backed check errors: package-removal rules come back `error`, not
# `pass`. In image mode the extracted rootfs is our scratch copy, so build
# the status file there from the stanzas. In rootfs_path mode the tree
# belongs to the caller and stays untouched; summarize warns instead.
# An absent, unreadable, non-regular, or out-of-tree status file cannot
# establish package absence, even when status.d/ is also absent.
# Recorded as dpkg_status=synthesized|missing in scan-plan.env, with the
# reason when the file could not be built.
DPKG_STATUS=""
DPKG_STATUS_PACKAGES=""
DPKG_STATUS_REASON=""
DPKG_STATUS_SOURCE=""
ROOTFS_REAL="$(cd "${ROOTFS_DIR}" && pwd -P)"
ROOTFS_REAL="${ROOTFS_REAL%/}"
if [ "${FAMILY}" = "dpkg" ] && rootfs_has -d "${ROOTFS_REAL}" "${ROOTFS_DIR}/var/lib/dpkg/status.d"; then
    DPKG_STATUS_SOURCE="/var/lib/dpkg/status.d"
fi
if [ "${FAMILY}" = "dpkg" ] && [ "${CLEANUP_ROOTFS}" = "1" ]; then
    # The helper decides whether to write the package database OpenSCAP
    # will read, so record it as a donor role in the provenance.
    resolve_donor dpkg-status
    # Decide and write inside the helper container, which sees only the
    # scratch rootfs: a symlinked var/lib/dpkg in the target image can't
    # redirect the write anywhere on the host, and the realpath check makes
    # sure the file lands where oscap-chroot will read it.
    #
    # Each stanza gets the Status line dpkg itself records for an installed
    # package when it is missing, and every stanza (the last one included)
    # ends in a blank line: the probe treats a final stanza with no
    # terminating blank line as a match for any package name.
    # One stanza per input file, normalized: CR stripped, a Status line
    # added after Package when absent, and a blank line after every stanza.
    # shellcheck disable=SC2016  # $0 and friends belong to awk
    stanza_awk='
        function flush(i) {
            if (n == 0) return
            for (i = 1; i <= n; i++) {
                print buf[i]
                if (i == pkg && !status) print "Status: install ok installed"
            }
            print ""
            n = 0; pkg = 0; status = 0
        }
        { sub(/\r$/, "") }
        /^[ \t]*$/ { flush(); next }
        {
            buf[++n] = $0
            if (!pkg && $0 ~ /^Package:/) pkg = n
            if ($0 ~ /^Status:/) status = 1
        }
        END { flush() }
    '
    dpkg_result="$(docker run --rm --network none -u 0:0 \
        -v "${ROOTFS_DIR}:/target" \
        -e STANZA_AWK="${stanza_awk}" \
        --entrypoint sh \
        "${DONOR_ID}" -c '
            set -eu
            d=/target/var/lib/dpkg
            if [ -e "$d/status" ] || [ -L "$d/status" ]; then
                case "$(readlink -f "$d/status" || true)" in
                    /target/*)
                        if [ -f "$d/status" ] && [ -r "$d/status" ]; then echo present; exit 0; fi
                        ;;
                esac
                echo unusable; exit 0
            fi
            if [ ! -d "$d/status.d" ]; then echo absent; exit 0; fi
            if [ "$(readlink -f "$d")" != "$d" ]; then echo symlinked; exit 0; fi
            # Build in container-private temporaries, never at a fixed
            # path in the image, where a planted symlink would redirect
            # the write. The one write into the rootfs is the final copy
            # to status, which was just checked to be absent.
            list="$(mktemp)"
            tmp="$(mktemp)"
            find "$d/status.d" -maxdepth 1 -type f ! -name "*.md5sums" | sort > "$list"
            while IFS= read -r f; do
                awk "$STANZA_AWK" "$f" >> "$tmp"
            done < "$list"
            count="$(grep -c "^Package:" "$tmp" || true)"
            if [ "${count:-0}" -eq 0 ]; then echo empty; exit 0; fi
            cp "$tmp" "$d/status"
            chmod 0644 "$d/status"
            echo "synthesized ${count}"
        ')"
    case "${dpkg_result}" in
        absent|unusable)
            DPKG_STATUS="missing"
            DPKG_STATUS_REASON="/var/lib/dpkg/status is absent or is not a readable regular file inside the rootfs"
            ;;
        synthesized\ *)
            DPKG_STATUS="synthesized"
            DPKG_STATUS_SOURCE="/var/lib/dpkg/status.d"
            DPKG_STATUS_PACKAGES="${dpkg_result#synthesized }"
            echo "==> Synthesized /var/lib/dpkg/status from status.d/ (${DPKG_STATUS_PACKAGES} packages) in the scratch rootfs"
            ;;
        empty)
            DPKG_STATUS="missing"
            DPKG_STATUS_SOURCE="/var/lib/dpkg/status.d"
            DPKG_STATUS_REASON="status.d/ holds no package stanzas"
            ;;
        symlinked)
            DPKG_STATUS="missing"
            DPKG_STATUS_REASON="/var/lib/dpkg is a symlink, which the orb does not write through"
            ;;
    esac
elif [ "${FAMILY}" = "dpkg" ]; then
    # The runner may not be able to read a mounted VM disk's root-owned
    # database. Inspect as root, like OpenSCAP, using the same recursively
    # read-only bind as the scanner. Never write to the caller's tree.
    resolve_donor dpkg-status
    # shellcheck disable=SC2016  # $d belongs to the helper container
    dpkg_result="$(docker run --rm --network none -u 0:0 "${ROOTFS_MOUNT[@]}" \
        --entrypoint sh "${DONOR_ID}" -c '
            set -eu
            d=/target/var/lib/dpkg
            case "$(readlink -f "$d/status" || true)" in
                /target/*)
                    if [ -f "$d/status" ] && [ -r "$d/status" ]; then echo present; exit 0; fi
                    ;;
            esac
            case "$(readlink -f "$d/status.d" || true)" in
                /target/*)
                    if [ -d "$d/status.d" ]; then echo missing-fragments; exit 0; fi
                    ;;
            esac
            echo missing
        ')"
    DPKG_STATUS_SOURCE=""
    case "${dpkg_result}" in
        present) ;;
        missing|missing-fragments)
            DPKG_STATUS="missing"
            DPKG_STATUS_REASON="/var/lib/dpkg/status is absent or unusable; the orb does not modify a rootfs_path tree"
            if [ "${dpkg_result}" = "missing-fragments" ]; then DPKG_STATUS_SOURCE="/var/lib/dpkg/status.d"; fi
            ;;
        *) echo "ERROR: unrecognized dpkg availability result: ${dpkg_result}" >&2; exit 2 ;;
    esac
fi
if [ "${DPKG_STATUS}" = "missing" ]; then
    echo "WARNING: the target has no usable /var/lib/dpkg/status (${DPKG_STATUS_REASON})." >&2
    echo "         OpenSCAP's dpkg probe reads only the status file, so package rules" >&2
    echo "         may error or evaluate false; package absence cannot be verified." >&2
fi

# --- 4. pull scanner image -----------------------------------------------
ensure_image "${SCANNER}" "scanner image"
SCANNER_ID="$(image_id "${SCANNER}")"
SCANNER_REPO_DIGESTS="$(image_repo_digests "${SCANNER_ID}")"
SCANNER_PLATFORM="$(image_platform "${SCANNER_ID}")"

# --- 5. acquire datastream -----------------------------------------------
# The Chainguard scanner ships datastreams inside its (immutable, digest-
# pinned) image; for non-RPM targets oscap-chroot reads
# /usr/share/xml/scap/ssg/content/<ds> there. Every other source is first
# copied into a private per-scan snapshot directory, and both the hash in
# step 6 and the scan read only that snapshot, so the recorded sha256 is
# the sha256 of the bytes oscap evaluated even if the original file changes
# mid-scan. RPM targets get the file donated from the Chainguard image (the
# compliance-operator scanner ships no content), fresh for every scan: a
# reused on-disk cache could be stale or modified and still be attributed
# to the pinned donor. Consumers can supply their own via datastream_path.

DATASTREAM_HOST_DIR=""
DATASTREAM_IN_SCANNER_PATH=""
DATASTREAM_SOURCE=""

# snapshot_datastream IMAGE_ID SRC [docker run args...]: copy SRC (a path
# inside IMAGE_ID's container) into a fresh snapshot dir as root, the user
# oscap-chroot runs as, so any file the scan could read can be snapshotted
# (e.g. a root-owned 0600 datastream_path written by an earlier root
# container). The copy is handed to the runner and made read-only.
snapshot_datastream() {
    local image="$1" src="$2"
    shift 2
    DATASTREAM_SNAP_DIR="$(mktemp -d -t stig-datastream.XXXXXX)"
    docker run --rm --network none -u 0:0 "$@" \
        -v "${DATASTREAM_SNAP_DIR}:/out" \
        -e SRC="${src}" \
        -e DS="${DATASTREAM}" \
        -e HOST_UID="${HOST_UID}" \
        -e HOST_GID="${HOST_GID}" \
        --entrypoint sh \
        "${image}" -c '
            set -e
            cp "${SRC}" "/out/${DS}"
            test -s "/out/${DS}"
            chown "${HOST_UID}:${HOST_GID}" "/out/${DS}"
            chmod 0444 "/out/${DS}"
        '
}

if [ -n "${DATASTREAM_PATH_OVERRIDE}" ]; then
    if [ ! -f "${DATASTREAM_PATH_OVERRIDE}" ]; then
        echo "ERROR: datastream-path '${DATASTREAM_PATH_OVERRIDE}' not found." >&2
        exit 2
    fi
    ds_src="$(cd "$(dirname "${DATASTREAM_PATH_OVERRIDE}")" && pwd)/$(basename "${DATASTREAM_PATH_OVERRIDE}")"
    echo "==> Using consumer-supplied datastream: ${DATASTREAM_PATH_OVERRIDE}"
    # The scanner image is the one image every scan has.
    if ! snapshot_datastream "${SCANNER_ID}" /src/datastream.xml \
        -v "${ds_src}:/src/datastream.xml:ro"; then
        echo "ERROR: could not read datastream-path '${DATASTREAM_PATH_OVERRIDE}' (or it is empty)." >&2
        exit 2
    fi
    DATASTREAM_SOURCE="datastream_path"
elif [ "${FAMILY}" != "rpm" ]; then
    # Non-RPM target families resolve to a Chainguard-shape scanner that
    # bundles every major datastream at /usr/share/xml/scap/ssg/content.
    # Key off FAMILY rather than a literal scanner-image match so that
    # air-gap consumers who set scanner-image to a mirror (e.g.
    # registry.local/openscap:latest-dev) still take this path instead
    # of falling into the donor flow and pulling the upstream Chainguard
    # image. If a consumer is mirroring a non-Chainguard-shape image for
    # a non-RPM target, they should set datastream-path explicitly.
    if [ -n "${TAILORING_FILE}" ]; then
        snapshot_datastream "${SCANNER_ID}" "/usr/share/xml/scap/ssg/content/${DATASTREAM}"
    fi
    DATASTREAM_IN_SCANNER_PATH="/usr/share/xml/scap/ssg/content/${DATASTREAM}"
    DATASTREAM_SOURCE="bundled"
    echo "==> Using datastream bundled inside scanner image (target family: ${FAMILY})"
else
    resolve_donor datastream
    DATASTREAM_SOURCE="donated"
    echo "==> Donating ${DATASTREAM} from ${DONOR_IMAGE}"
    snapshot_datastream "${DONOR_ID}" "/usr/share/xml/scap/ssg/content/${DATASTREAM}"
fi
if [ -n "${DATASTREAM_SNAP_DIR}" ]; then
    DATASTREAM_HOST_DIR="${DATASTREAM_SNAP_DIR}"
    DATASTREAM_IN_SCANNER_PATH="/ds/${DATASTREAM}"
fi

# --- 6. run oscap-chroot -------------------------------------------------
ds_mount_args=()
if [ -n "${DATASTREAM_HOST_DIR}" ]; then
    ds_mount_args=( -v "${DATASTREAM_HOST_DIR}:/ds:ro" )
fi
# Tailoring is copied once by the scanner's root user, just like a supplied
# datastream. The original file is never mounted during evaluation.
tailoring_mount_args=()
TAILORING_PATH=""
TAILORING_SHA256=""
TAILORING_META_SHA256=""
if [ -n "${TAILORING_FILE}" ]; then
    [ -f "${TAILORING_FILE}" ] || { echo "ERROR: tailoring_file is not a regular file: ${TAILORING_FILE}" >&2; exit 2; }
    tailoring_src="$(cd "$(dirname "${TAILORING_FILE}")" && pwd)/$(basename "${TAILORING_FILE}")"
    TAILORING_SNAP_DIR="$(mktemp -d -t stig-tailoring.XXXXXX)"
    docker run --rm --network none -u 0:0 \
        -v "${tailoring_src}:/src/tailoring.xml:ro" -v "${TAILORING_SNAP_DIR}:/out" \
        -e HOST_UID="${HOST_UID}" -e HOST_GID="${HOST_GID}" \
        --entrypoint sh "${SCANNER_ID}" -c '
            set -eu
            # Bound the snapshot before parsing; never copy a growing file unbounded.
            head -c 16777217 /src/tailoring.xml > /out/tailoring.xml
            test -s /out/tailoring.xml
            test "$(wc -c < /out/tailoring.xml)" -le 16777216
            chown "${HOST_UID}:${HOST_GID}" /out/tailoring.xml
            chmod 0444 /out/tailoring.xml
        '
    TAILORING_PATH="/tailoring/tailoring.xml"
    tailoring_mount_args=( -v "${TAILORING_SNAP_DIR}:/tailoring:ro" )
    python3 - "${TAILORING_SNAP_DIR}/tailoring.xml" "${DATASTREAM_HOST_DIR}/${DATASTREAM}" \
        "${PROFILE}" "${TAILORING_SNAP_DIR}/meta.json" <<'PY_TAILORING'
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET

X = "{http://checklists.nist.gov/xccdf/1.2}"
HREF_RULE = "https://www.cyber.mil/stigs/srg-stig-tools/"
HREF_VULN = "https://www.cyber.mil/stigs/srg-stig-tools#vulnerability_id"


def read_xml(path, cap):
    with open(path, "rb") as f:
        data = f.read(cap + 1)
    if not data or len(data) > cap:
        raise ValueError("empty or oversized XML input")
    # OpenSCAP's libxml and the runner's expat must see the same literal
    # content. Tailoring does not need DTDs or external entities.
    text = data.decode("utf-8-sig")
    encoding = re.search(r"<\?xml[^?]*encoding\s*=\s*[\"\']([^\"\']+)", text, re.I)
    if encoding and encoding.group(1).lower() not in ("utf-8", "utf8"):
        raise ValueError("tailoring/source XML must use UTF-8")
    if re.search(r"<!\s*(DOCTYPE|ENTITY)\b", text, re.I):
        raise ValueError("DTD/entity declarations are not supported")
    return data, ET.fromstring(text)


def indexed(elements):
    result = {}
    for el in elements:
        key = el.get("id")
        if not key or key in result:
            raise ValueError("missing or duplicate XCCDF id: " + str(key))
        result[key] = el
    return result


def prepare(tailoring_path, datastream_path, profile_id):
    raw, tailoring = read_xml(tailoring_path, 16 << 20)
    source, ds = read_xml(datastream_path, 128 << 20)
    if tailoring.tag != X + "Tailoring":
        raise ValueError("expected an XCCDF 1.2 Tailoring document")
    benches = list(ds.iter(X + "Benchmark"))
    if len(benches) != 1:
        raise ValueError("tailoring requires a datastream with exactly one Benchmark")
    bench = benches[0]
    links = tailoring.findall(X + "benchmark")
    if len(links) != 1 or not links[0].get("href"):
        raise ValueError("tailoring must name its source benchmark")
    if links[0].get("id") and links[0].get("id") != bench.get("id"):
        raise ValueError("tailoring names a different benchmark id")
    # href is a source label, never a resource to fetch. The explicit input
    # datastream is authoritative, and every idref below must resolve in it.
    local = indexed(tailoring.findall(X + "Profile"))
    original = indexed(bench.findall(X + "Profile"))
    if set(local) & set(original):
        raise ValueError("tailoring profile ids must not shadow benchmark profiles")
    if profile_id not in local:
        raise ValueError("profile_id must name a profile in the tailoring file")
    chain, seen = [], set()
    current = profile_id
    while current in local:
        if current in seen:
            raise ValueError("cyclic tailoring profile inheritance")
        seen.add(current)
        chain.append(local[current])
        current = local[current].get("extends")
    if current not in original:
        raise ValueError("tailored profile must extend an existing benchmark profile")
    base_profile = current
    ancestry = []
    while current:
        if current in seen or current not in original:
            raise ValueError("cyclic or unresolved benchmark profile inheritance")
        seen.add(current)
        ancestry.append(current)
        current = original[current].get("extends")
    rules = indexed(bench.iter(X + "Rule"))
    groups = indexed(bench.iter(X + "Group"))
    values = indexed(bench.iter(X + "Value"))
    selected, refined = {}, {}
    for profile in reversed(chain):
        duplicates = set()
        for el in profile:
            tag = el.tag[len(X) :] if el.tag.startswith(X) else el.tag
            if tag not in ("select", "set-value", "refine-value", "refine-rule"):
                continue
            rid = el.get("idref")
            if (tag, rid) in duplicates:
                raise ValueError("duplicate tailoring directive: " + str(rid))
            duplicates.add((tag, rid))
            if tag == "select":
                if rid not in rules and rid not in groups:
                    raise ValueError("tailoring selects an unknown rule/group: " + str(rid))
                flag = el.get("selected")
                if flag not in ("true", "false", "1", "0"):
                    raise ValueError("invalid tailoring selected flag")
                targets = [rid] if rid in rules else [r.get("id") for r in groups[rid].iter(X + "Rule")]
                for target in targets:
                    selected[target] = flag in ("true", "1")
            elif tag in ("set-value", "refine-value"):
                if rid not in values:
                    raise ValueError("tailoring refines an unknown value: " + str(rid))
                if tag == "set-value":
                    value = "".join(el.itertext())
                else:
                    matches = [
                        v for v in values[rid].findall(X + "value") if v.get("selector", "") == el.get("selector")
                    ]
                    if el.get("selector") is not None and len(matches) != 1:
                        raise ValueError("tailoring value selector does not resolve uniquely: " + str(rid))
                    value = "".join(matches[0].itertext()) if matches else None
                directives = refined.get(rid, {}).get("directives", []) + [
                    {
                        "profile_id": profile.get("id"),
                        "directive": tag,
                        "value": value,
                        "selector": el.get("selector"),
                        "operator": el.get("operator"),
                    }
                ]
                refined[rid] = {
                    "value": value,
                    "directive": tag,
                    "selector": el.get("selector"),
                    "operator": el.get("operator"),
                    "directives": directives,
                }
            elif rid not in rules and rid not in groups:
                raise ValueError("tailoring refines an unknown rule/group: " + str(rid))
    lines = []
    for rid in sorted(rules):
        refs = rules[rid].findall(X + "reference")
        svs = sorted({(r.text or "").strip() for r in refs if r.get("href") == HREF_RULE})
        vids = sorted({(r.text or "").strip() for r in refs if r.get("href") == HREF_VULN})
        lines.append(rid + "\t" + " ".join(svs) + "\t" + " ".join(vids))
    return {
        "schema": "stig-scanner-orb/tailoring/v1",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "datastream_sha256": hashlib.sha256(source).hexdigest(),
        "benchmark_id": bench.get("id"),
        "benchmark_version": bench.findtext(X + "version"),
        "benchmark_href": links[0].get("href"),
        "profile_id": profile_id,
        "profile_title": (
            " ".join("".join(local[profile_id].find(X + "title").itertext()).split())
            if local[profile_id].find(X + "title") is not None
            else profile_id
        ),
        "base_profile_id": base_profile,
        "base_profile_ancestry": ancestry,
        "references_sha256": hashlib.sha256("\n".join(lines).encode()).hexdigest(),
        "deselected_rules": sorted(rid for rid, flag in selected.items() if not flag),
        "values": refined,
    }


if __name__ == "__main__":
    try:
        meta = prepare(*sys.argv[1:4])
        encoded = (json.dumps(meta, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(encoded) > 16 << 20:
            raise ValueError("derived tailoring metadata exceeds 16 MiB")
        with open(sys.argv[4], "xb") as f:
            f.write(encoded)
    except (OSError, ValueError, ET.ParseError) as exc:
        print("ERROR: invalid tailoring: " + str(exc), file=sys.stderr)
        sys.exit(2)
PY_TAILORING
    # Validate with the exact OpenSCAP that will evaluate it, offline and before
    # any target evaluation. Schema errors and missing profiles fail closed.
    docker run --rm --network none -u 0:0 "${tailoring_mount_args[@]}" \
        --entrypoint oscap "${SCANNER_ID}" xccdf validate --skip-schematron "${TAILORING_PATH}"
    TAILORING_SHA256="$(sha256sum "${TAILORING_SNAP_DIR}/tailoring.xml" | awk '{print $1}')"
    TAILORING_META_SHA256="$(sha256sum "${TAILORING_SNAP_DIR}/meta.json" | awk '{print $1}')"
fi
# ${a[@]+"${a[@]}"}: an empty array is an unbound variable under set -u
# in bash < 4.4 (e.g. the macOS system bash used for local runs).
[ "${#ROOTFS_MOUNT[@]}" -gt 0 ] || ROOTFS_MOUNT=( -v "${ROOTFS_DIR}:/target:ro" )
# Verify RPM inventory through the scanner's own librpm, user and rootfs
# mount. A failed package probe is not evidence of absence.
RPM_STATUS=""
RPM_STATUS_PACKAGES=""
RPM_STATUS_REASON=""
if [ "${FAMILY}" = "rpm" ]; then
    # shellcheck disable=SC2016  # $packages belongs to the scanner container
    rpm_inventory="$(docker run --rm --network none -u 0:0 "${ROOTFS_MOUNT[@]}" \
        --entrypoint sh "${SCANNER_ID}" -c '
            set -eu
            if packages=$(rpm --root /target -qa --qf "%{NAME}\n"); then
                if [ -n "$packages" ]; then printf "%s\n" "$packages" | wc -l; exit 0; fi
            fi
            echo missing
        ')"
    case "${rpm_inventory}" in
        ""|*[!0-9]*|0)
            RPM_STATUS="missing"
            RPM_STATUS_REASON="the scanner could not query a nonempty RPM inventory through its read-only rootfs mount"
            echo "WARNING: ${RPM_STATUS_REASON}; package absence cannot be verified." >&2
            ;;
        *) RPM_STATUS="available"; RPM_STATUS_PACKAGES="${rpm_inventory}" ;;
    esac
fi
# The scanner writes into a fresh private dir, never into output-dir
# itself: output-dir is the caller's (it may be shared, hold sockets, or
# contain the scratch rootfs), and /out is the scanner's one writable
# mount. The two reports are copied out afterwards.
OUT_STAGE_DIR="$(mktemp -d -t stig-out.XXXXXX)"
mount_args=( "${ROOTFS_MOUNT[@]}" -v "${OUT_STAGE_DIR}:/out" ${ds_mount_args[@]+"${ds_mount_args[@]}"} ${tailoring_mount_args[@]+"${tailoring_mount_args[@]}"} )

# Hash the datastream as the scanner sees it: same image, same mount, same
# path and same user (root) as oscap-chroot below. The image's default user
# can be unprivileged (65532 in the Chainguard image) and unable to enter
# the snapshot directory (mktemp -d, mode 0700) that the root scan reads.
DATASTREAM_SHA256="$(docker run --rm --network none -u 0:0 ${ds_mount_args[@]+"${ds_mount_args[@]}"} \
    --entrypoint sha256sum "${SCANNER_ID}" "${DATASTREAM_IN_SCANNER_PATH}" 2>/dev/null \
    | awk '{print $1}')" || DATASTREAM_SHA256=""
case "${DATASTREAM_SHA256}" in
    *[!0-9a-f]*) DATASTREAM_SHA256="" ;;
esac
if [ "${#DATASTREAM_SHA256}" -ne 64 ]; then
    echo "WARNING: could not hash ${DATASTREAM_IN_SCANNER_PATH} inside the scanner image; datastream_sha256 will be empty." >&2
    DATASTREAM_SHA256=""
    if [ -n "${TAILORING_FILE}" ]; then
        echo "ERROR: a tailored scan requires a hashed datastream." >&2
        exit 2
    fi
fi

echo "==> Running oscap-chroot"
# Never allow files from an earlier invocation to make an otherwise
# output-less scanner run look successful.
rm -f "${OUTPUT_DIR_ABS}/results.xml" "${OUTPUT_DIR_ABS}/report.html"
set +e
docker run --rm --network none -u 0:0 \
    "${mount_args[@]}" \
    -e PROFILE="${PROFILE}" \
    -e DS_PATH="${DATASTREAM_IN_SCANNER_PATH}" \
    -e TAILORING_PATH="${TAILORING_PATH}" \
    -e HOST_UID="${HOST_UID}" \
    -e HOST_GID="${HOST_GID}" \
    --entrypoint /bin/sh \
    "${SCANNER_ID}" -c '
        set --
        if [ -n "${TAILORING_PATH}" ]; then
            set -- --tailoring-file "${TAILORING_PATH}"
        fi
        oscap-chroot /target xccdf eval "$@" \
            --profile "${PROFILE}" \
            --report /out/report.html \
            --results /out/results.xml \
            "${DS_PATH}"
        rc=$?
        chown "${HOST_UID}:${HOST_GID}" /out/report.html /out/results.xml 2>/dev/null || true
        # oscap exits 2 when the scan completed but at least one rule
        # failed. Treat that as success; the gate decision lives in the
        # summarize step.
        case "$rc" in
            0|2) exit 0 ;;
            *)   echo "ERROR: oscap-chroot exited $rc" >&2; exit "$rc" ;;
        esac
    '
oscap_rc=$?
set -e

if [ "${oscap_rc}" -ne 0 ]; then
    echo "ERROR: oscap-chroot failed (exit ${oscap_rc})." >&2
    exit "${oscap_rc}"
fi
# The scanner controlled the staging dir: copy only regular files. A
# symlink would be followed here, in the host namespace, and could pull
# any runner-readable file into the published artifacts.
for f in results.xml report.html; do
    src="${OUT_STAGE_DIR}/${f}"
    if [ -L "${src}" ] || { [ -e "${src}" ] && [ ! -f "${src}" ]; }; then
        echo "ERROR: the scanner left ${f} as something other than a regular file; not copying it." >&2
        exit 1
    fi
    if [ -s "${src}" ]; then
        cp "${src}" "${OUTPUT_DIR_ABS}/${f}"
    fi
done

if [ ! -s "${OUTPUT_DIR_ABS}/results.xml" ] || [ ! -s "${OUTPUT_DIR_ABS}/report.html" ]; then
    echo "ERROR: oscap-chroot reported success but did not produce non-empty results.xml and report.html." >&2
    exit 1
fi

if [ -n "${TAILORING_FILE}" ]; then
    cp -- "${TAILORING_SNAP_DIR}/meta.json" "${OUTPUT_DIR_ABS}/tailoring-meta.json"
fi

# --- 7. record what produced these reports ------------------------------
# summarize.sh turns this into the provenance block of summary.txt and
# provenance.json. One key=value per line; list values are comma-separated.
# *_image_id is the local, store-dependent id; *_repo_digests are the
# registry digests to cite.
{
    echo "target_base=${TARGET_BASE}"
    echo "target_base_requested=${TARGET_BASE_REQUESTED}"
    echo "target_base_source=${TARGET_BASE_SOURCE}"
    echo "scanner=${SCANNER}"
    echo "scanner_image_id=${SCANNER_ID}"
    echo "scanner_repo_digests=${SCANNER_REPO_DIGESTS}"
    echo "scanner_platform=${SCANNER_PLATFORM}"
    echo "datastream=${DATASTREAM}"
    echo "datastream_source=${DATASTREAM_SOURCE}"
    echo "datastream_sha256=${DATASTREAM_SHA256}"
    echo "results_sha256=$(sha256sum "${OUTPUT_DIR_ABS}/results.xml" | awk '{print $1}')"
    if [ -n "${DONOR_USED_FOR}" ]; then
        echo "donor_image=${DONOR_IMAGE}"
        echo "donor_image_id=${DONOR_ID}"
        echo "donor_repo_digests=${DONOR_REPO_DIGESTS}"
        echo "donor_platform=${DONOR_PLATFORM}"
        echo "donor_used_for=${DONOR_USED_FOR}"
    fi
    echo "profile=${PROFILE}"
    if [ -n "${TAILORING_FILE}" ]; then
        echo "tailoring_file=${TAILORING_FILE}"
        echo "tailoring_sha256=${TAILORING_SHA256}"
        echo "tailoring_profile=${PROFILE}"
        echo "tailoring_meta_sha256=${TAILORING_META_SHA256}"
    fi
    echo "family=${FAMILY}"
    if [ -n "${RPM_STATUS}" ]; then
        echo "rpm_status=${RPM_STATUS}"
        echo "rpm_status_packages=${RPM_STATUS_PACKAGES}"
        echo "rpm_status_reason=${RPM_STATUS_REASON}"
    fi
    if [ -n "${DPKG_STATUS}" ]; then
        echo "dpkg_status=${DPKG_STATUS}"
        echo "dpkg_status_packages=${DPKG_STATUS_PACKAGES}"
        echo "dpkg_status_reason=${DPKG_STATUS_REASON}"
        echo "dpkg_status_source=${DPKG_STATUS_SOURCE}"
    fi
    if [ -n "${IMAGE}" ]; then
        echo "image=${IMAGE}"
        echo "image_id=${TARGET_IMAGE_ID}"
        echo "image_repo_digests=${TARGET_REPO_DIGESTS}"
        echo "image_platform=${TARGET_PLATFORM}"
    else
        echo "rootfs_path=${ROOTFS_PATH}"
    fi
} > "${OUTPUT_DIR_ABS}/scan-plan.env"

echo "==> Scan complete. Outputs:"
ls -la "${OUTPUT_DIR_ABS}"
