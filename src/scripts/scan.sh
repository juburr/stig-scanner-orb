#!/usr/bin/env bash
# Run an OpenSCAP STIG scan against a container image or extracted rootfs.
#
# Flow:
#   1. Validate inputs (exactly one of image / rootfs-path).
#   2. If image mode: docker create + docker export the target rootfs to
#      a host temp dir.
#   3. Resolve target-base → (scanner-image, datastream, profile-id) by
#      auto-detection from /etc/os-release if needed.
#   4. For RPM-family targets, copy the datastream out of the Chainguard
#      openscap image (which bundles all major datastreams) and into a
#      cache dir. The compliance-operator scanner that ships rpm probes
#      doesn't bundle SCAP content, so we donate it from Chainguard.
#   5. Pull the resolved scanner image (cacheable).
#   6. Run oscap-chroot inside the scanner against the extracted rootfs,
#      writing report.html + results.xml to the output dir.

set -euo pipefail

# --- env-substitution shim: works in CircleCI and locally -----------------
subst() {
    if command -v circleci >/dev/null 2>&1; then
        circleci env subst "$1"
    else
        echo "$1"
    fi
}

IMAGE="$(subst "${PARAM_IMAGE:-}")"
ROOTFS_PATH="$(subst "${PARAM_ROOTFS_PATH:-}")"
TARGET_BASE="$(subst "${PARAM_TARGET_BASE:-auto}")"
SCANNER_IMAGE_OVERRIDE="$(subst "${PARAM_SCANNER_IMAGE:-}")"
DATASTREAM_NAME_OVERRIDE="$(subst "${PARAM_DATASTREAM_NAME:-}")"
DATASTREAM_PATH_OVERRIDE="$(subst "${PARAM_DATASTREAM_PATH:-}")"
PROFILE_ID_OVERRIDE="$(subst "${PARAM_PROFILE_ID:-}")"
OUTPUT_DIR="$(subst "${PARAM_OUTPUT_DIR:-build/stig}")"
DONOR_IMAGE="$(subst "${PARAM_DONOR_IMAGE:-cgr.dev/chainguard/openscap:latest-dev}")"

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

# --- 1. validate input shape ---------------------------------------------
if [ -n "${IMAGE}" ] && [ -n "${ROOTFS_PATH}" ]; then
    echo "ERROR: specify exactly one of 'image' or 'rootfs-path'." >&2
    exit 2
fi
if [ -z "${IMAGE}" ] && [ -z "${ROOTFS_PATH}" ]; then
    echo "ERROR: must specify either 'image' (an image tag in the local docker daemon) or 'rootfs-path' (a directory on disk)." >&2
    exit 2
fi

mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR_ABS="$(cd "${OUTPUT_DIR}" && pwd)"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

# --- 2. extract target rootfs (if image mode) ----------------------------
ROOTFS_DIR=""
CLEANUP_ROOTFS=0
CID=""

# Single cleanup trap, installed BEFORE any resource is created so an
# early failure (failed pull / create / export) can't leak the mktemp'd
# rootfs dir or a dangling create-only container.
cleanup() {
    if [ -n "${CID}" ]; then
        docker rm -f "${CID}" >/dev/null 2>&1 || true
    fi
    if [ "${CLEANUP_ROOTFS}" = "1" ] && [ -n "${ROOTFS_DIR}" ] && [ -d "${ROOTFS_DIR}" ]; then
        # The extracted rootfs carries the image's original UIDs/GIDs, so
        # it likely contains root-owned files in restrictive directories
        # the host runner can't rm. Use the donor image (already pulled,
        # parameterizable for air-gap) as a root-privileged rm helper; the
        # host then only has to drop an empty directory.
        if docker image inspect "${DONOR_IMAGE}" >/dev/null 2>&1; then
            docker run --rm -u 0:0 \
                -v "${ROOTFS_DIR}:/cleanup" \
                --entrypoint sh \
                "${DONOR_IMAGE}" -c \
                'rm -rf /cleanup/* /cleanup/.[!.]* /cleanup/..?* 2>/dev/null || true' \
                >/dev/null 2>&1 || true
        fi
        rmdir "${ROOTFS_DIR}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

if [ -n "${IMAGE}" ]; then
    if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
        echo "==> Image '${IMAGE}' not in local daemon, pulling..."
        if ! docker pull "${IMAGE}"; then
            echo "ERROR: image '${IMAGE}' not in local daemon and pull failed." >&2
            echo "       Either pre-load it via image-tarball or ensure the tag is pullable." >&2
            exit 2
        fi
    fi
    # Pull the donor image first — we use it as a root-privileged tar
    # host so the extracted rootfs preserves the original numeric UID/
    # GID from the image. Host-side `tar -xf` running as the runner
    # cannot restore those, which silently changes ownership and breaks
    # ownership-based STIG rules (e.g. "/etc/shadow must be owned by
    # root"). The donor image is parameterized via PARAM_DONOR_IMAGE so
    # air-gap consumers point it at their mirror.
    if ! docker image inspect "${DONOR_IMAGE}" >/dev/null 2>&1; then
        echo "==> Pulling extraction helper image ${DONOR_IMAGE}"
        docker pull "${DONOR_IMAGE}" >/dev/null
    fi

    ROOTFS_DIR="$(mktemp -d -t stig-rootfs.XXXXXX)"
    CLEANUP_ROOTFS=1
    echo "==> Extracting rootfs of ${IMAGE} to ${ROOTFS_DIR} (preserving UID/GID)"
    # --entrypoint is overridden so `docker create` succeeds even on
    # images that ship no default CMD/ENTRYPOINT (e.g. cgr.dev/chainguard
    # /static). The container is never started, so the value is
    # cosmetic; we just need create to succeed so we can export it.
    CID="$(docker create --entrypoint /placeholder "${IMAGE}")"
    # Pipe the export tar into a docker container running as root, which
    # runs `tar -xf --numeric-owner` so the extracted tree carries the
    # image's original numeric UIDs/GIDs (not the runner's). tar restores
    # ownership by default when extracting as root, so --numeric-owner is
    # sufficient; we deliberately do NOT pass GNU tar's --same-owner here
    # because the donor image ships busybox tar, which rejects that flag
    # and would abort the extraction (and thus every image-mode scan).
    # --exclude='dev/*' skips device nodes (mknod can fail in some
    # rootless setups; SCAP probes don't read device nodes anyway).
    docker export "${CID}" | docker run --rm -i -u 0:0 \
        -v "${ROOTFS_DIR}:/target" \
        --entrypoint tar \
        "${DONOR_IMAGE}" \
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
    ROOTFS_DIR="$(cd "${ROOTFS_PATH}" && pwd)"
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
detect_target_base() {
    local rootfs="$1"
    local id="" version_id="" has_osr=0 os_release=""
    # /etc/os-release is commonly an absolute symlink to
    # /usr/lib/os-release. Following that link on the host can read the
    # host's release file instead of the target's, so never open a symlink
    # here and explicitly try the canonical in-rootfs fallback.
    if [ -e "${rootfs}/etc/os-release" ] || [ -L "${rootfs}/etc/os-release" ]; then
        has_osr=1
    fi
    if [ ! -L "${rootfs}/etc/os-release" ] && [ -f "${rootfs}/etc/os-release" ]; then
        os_release="${rootfs}/etc/os-release"
    elif [ -f "${rootfs}/usr/lib/os-release" ]; then
        os_release="${rootfs}/usr/lib/os-release"
        has_osr=1
    fi
    if [ -n "${os_release}" ]; then
        id="$(parse_os_release_field "${os_release}" ID)"
        version_id="$(parse_os_release_field "${os_release}" VERSION_ID)"
    fi
    case "${id}" in
        wolfi|chainguard) echo wolfi; return ;;
        rhel)
            case "${version_id}" in
                10|10.*) echo rhel10; return ;;
                9|9.*)   echo rhel9; return ;;
                8|8.*)   echo rhel8; return ;;
            esac ;;
        rocky|almalinux|ol|oracle)
            case "${version_id}" in
                10|10.*) echo rhel10; return ;;
                9|9.*)   echo rhel9; return ;;
                8|8.*)   echo rhel8; return ;;
            esac ;;
        fedora) echo fedora; return ;;
        debian)
            case "${version_id}" in
                12|12.*) echo debian12; return ;;
            esac ;;
        ubuntu)
            case "${version_id}" in
                22.04|22.04.*) echo ubuntu2204; return ;;
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
    if [ -d "${rootfs}/lib/apk/db" ] || [ -f "${rootfs}/sbin/apk" ]; then
        echo wolfi; return
    fi
    if [ -d "${rootfs}/var/lib/rpm" ]; then
        echo rhel9; return
    fi
    if [ -f "${rootfs}/var/lib/dpkg/status" ]; then
        echo debian12; return
    fi
    return 1
}

if [ "${TARGET_BASE}" = "auto" ]; then
    if ! TARGET_BASE="$(detect_target_base "${ROOTFS_DIR}")"; then
        echo "ERROR: could not auto-detect a supported target-base from the rootfs." >&2
        echo "       Either /etc/os-release is missing and no recognized package DB" >&2
        echo "       is present, or os-release names an OS/version this orb does not" >&2
        echo "       ship a default for. Set 'target-base' explicitly to one of:" >&2
        echo "         wolfi, debian12, ubuntu2204, rhel8, rhel9, rhel10, fedora" >&2
        exit 2
    fi
    echo "==> auto-detected target-base: ${TARGET_BASE}"
fi

case "${TARGET_BASE}" in
    wolfi)
        SCANNER="cgr.dev/chainguard/openscap:latest-dev"
        DATASTREAM="ssg-chainguard-gpos-ds.xml"
        PROFILE="xccdf_basic_profile_.check"
        FAMILY="apk" ;;
    debian12)
        SCANNER="cgr.dev/chainguard/openscap:latest-dev"
        DATASTREAM="ssg-debian12-ds.xml"
        PROFILE="xccdf_org.ssgproject.content_profile_anssi_np_nt28_high"
        FAMILY="dpkg" ;;
    ubuntu2204)
        SCANNER="cgr.dev/chainguard/openscap:latest-dev"
        DATASTREAM="ssg-ubuntu2204-ds.xml"
        PROFILE="xccdf_org.ssgproject.content_profile_stig"
        FAMILY="dpkg" ;;
    rhel8)
        SCANNER="quay.io/compliance-operator/openscap-ocp:latest"
        DATASTREAM="ssg-rhel8-ds.xml"
        PROFILE="xccdf_org.ssgproject.content_profile_stig"
        FAMILY="rpm" ;;
    rhel9)
        SCANNER="quay.io/compliance-operator/openscap-ocp:latest"
        DATASTREAM="ssg-rhel9-ds.xml"
        PROFILE="xccdf_org.ssgproject.content_profile_stig"
        FAMILY="rpm" ;;
    rhel10)
        SCANNER="quay.io/compliance-operator/openscap-ocp:latest"
        DATASTREAM="ssg-rhel10-ds.xml"
        PROFILE="xccdf_org.ssgproject.content_profile_stig"
        FAMILY="rpm" ;;
    fedora)
        SCANNER="quay.io/compliance-operator/openscap-ocp:latest"
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

echo "==> Scan plan"
echo "    target-base:   ${TARGET_BASE}"
echo "    scanner:       ${SCANNER}"
echo "    datastream:    ${DATASTREAM}"
echo "    profile:       ${PROFILE}"
echo "    output:        ${OUTPUT_DIR_ABS}"

# --- 4. acquire datastream -----------------------------------------------
# Chainguard scanner ships datastreams internally; we point oscap-chroot at
# /usr/share/xml/scap/ssg/content/<ds>. compliance-operator scanner doesn't
# ship content, so we donate the file from the Chainguard image to a cache
# dir on the host and bind-mount it. Consumers can short-circuit both paths
# by setting datastream-path to a host-local file.

DATASTREAM_HOST_DIR=""
DATASTREAM_IN_SCANNER_PATH=""

if [ -n "${DATASTREAM_PATH_OVERRIDE}" ]; then
    if [ ! -f "${DATASTREAM_PATH_OVERRIDE}" ]; then
        echo "ERROR: datastream-path '${DATASTREAM_PATH_OVERRIDE}' not found." >&2
        exit 2
    fi
    DATASTREAM_HOST_DIR="$(cd "$(dirname "${DATASTREAM_PATH_OVERRIDE}")" && pwd)"
    DATASTREAM_IN_SCANNER_PATH="/ds/$(basename "${DATASTREAM_PATH_OVERRIDE}")"
    echo "==> Using consumer-supplied datastream: ${DATASTREAM_PATH_OVERRIDE}"
elif [ "${FAMILY}" != "rpm" ]; then
    # Non-RPM target families resolve to a Chainguard-shape scanner that
    # bundles every major datastream at /usr/share/xml/scap/ssg/content.
    # Key off FAMILY rather than a literal scanner-image match so that
    # air-gap consumers who set scanner-image to a mirror (e.g.
    # registry.local/openscap:latest-dev) still take this path instead
    # of falling into the donor flow and pulling the upstream Chainguard
    # image. If a consumer is mirroring a non-Chainguard-shape image for
    # a non-RPM target, they should set datastream-path explicitly.
    DATASTREAM_IN_SCANNER_PATH="/usr/share/xml/scap/ssg/content/${DATASTREAM}"
    echo "==> Using datastream bundled inside scanner image (target family: ${FAMILY})"
else
    DATASTREAM_HOST_DIR="${HOME}/.cache/stig-scanner-orb/datastreams"
    mkdir -p "${DATASTREAM_HOST_DIR}"
    if [ ! -f "${DATASTREAM_HOST_DIR}/${DATASTREAM}" ]; then
        echo "==> Donating ${DATASTREAM} from ${DONOR_IMAGE}"
        docker pull "${DONOR_IMAGE}" >/dev/null
        docker run --rm -u 0:0 \
            -v "${DATASTREAM_HOST_DIR}:/out" \
            -e DS="${DATASTREAM}" \
            -e HOST_UID="${HOST_UID}" \
            -e HOST_GID="${HOST_GID}" \
            --entrypoint sh \
            "${DONOR_IMAGE}" -c '
                set -e
                tmp="/out/.${DS}.tmp.$$"
                trap '\''rm -f "${tmp}"'\'' EXIT
                cp "/usr/share/xml/scap/ssg/content/${DS}" "${tmp}"
                test -s "${tmp}"
                chown "${HOST_UID}:${HOST_GID}" "${tmp}"
                chmod 0644 "${tmp}"
                mv -f "${tmp}" "/out/${DS}"
            '
    else
        echo "==> Reusing cached datastream at ${DATASTREAM_HOST_DIR}/${DATASTREAM}"
    fi
    DATASTREAM_IN_SCANNER_PATH="/ds/${DATASTREAM}"
fi

# --- 5. pull scanner image -----------------------------------------------
if ! docker image inspect "${SCANNER}" >/dev/null 2>&1; then
    echo "==> Pulling scanner image: ${SCANNER}"
    docker pull "${SCANNER}" >/dev/null
fi

# --- 6. run oscap-chroot -------------------------------------------------
mount_args=( -v "${ROOTFS_DIR}:/target:ro" -v "${OUTPUT_DIR_ABS}:/out" )
if [ -n "${DATASTREAM_HOST_DIR}" ]; then
    mount_args+=( -v "${DATASTREAM_HOST_DIR}:/ds:ro" )
fi

echo "==> Running oscap-chroot"
# Never allow files from an earlier invocation to make an otherwise
# output-less scanner run look successful.
rm -f "${OUTPUT_DIR_ABS}/results.xml" "${OUTPUT_DIR_ABS}/report.html"
set +e
docker run --rm -u 0:0 \
    "${mount_args[@]}" \
    -e PROFILE="${PROFILE}" \
    -e DS_PATH="${DATASTREAM_IN_SCANNER_PATH}" \
    -e HOST_UID="${HOST_UID}" \
    -e HOST_GID="${HOST_GID}" \
    --entrypoint /bin/sh \
    "${SCANNER}" -c '
        oscap-chroot /target xccdf eval \
            --profile "${PROFILE}" \
            --report /out/report.html \
            --results /out/results.xml \
            "${DS_PATH}"
        rc=$?
        chown -R "${HOST_UID}:${HOST_GID}" /out 2>/dev/null || true
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

if [ ! -s "${OUTPUT_DIR_ABS}/results.xml" ] || [ ! -s "${OUTPUT_DIR_ABS}/report.html" ]; then
    echo "ERROR: oscap-chroot reported success but did not produce non-empty results.xml and report.html." >&2
    exit 1
fi

# Persist the scan plan alongside results so summarize.sh / artifact
# consumers know what produced these reports.
{
    echo "target_base=${TARGET_BASE}"
    echo "scanner=${SCANNER}"
    echo "datastream=${DATASTREAM}"
    echo "profile=${PROFILE}"
    echo "family=${FAMILY}"
    if [ -n "${IMAGE}" ]; then
        echo "image=${IMAGE}"
    else
        echo "rootfs_path=${ROOTFS_PATH}"
    fi
} > "${OUTPUT_DIR_ABS}/scan-plan.env"

echo "==> Scan complete. Outputs:"
ls -la "${OUTPUT_DIR_ABS}"
