#!/usr/bin/env bash
# A rootfs_path scan of a non-RPM target with no datastream_path and no
# tailoring_file leaves ds_mount_args and tailoring_mount_args empty, and
# scan.sh expands both for the datastream hash and the oscap-chroot run.
# Under set -u, bash before 4.4 treats an empty array as unset, so a plain
# "${a[@]}" aborts the scan with "unbound variable"; scan.sh expands them as
# ${a[@]+"${a[@]}"}. No docker: a stub answers the scanner image inspects,
# the hash and the scan, and flags any empty argument, which a fix like
# "${a[@]:-}" would pass on any bash. With bash 4.3 or older first on the
# PATH, the test also catches the abort.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
failures=0

fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

work="$(mktemp -d)"
trap 'rm -rf -- "${work}"' EXIT
mkdir -p "${work}/bin" "${work}/rootfs/etc" "${work}/out"
printf 'ID=wolfi\n' > "${work}/rootfs/etc/os-release"
image_id="sha256:$(printf 'a%.0s' {1..64})"
ds_sha256="$(printf 'c%.0s' {1..64})"

# The stub logs each call's arguments, one per line after a "--- docker"
# line, and an "EMPTY ARGUMENT in: docker ..." line for a call with an
# empty one.
cat > "${work}/bin/docker" <<EOF
#!/bin/sh
log="\$(dirname "\$0")/../docker.log"
echo "--- docker" >> "\${log}"
printf '%s\n' "\$@" >> "\${log}"
for arg in "\$@"; do
    if [ -z "\${arg}" ]; then
        echo "EMPTY ARGUMENT in: docker \$*" | head -n 1 >> "\${log}"
        break
    fi
done
case "\$1" in
    image)
        case "\${4:-}" in
            *.Id*) echo "${image_id}" ;;
            *RepoDigests*) echo "example.invalid/openscap@${image_id}" ;;
            *.Os*) echo "linux/amd64" ;;
        esac
        exit 0 ;;
    run)
        prev="" out="" entry=""
        for arg in "\$@"; do
            case "\${prev}" in
                -v) case "\${arg}" in *:/out) out="\${arg%:/out}" ;; esac ;;
                --entrypoint) entry="\${arg}" ;;
            esac
            prev="\${arg}"
        done
        case "\${entry}" in
            sha256sum) printf '%s  %s\n' "${ds_sha256}" "\${prev}" ;;
            /bin/sh)
                [ -n "\${out}" ] || exit 1
                echo '<Benchmark/>' > "\${out}/results.xml"
                echo '<html/>' > "\${out}/report.html" ;;
            *) exit 1 ;;
        esac
        exit 0 ;;
esac
exit 1
EOF
cat > "${work}/bin/circleci" <<'EOF'
#!/bin/sh
[ "$1 $2" = "env subst" ] && [ "$#" -eq 2 ] || exit 1
cat
EOF
chmod +x "${work}/bin/docker" "${work}/bin/circleci"

rc=0
PATH="${work}/bin:${PATH}" PARAM_ROOTFS_PATH="${work}/rootfs" PARAM_TARGET_BASE=wolfi \
    PARAM_OUTPUT_DIR="${work}/out" bash "${ROOT}/src/scripts/scan.sh" > "${work}/scan.log" 2>&1 || rc=$?
if [ "${rc}" -ne 0 ]; then
    fail "scan.sh exited ${rc}: $(tail -5 "${work}/scan.log")"
fi
if grep -q 'unbound variable' "${work}/scan.log"; then
    fail "scan.sh hit an unbound variable: $(grep 'unbound variable' "${work}/scan.log")"
fi
touch "${work}/docker.log"
if grep -q '^EMPTY ARGUMENT in: ' "${work}/docker.log"; then
    fail "$(grep '^EMPTY ARGUMENT in: ' "${work}/docker.log")"
fi
if grep -qE ':/(ds|tailoring):ro$' "${work}/docker.log"; then
    fail "the scan mounted a datastream or tailoring snapshot it does not have"
fi
# The hash comes from the docker run that expands the empty ds_mount_args.
if ! grep -qx "datastream_sha256=${ds_sha256}" "${work}/out/scan-plan.env" 2>/dev/null; then
    fail "scan-plan.env does not record the stub's datastream hash"
fi
if [ ! -s "${work}/out/results.xml" ]; then
    fail "the scan did not copy out results.xml"
fi

if [ "${failures}" -ne 0 ]; then
    echo "${failures} empty-mount scan check(s) failed." >&2
    exit 1
fi
echo "rootfs scan without datastream_path or tailoring_file ok: no empty docker arguments"
