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
if [ "${failures}" -ne 0 ]; then
    exit 1
fi
echo "container isolation ok: ${runs} docker run invocation(s), all --network none"
