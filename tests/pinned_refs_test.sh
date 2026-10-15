#!/usr/bin/env bash
# The default scanner/donor images are pinned once, at the top of
# scan.sh. Check that every pin is a name:tag@sha256:<64 hex> reference,
# that the README lists each one verbatim, and that no floating default
# (a bare :latest / :latest-dev) has crept back into src/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCAN="${ROOT}/src/scripts/scan.sh"
README="${ROOT}/README.md"
failures=0

fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

refs="$(sed -n 's/^DEFAULT_[A-Z_]*_IMAGE="\(.*\)"$/\1/p' "${SCAN}")"
if [ -z "${refs}" ]; then
    fail "no DEFAULT_*_IMAGE pins found in ${SCAN}"
fi

for ref in ${refs}; do
    name_tag="${ref%@sha256:*}"
    digest="${ref##*@sha256:}"
    if [ "${name_tag}" = "${ref}" ]; then
        fail "${ref}: not pinned by digest"
        continue
    fi
    case "${name_tag}" in
        *:*) ;;
        *) fail "${ref}: keep the tag (name:tag@sha256:...) so readers can see what was pinned" ;;
    esac
    if [ "${#digest}" -ne 64 ] || [ -n "$(printf '%s' "${digest}" | tr -d '0-9a-f')" ]; then
        fail "${ref}: digest is not 64 lowercase hex characters"
    fi
    if ! grep -qF -- "${ref}" "${README}"; then
        fail "${ref}: README does not list this pin verbatim"
    fi
done

# Every openscap / openscap-ocp digest the README mentions anywhere (the
# air-gap mirroring example included) must be one of the current pins, so
# a bump can't leave a stale digest behind in the docs.
pinned_digests="$(printf '%s\n' "${refs}" | sed -n 's/.*@sha256:\([0-9a-f]*\)$/\1/p')"
while IFS= read -r digest; do
    [ -n "${digest}" ] || continue
    if ! printf '%s\n' "${pinned_digests}" | grep -qx "${digest}"; then
        fail "README mentions openscap digest ${digest}, which is not a current pin"
    fi
done < <(grep -oE 'openscap(-ocp)?[^@[:space:]`]*@sha256:[0-9a-f]{64}' "${README}" | sed 's/.*@sha256://' | sort -u)

# A quoted image default ending in a floating tag, e.g. "...:latest-dev".
if grep -rnE '(openscap:latest-dev|openscap-ocp:latest)"' "${ROOT}/src"; then
    fail "floating scanner/donor default found in src/ (see matches above)"
fi

if [ "${failures}" -ne 0 ]; then
    echo "${failures} pinned-ref check(s) failed." >&2
    exit 1
fi
echo "pinned refs ok: $(echo "${refs}" | wc -l | tr -d ' ') digest-pinned default image(s), all listed in README"

# Bundle identity and source ZIP pins must move with every datastream pin.
python3 - "${ROOT}" <<'PY_BUNDLE_PINS'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
script = root / 'src/scripts/checklist.sh'
code = script.read_text().split("<<'PY_CHECKLIST'\n", 1)[1].split('\nPY_CHECKLIST\n', 1)[0]
gen = {'__name__': 'pins'}
exec(compile(code, str(script), 'exec'), gen)
sources = json.loads((root / 'tools/stig-sources.json').read_text())
expected = {sha for sha, entry in gen['RELEASE_TABLE'].items() if entry[4].get('kind') != 'vendor-srg'}
assert set(gen['BUNDLE_TABLE']) == expected, 'bundle/datastream pin sets differ'
for sha, descriptor in gen['BUNDLE_TABLE'].items():
    data = gen['load_bundle'](sha, str(root / 'src/scripts/stig-data'))
    assert (data['version'], data['releaseinfo']) == gen['RELEASE_TABLE'][sha][3]
    source = sources[descriptor['alias']]
    assert data['source_sha256'] == source['sha256']
    assert data['source_path'] == source['url']
    assert data['credits'] == source['credits']
for sha, entry in gen['RELEASE_TABLE'].items():
    if entry[4].get('kind') == 'vendor-srg':
        assert gen['load_bundle'](sha, str(root / 'src/scripts/stig-data')) is None
        assert entry[:2] == (gen['GPOS_BENCHMARK'], '3.2.17')
        assert set(entry[2]) == {gen['GPOS_PROFILE']}
        identity = (gen['GPOS_STIG'][0], entry[3][0], entry[3][1].split()[1])
        count, inventory, releaseinfo = gen['STIG_INVENTORY'][identity]
        assert (count, inventory, releaseinfo) == (
            entry[4]['profiles'][gen['GPOS_PROFILE']]['vids'],
            entry[4]['reference']['inventory_sha256'], entry[3][1])
print('DISA pins ok: bundled releases/source ZIPs and native vendor reference inventory agree')
PY_BUNDLE_PINS
