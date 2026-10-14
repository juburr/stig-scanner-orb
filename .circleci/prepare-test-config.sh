#!/usr/bin/env bash
# Keep the integration matrix below CircleCI's compiled-config size limit.
# One smoke uses the complete packed orb. The remaining scans use an exact
# copy whose four staging commands run the same generated scripts from checkout;
# scanner, generator, summary, job wiring and guards remain packed and identical.
set -euo pipefail
STIG_CI_PACKED="$(mktemp)"
STIG_CI_TEMPLATE="$(mktemp)"
trap 'rm -f -- "${STIG_CI_PACKED}" "${STIG_CI_TEMPLATE}"' EXIT
export STIG_CI_PACKED
circleci orb pack src/ > "${STIG_CI_PACKED}"
sed 's/stig-scanner-orb\//matrix-stig-scanner-orb\//g' .circleci/test-deploy.yml > "${STIG_CI_TEMPLATE}"
yq '.orbs."stig-scanner-orb" = load(env(STIG_CI_PACKED)) |
    .orbs."matrix-stig-scanner-orb" = load(env(STIG_CI_PACKED))' \
    "${STIG_CI_TEMPLATE}" > /tmp/stig-test-config.yml
for STIG_CI_ALIAS in rhel8 rhel9 rhel10 ubuntu2204; do
    export STIG_CI_STAGE_NAME="Stage bundled DISA reference (${STIG_CI_ALIAS})"
    export STIG_CI_STAGE_COMMAND="bash src/scripts/stig-data/${STIG_CI_ALIAS}.sh"
    yq -i '(.orbs."matrix-stig-scanner-orb".commands.checklist.steps[] |
            select(.run.name == env(STIG_CI_STAGE_NAME))).run.command = env(STIG_CI_STAGE_COMMAND)' \
        /tmp/stig-test-config.yml
done
# Keep one end-to-end scan on the actual published staging includes.
yq -i '(.workflows[].jobs[] |
        select(has("matrix-stig-scanner-orb/scan")) |
        select(."matrix-stig-scanner-orb/scan".name == "smoke-rhel9")) |=
        with_entries(.key = "stig-scanner-orb/scan")' /tmp/stig-test-config.yml

# Prove the adapter changes only the four staging command bodies.
cmp \
    <(yq -o=json '.orbs."stig-scanner-orb" |
        del(.commands.checklist.steps[0].run.command,
            .commands.checklist.steps[1].run.command,
            .commands.checklist.steps[2].run.command,
            .commands.checklist.steps[3].run.command)' /tmp/stig-test-config.yml | jq -S .) \
    <(yq -o=json '.orbs."matrix-stig-scanner-orb" |
        del(.commands.checklist.steps[0].run.command,
            .commands.checklist.steps[1].run.command,
            .commands.checklist.steps[2].run.command,
            .commands.checklist.steps[3].run.command)' /tmp/stig-test-config.yml | jq -S .)
yq -e '[.workflows[].jobs[] | select(has("stig-scanner-orb/scan"))] |
       length == 1' /tmp/stig-test-config.yml > /dev/null
