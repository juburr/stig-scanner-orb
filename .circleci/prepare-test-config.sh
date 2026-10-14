#!/usr/bin/env bash
# Keep the integration matrix below CircleCI's compiled-config size limit.
# One smoke uses the complete packed orb. The remaining scans use an exact
# copy whose four staging commands run the same generated scripts from checkout.
set -euo pipefail
trap 'echo "Integration config preparation failed at line ${LINENO}" >&2' ERR
STIG_CI_PACKED="$(mktemp)"
STIG_CI_TEMPLATE="$(mktemp)"
trap 'rm -f -- "${STIG_CI_PACKED}" "${STIG_CI_TEMPLATE}"' EXIT

echo "Packing production orb"
circleci orb pack src/ > "${STIG_CI_PACKED}"
echo "Preparing matrix adapter"
yq -o=json '.' .circleci/test-deploy.yml > "${STIG_CI_TEMPLATE}"
yq -o=json '.' "${STIG_CI_PACKED}" | jq --slurpfile template "${STIG_CI_TEMPLATE}" '
    . as $orb |
    $template[0] |
    .orbs."stig-scanner-orb" = $orb |
    .orbs."matrix-stig-scanner-orb" = $orb |
    (.orbs."matrix-stig-scanner-orb".commands.checklist.steps[] |
        select(.run.name | startswith("Stage bundled DISA reference ("))).run.command |=
        (capture("(?<alias>rhel8|rhel9|rhel10|ubuntu2204)").alias |
         "bash src/scripts/stig-data/" + . + ".sh") |
    (.workflows[].jobs[]) |=
        if has("stig-scanner-orb/scan") and ."stig-scanner-orb/scan".name != "smoke-rhel9" then
            ."matrix-stig-scanner-orb/scan" = ."stig-scanner-orb/scan" |
            del(."stig-scanner-orb/scan") |
            ."matrix-stig-scanner-orb/scan"."pre-steps" =
                ["checkout"] + (."matrix-stig-scanner-orb/scan"."pre-steps" // [])
        else . end
' > /tmp/stig-test-config.yml

# Prove the orb adapter changes only four staging bodies. Matrix checkouts
# run before scans, including jobs that disable the production checkout step.
echo "Verifying adapter and full packed-orb smoke"
cmp \
    <(jq -S '.orbs."stig-scanner-orb" |
        del(.commands.checklist.steps[0].run.command,
            .commands.checklist.steps[1].run.command,
            .commands.checklist.steps[2].run.command,
            .commands.checklist.steps[3].run.command)' /tmp/stig-test-config.yml) \
    <(jq -S '.orbs."matrix-stig-scanner-orb" |
        del(.commands.checklist.steps[0].run.command,
            .commands.checklist.steps[1].run.command,
            .commands.checklist.steps[2].run.command,
            .commands.checklist.steps[3].run.command)' /tmp/stig-test-config.yml)
jq -e '[.workflows[].jobs[] | select(has("stig-scanner-orb/scan"))] |
       length == 1' /tmp/stig-test-config.yml > /dev/null
jq -e '[.workflows[].jobs[] | select(has("matrix-stig-scanner-orb/scan")) |
       ."matrix-stig-scanner-orb/scan"."pre-steps"[0] == "checkout"] |
       length > 0 and all' /tmp/stig-test-config.yml > /dev/null
