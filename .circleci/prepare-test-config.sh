#!/usr/bin/env bash
# Keep the integration matrix below CircleCI's compiled-config size limit.
# One smoke uses the complete packed orb. The remaining scans use an exact
# copy whose four staging bodies and artifact guard run identical checkout
# scripts. Checklist generation and every other command remain packed.
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
    walk(if type == "object" then
        with_entries(.key |= sub("^stig-scanner-orb/"; "matrix-stig-scanner-orb/"))
        else . end) |
    .orbs."stig-scanner-orb" = $orb |
    .orbs."matrix-stig-scanner-orb" = $orb |
    (.orbs."matrix-stig-scanner-orb".commands.generate_checklist.steps[] |
        select(.run.name | startswith("Stage bundled DISA reference ("))).run.command |=
        (capture("(?<alias>rhel8|rhel9|rhel10|ubuntu2204)").alias |
         "bash src/scripts/stig-data/" + . + ".sh") |
    (.orbs."matrix-stig-scanner-orb".jobs.scan.steps[] |
        select(.run.name? == "Guard checklist artifacts before upload")).run.command =
        "bash src/scripts/checklist.sh" |
    (.workflows[].jobs[]) |=
        if has("matrix-stig-scanner-orb/scan") then
            if ."matrix-stig-scanner-orb/scan".name == "smoke-rhel9" then
                ."stig-scanner-orb/scan" = ."matrix-stig-scanner-orb/scan" |
                del(."matrix-stig-scanner-orb/scan")
            else
                ."matrix-stig-scanner-orb/scan"."pre-steps" =
                    ["checkout"] + (."matrix-stig-scanner-orb/scan"."pre-steps" // [])
            end
        else . end
' > /tmp/stig-test-config.yml

# Prove the adapter changes only four staging bodies and the guard body.
# Generation still exercises packed product code in every scan. Matrix checkouts
# run before scans, including jobs that disable the production checkout step.
echo "Verifying adapter and full packed-orb smoke"
cmp \
    <(jq -S '.orbs."stig-scanner-orb" |
        del(.commands.generate_checklist.steps[0].run.command,
            .commands.generate_checklist.steps[1].run.command,
            .commands.generate_checklist.steps[2].run.command,
            .commands.generate_checklist.steps[3].run.command) |
        (.jobs.scan.steps[] | select(.run.name? == "Guard checklist artifacts before upload")).run |= del(.command)' /tmp/stig-test-config.yml) \
    <(jq -S '.orbs."matrix-stig-scanner-orb" |
        del(.commands.generate_checklist.steps[0].run.command,
            .commands.generate_checklist.steps[1].run.command,
            .commands.generate_checklist.steps[2].run.command,
            .commands.generate_checklist.steps[3].run.command) |
        (.jobs.scan.steps[] | select(.run.name? == "Guard checklist artifacts before upload")).run |= del(.command)' /tmp/stig-test-config.yml)
jq -e '[.orbs."matrix-stig-scanner-orb".jobs.scan.steps[] |
       select(.run.name? == "Guard checklist artifacts before upload") | .run.command] |
       . == ["bash src/scripts/checklist.sh"]' /tmp/stig-test-config.yml > /dev/null
jq -e '[.workflows[].jobs[] | select(has("stig-scanner-orb/scan"))] |
       length == 1' /tmp/stig-test-config.yml > /dev/null
jq -e '[.workflows[].jobs[] | select(has("matrix-stig-scanner-orb/scan")) |
       ."matrix-stig-scanner-orb/scan"."pre-steps"[0] == "checkout"] |
       length > 0 and all' /tmp/stig-test-config.yml > /dev/null
# Custom jobs also invoke reusable commands, rather than the orb scan job.
# They already checkout; reject any future adapter call lacking that preparation.
jq -e '[.jobs[] | select(any(.steps[] | objects | keys[]; startswith("matrix-stig-scanner-orb/"))) |
       .steps[0] == "checkout"] | length > 0 and all' /tmp/stig-test-config.yml > /dev/null
# Only the single full smoke may reference the production orb namespace.
jq -e '[(.jobs, .commands, .workflows) | .. | objects | keys[] |
        select(startswith("stig-scanner-orb/"))] |
       . == ["stig-scanner-orb/scan"]' /tmp/stig-test-config.yml > /dev/null
