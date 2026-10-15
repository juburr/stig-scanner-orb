# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A CircleCI orb that runs OpenSCAP DISA STIG scans against container images and extracted filesystems. The user-facing surface is `juburr/stig-scanner-orb/scan` (a job) plus `scan` / `checklist` / `summarize` / `load_image` (commands).

## Local working notes

`docs/` is **gitignored on purpose** — it holds the planning trail (`implementation_plan.md`, `spike-results.md`, `chainguard_request.md`). Read these before significant changes; they document why two scanner images, why `oscap-chroot` not `oscap-docker`, why we don't fetch datastreams at runtime, and what the RHEL-host-STIG-on-container result actually means. Update them as decisions evolve, but never reference them from committed files (README, scripts, etc.) — those references would break for cloners.

The exception is `docs/planning/`, which **is committed**: plans for work that spans several PRs, with their spike notes and research reports (`docs/planning/research_notes/` stays local; it holds raw notes and downloaded DISA files). Current plan: `docs/planning/stig-checklist/plan.md` (STIG Viewer `.ckl`/`.cklb` output with derived N/A justifications). Read it before touching checklist code, and update its status as PRs land. Keep user-facing docs (README, CHANGELOG) self-contained rather than pointing into `docs/planning/`.

## Common commands

```sh
shellcheck src/scripts/*.sh                                         # lint shell
circleci orb pack src/ > /tmp/packed-orb.yml                        # pack the orb
circleci orb validate /tmp/packed-orb.yml                           # validate packed orb

# end-to-end smoke (works locally, exact same scripts CI runs)
docker pull cgr.dev/chainguard/static:latest
PARAM_IMAGE=cgr.dev/chainguard/static:latest \
  PARAM_TARGET_BASE=auto \
  PARAM_OUTPUT_DIR=/tmp/orb-smoke \
  bash src/scripts/scan.sh
PARAM_OUTPUT_DIR=/tmp/orb-smoke bash src/scripts/summarize.sh
```

To validate `.circleci/test-deploy.yml` locally, splice the packed orb in first — `circleci config validate` can't see the dev-orb (it's only injected by `orb-tools/continue` at pipeline runtime):

```sh
python3 -c '
import yaml
packed = yaml.safe_load(open("/tmp/packed-orb.yml"))
cfg = yaml.safe_load(open(".circleci/test-deploy.yml"))
cfg["orbs"]["stig-scanner-orb"] = packed
yaml.safe_dump(cfg, open("/tmp/inlined.yml", "w"), default_flow_style=False, width=10000)
'
circleci config validate --skip-update-check /tmp/inlined.yml
```

## Architecture: the two-scanner dispatch

This is the single concept that touches every file:

- **Non-RPM targets** (`wolfi`, `debian12`, `ubuntu2204`) → scanner is `cgr.dev/chainguard/openscap:latest-dev` (digest-pinned, see below). It bundles every major datastream internally, so the scan points `oscap-chroot` at `/usr/share/xml/scap/ssg/content/<ds>` inside the scanner.
- **RPM targets** (`rhel8`, `rhel9`, `rhel10`, `fedora`) → scanner is `quay.io/compliance-operator/openscap-ocp:1.3.6` (digest-pinned; `:latest` is the same April-2023 build). It has the `probe_rpminfo` family but ships no SCAP content. Before the scan, `scan.sh` "donates" the datastream by `docker run`-ing the Chainguard image with a one-shot `cp` into a private per-scan snapshot dir (`mktemp -d`, removed by the EXIT trap), then bind-mounts that into the compliance-operator scanner. A `datastream_path` file is snapshotted the same way, by the scanner image as root (a host `cp` would reject a root-owned 0600 file the root scan can read). The hash and the scan both read the snapshot, so the recorded sha256 can't diverge from what oscap evaluated. There is deliberately **no persistent datastream cache**: a reused file could be stale or tampered and still be attributed to the pinned donor, and it only ever saved a ~1 s `cp`.

Both defaults are pinned by digest in exactly one place: `DEFAULT_CHAINGUARD_IMAGE` / `DEFAULT_RPM_SCANNER_IMAGE` at the top of `scan.sh` (the YAML `donor_image`/`scanner_image` defaults are `""`, meaning "use the pin"). `tests/pinned_refs_test.sh` fails if a pin loses its digest or the README's pinned-images table drifts from it. Bump procedure: README → "Updating the pinned images". Never reintroduce a floating default. Every container runs from the resolved local image id (`image_id`), and `scan-plan.env` / `provenance.json` record that id (store-dependent: config digest on Docker's classic store, manifest/index digest on containerd), the registry `repo_digests` (always looked up *by the captured id*, never the tag, so a concurrently repointed tag can't misattribute), and the `platform` (`os/arch`) — cite `repo_digests` + `platform`, since the Chainguard pin is a multi-arch index. All pulls go through `pull_image` (3 attempts, 10 s/20 s backoff): registry token/manifest timeouts are not retried by docker itself, and one flaked a CI run.

This split exists because Chainguard built their `oscap` without `librpm` (Wolfi uses APK), so it silently returns `N/A` for every rpm-state rule. `quay.io/compliance-operator/openscap-ocp` has the rpm probes but no datastreams. They're complementary; neither alone is universal.

The dispatch table lives once in `src/scripts/scan.sh` (the big `case "${TARGET_BASE}"` block) — that's the source of truth.

## Architecture: scan flow

`oscap-chroot` against a host-extracted rootfs, *not* `oscap-docker`. This avoids `--pid=host` and bind-mounting the docker socket into the scanner.

1. Optional `docker load` of an image tarball (load-image.sh).
2. `docker create --entrypoint /placeholder` + `docker export | tar -xf - --exclude='dev/*'` → host tmpdir. The `--entrypoint` placeholder is required for distroless images that ship no default CMD; the container is never started so the value is cosmetic. `--exclude='dev/*'` is required because rootless tar can't `mknod` device nodes.
3. `target_base: auto` reads `/etc/os-release` from the extracted rootfs (parsed field-by-field with `awk` as untrusted data — never `source`d, because the file comes from the target image and could carry arbitrary shell), falling back to filesystem-shape hints (`apk` DB → wolfi, `rpm` DB → rhel9, dpkg `status` or distroless `status.d/` → debian12). `tests/detect_target_base_test.sh` covers the table without docker (stub `docker`/`circleci` on PATH). An os-release that's present but names an unsupported OS/version is authoritative and errors out; the filesystem-shape fallback only runs when there's no os-release at all (e.g. some distroless images).
4. dpkg family only: if the rootfs has `/var/lib/dpkg/status.d/` but no `status` (Google distroless), image mode synthesizes `status` from the stanzas *inside the donor container* (it sees only the scratch rootfs, so a hostile symlink can't redirect the write off the host's scratch dir; a `readlink -f` check refuses a symlinked `var/lib/dpkg`, and temporaries live in the container's own `/tmp`, never at a fixed path in the image where a planted symlink could redirect the write onto another rootfs file). A `status.d/` with no package stanzas or a symlinked `var/lib/dpkg` records `dpkg_status=missing` plus `dpkg_status_reason` and warns. OpenSCAP's dpkginfo probe reads only `<root>/var/lib/dpkg/status` (`fopen` in `dpkginfo-helper.c`) and treats a final stanza with no trailing blank line as a match for *any* package name, so every synthesized stanza must end in a blank line. The helper run is recorded as `donor_used_for` role `dpkg-status`. rootfs_path trees are never modified — they get `dpkg_status=missing` and a warning. Auto-detection's filesystem-shape hints (`apk`/`rpm`/`dpkg` paths) go through `rootfs_has`, which only trusts a path that resolves inside the rootfs, as `os-release` does.
5. Run scanner via `docker run -v rootfs:/target:ro -v out:/out` → `oscap-chroot /target xccdf eval ... > /out/...`. Always `-u 0:0` inside; results get `chown`-ed back to host UID/GID at the end.
6. `summarize.sh` parses `results.xml` with Python's stdlib `xml.etree`, applies the ignore-list (matches against short DISA id, full XCCDF rule id, and any `<ident>` value — case-insensitive), and enforces `fail_on_finding` exit codes.

## YAML ↔ shell convention

Every command is a thin YAML wrapper around a script in `src/scripts/`. Pattern:

```yaml
- run:
    name: ...
    environment:
      PARAM_FOO: <<parameters.foo>>
    command: <<include(scripts/foo.sh)>>
```

Inside the script, every `PARAM_*` env var goes through a `subst()` shim that calls `circleci env subst -- "$1"` if present, else passes through. The `--` is required: values starting with a dash must not become CLI flags or help text. This is what lets the scripts run locally as plain bash — no CircleCI runtime dependency for development.

When adding a parameter, edit four places: the command's `parameters:` block, the command's `environment:` block, the corresponding pass-through in `jobs/scan.yml`, and the script's variable read at the top.

## Pitfalls / non-obvious knowledge

- **`orb-tools/review` RC009 fails any inline `run` command in `src/jobs` / `src/commands` longer than 64 characters.** Put it in `src/scripts/` and use `<<include(...)>>`. A failing review stops the setup workflow, so none of the test-deploy jobs run.
- **`pre-steps` and `post-steps` are reserved orb job parameters.** Don't declare them — CircleCI auto-provides them on every orb job.
- **The RHEL host STIG against a container is mostly — not entirely — notapplicable.** With SSG 0.1.82 it evaluates the container-applicable subset (file permissions/ownership, package-removal, crypto policy, umask): ~70 of ~480 selected rules on `ubi9/ubi` and `ubi10/ubi`, ~50 on `ubi8/ubi`, with real `fail` results. An older note here claimed "0 pass / 0 fail / ~485 N/A"; that is stale, and tests built on it failed (`smoke-rhel9` / `smoke-rhel8-auto` asserted a hollow scan and got 70 / 51 evaluated rules). The ~400 N/A rules are correct OpenSCAP behavior for host controls, not a scanner defect; don't add scanner-side workarounds — the checklist generator derives N/A reasons without deselecting host rules. A scan with **zero** evaluated rules is a different thing: it means mis-dispatch (wrong `target_base`, scanner missing a probe family, unreadable package DB), and `summarize.sh` fails it by default (`require_evaluated_rules: true`). Smoke jobs therefore run at the default gate (it is the non-hollow assertion) and assert `Evaluated rules > 0` plus the N/A baseline — never a `pass > N` threshold, which drifts with SSG content. `smoke-hollow` is the negative test: it forces `target_base: rhel9` onto a Wolfi image and asserts the gate fails closed.
- **`debian12` defaults to CIS Level 1 Server, not ANSSI.** No DISA STIG exists for Debian; 2.0.0 moved the default off the legacy `anssi_np_nt28_high` (19 evaluated rules on `debian:12-slim`) to `cis_level1_server` (136). The README's Debian 12 profile table has measured counts for all 13 profiles — refresh it when the pin moves, and re-check the README's known-defect note (ComplianceAsCode#15150: SSG 0.1.82's CIS banner rules false-pass stock Debian banners on host trees; `notapplicable` in containers). Don't describe CIS as a DISA-accepted STIG substitute: the Cloud Computing SRG allowance is for CSPs at IL2 only.
- **Every `docker run` uses `--network none`.** The README's security-teams section promises that a scan's only network traffic is the daemon's image pulls; `tests/container_isolation_test.sh` fails on any `docker run` without it. Nothing in the scan path needs the network (no `--fetch-remote-resources`; datastreams come from the pinned image). If you add a container, keep the flag — and if you add any network dependency, update the README egress table first. `scan.sh` also refuses a `rootfs_path` containing a socket, FIFO or device node (a read-only bind mount doesn't stop `connect()`, so a live tree with `/run/docker.sock` would hand the scanner the daemon). The host-side `find` is incomplete when the runner can't read part of the tree, so a non-zero exit with no hit reruns the check as root in the donor/helper image (never the scanner image), failing closed; `tests/container_isolation_test.sh` and `smoke-rootfs-socket` cover it. The scanner's only writable mount is a fresh `mktemp -d` staging dir (`/out`); never mount `output_dir` into it. A `rootfs_path` with nested mounts (per `/proc/self/mountinfo`), or where that can't be read, is bound with `--mount …,bind-recursive=readonly`, because `-v …:ro` leaves submounts writable on kernels < 5.12.
- **Don't add backward-compat shims for the deleted `greet`/`hello` scaffolding.** It's gone; references to it should be deleted, not preserved.
- **Don't try to use `registry.access.redhat.com/ubi9/openscap` as a scanner default.** It's not anonymously pullable as of 2026; that's why we use `quay.io/compliance-operator/openscap-ocp` for RPM targets.
- **The CircleCI orb size limit is 8 MB packed.** Tailoring files inline cleanly (~5–20 KB). Full datastreams (~28 MB each) cannot be inlined — but we don't need to, because Chainguard's image bundles them.

## Tests

`.circleci/test-deploy.yml` runs a matrix of integration jobs, each driving the real `stig-scanner-orb/scan` job (so the machine executor and the load → scan → summarize → store_artifacts wiring are exercised, not just the commands): `smoke-wolfi` (real signal — pass and N/A both > 50 against `cgr.dev/chainguard/static`, the summary must not be a hollow scan, and `provenance.json` must record the pinned scanner digest and a hashed datastream), `smoke-gate` (verifies `fail_on_finding` + ignore-list exit codes), `test-scripts` (runs every `tests/*_test.sh`, no docker: summarize gate fixtures, provenance rendering, pinned-image refs incl. README digest drift, `--network none` on every container), `smoke-ubuntu2204` and `smoke-debian12-auto` (dpkg probes; the latter also exercises `target_base: auto`), `smoke-rhel8-auto` and `smoke-rhel9` (the RPM path — compliance-operator scanner + datastream donation; `smoke-rhel8-auto` also exercises `target_base: auto` on the RPM family; both run at the default `require_evaluated_rules` gate and assert evaluated > 0 plus the host-STIG N/A baseline, never a pass count), `smoke-rhel10-auto` (RHEL 10 on `ubi10/ubi` via `auto`: the same RPM-path and gate assertions, plus the profile pinned to the DISA STIG for RHEL 10 and 0 `error`/`unknown`), `smoke-rhel9-cis` (the `profile_id` override — CIS Level 1, which unlike the host STIG profile yields evaluated pass/fail signal against a container), `smoke-fedora` (second RPM datastream/profile; dispatch + complete-output assertion, no count threshold), `smoke-hollow` (real-scanner negative test: a deliberately mis-dispatched scan must fail `require_evaluated_rules` and pass with the explicit opt-out), `smoke-rootfs-socket` (non-root runner, socket hidden in a root-owned 0700 dir of a `rootfs_path`: the root helper check must find it and the scan must exit 2), `smoke-ubi9-minimal` / `smoke-ubi8-minimal-cis` (ubi-minimal bases via `auto`; STIG and CIS L1 respectively; assert 0 `error`), `smoke-distroless-debian12` (dpkg status synthesis must happen and leave 0 `error`) and `smoke-distroless-rootfs` (the same layout via `rootfs_path` must stay unmodified and warn), `smoke-datastream-path` (`datastream_path` mode with a root-owned 0600 file the runner can't read: the snapshot copy must run as root like the scan, and provenance must record that file's sha256), `smoke-rootfs` (`rootfs_path` mode), and `smoke-tarball` (`image_tarball` load mode). Distroless pulls from `gcr.io`. RHEL/UBI targets pull from `registry.access.redhat.com` and fedora from `quay.io` to dodge Docker Hub anonymous pull-rate limits. All run on every push and gate publish; publish only fires on `v*` tags.

`smoke-rhel10-auto` is the only CI coverage for `rhel10`, and the compliance-operator scanner predates RHEL 10 (OpenSCAP 1.3.6 and rpm 4.14 on RHEL 8.7). It finds the target's rpmdb (`/usr/lib/sysimage/rpm`) only through RHEL 10's `/var/lib/rpm` compatibility symlink. An unreadable rpmdb doesn't show up as `error`s: SSG's RHEL Benchmark platform is an `rpminfo` test on `redhat-release`, so every rule goes `notapplicable` and the default `require_evaluated_rules` gate fails the job (measured by deleting the symlink from a ubi10 tree). The job also asserts that `ssg-rhel10-ds.xml` still ships `content_profile_stig` as the DISA STIG for RHEL 10; if a pin bump breaks that, the `rhel10` default in `scan.sh` is what's wrong, not the assertion.

When debugging a scan-script change, the local end-to-end smoke against `cgr.dev/chainguard/static` is the fastest signal — finishes in ~20 s and exercises the full pipeline.

## Checklist core

`src/scripts/checklist.sh` embeds the stdlib generator and artifact guard.
`RELEASE_TABLE` binds exact datastream hashes to benchmark/version, profiles,
selection/reference fingerprints, V-ID counts, unmapped allowlists and DISA
release identity. Never infer release identity from a profile title.
`tools/fingerprint-stig.py` verifies new pins against candidate DISA releases.
The scan job runs checklist between scan and summarize; summarize is the only
gatekeeper. Job/checklist defaults are `auto`, standalone summarize is `none`.

Cleanup invalidates meta first, following the physical overlap check in rootfs
mode. The always-run guard also receives rootfs_path to avoid modifying a tree
when scan refused overlapping output. Publication stages all formats, checks
parse-back, and commits meta last. Meta binds results and files by SHA-256.
The scan job uploads ordinary evidence individually before the guard; CKL/CKLB
use `when: on_success` after it. Summarize records policy exit status with
`defer_gate: true`, and `enforce-gate.sh` applies it after artifact upload.
Parsing and guard failures are never deferred. Keep standalone summarize at
`defer_gate: false`. Never restore a whole-output-dir upload after the guard.
A recorded `dpkg_status=missing` skips checklist generation, since package and
kernel platform conditions cannot establish absence without that database.
Rootfs N/A wording stays neutral: mounted VM disks and host trees are supported,
so a false host/firmware gate cannot imply a container-host relationship.
Shell string arguments use `--option=value` to prevent argparse treating
dash-prefixed values as options before stale-output invalidation.
`tests/checklist_test.py` loads production code, adding isolated release entries
only in tests. Consumer validators in `tools/checklist-validator/` are CI-only.

`stig_xccdf_path` supports a runner-readable DISA manual XCCDF or ZIP.
Snapshot bytes in bounded memory (16 MiB archive and member), hash the exact
XCCDF parsed and the source archive, never extract ZIP paths. STIG_INVENTORY
contains identifier-only fingerprints; refresh with tools/stig-inventory.py.
A skeleton supplies official metadata and all rows; any differing contributing
Rule ID revision becomes Not_Reviewed, retaining automated evidence. Known
release inventories and internal profile inventories are separate checks;
unknown releases report self-consistency only. Skeletons never waive scan
provenance, selected mapping, inventory or architecture checks. Without a
skeleton, SSG-only limits still apply. Answer files are not implemented. Manual STIG Viewer 3 import and ISSM
wording review remain release acceptance tasks.

## Tailoring

`scan.sh` snapshots `tailoring_file` through the root scanner, preflights bounded
UTF-8 XCCDF 1.2 XML and validates its schema with the exact scanner. Use
`--skip-schematron`: the pinned RPM scanner lacks tailoring schematron rules.
The chosen profile must be defined in the file and extend a benchmark profile.
`tailoring-meta.json` is derived from the same snapshots used by evaluation;
its SHA-256 and the original tailoring hash/profile are in scan-plan.env.
Conversion validates the complete Rule/DISA reference inventory against the
source snapshot rather than applying the stock selection fingerprint to a
custom profile. It still gates on the inherited STIG profile and pinned
benchmark/version. Tailored generation requires bundled or supplied DISA data:
additions can select mappings outside the stock release verification.
Explicit tailoring deselections withhold the whole V-ID verdict even when
another contributor ran. Preserve its evidence. Refined values use check-export
value ids and TestResult set-values. The caller's source is never reopened. Resolve `cluster-id` aliases by item type and expand them in the evaluated XML
(the pinned RPM OpenSCAP ignores value aliases). Bind original and evaluated
XML with separate hashes,
reject complex-value tailoring before evaluation (the pinned RPM OpenSCAP
cannot resolve it reliably), and follow benchmark profile ancestry to the
verified STIG base. The results parser also retains complex TestResult values
when supplied by other scan producers.
`tests/tailoring_test.py` loads the exact scan preflight and checklist generator;
`smoke-rhel9-tailoring` also feeds the consumer validators.

## Bundled DISA data

PR 3 defaults verified pins to full DISA metadata from generated
`src/scripts/stig-data/*.sh` includes. Only payload file paths enter BASH_ENV;
never put the base64 data into an env var or a YAML inline command. Local
checklist.sh reads sibling includes directly, while packed commands stage them
in private mktemp files. Staging errors leave an empty variable; generation
records failed meta and summarize remains the gatekeeper. Unknown datastreams
never borrow a bundle. BUNDLE_TABLE and RELEASE_TABLE key sets must agree.
`tools/refresh-stig-data.py` is maintainer-only: reviewed ZIP checksum pins in
`tools/stig-sources.json`, exact release/inventory checks, deterministic XZ
and JSON, per-command size guards, `--check` reproducibility. Consumer CI reproduces from source ZIPs.
Retain source credits and THIRD_PARTY_NOTICES.md when refreshing releases.
A user skeleton can retain a verdict across revisions only when every scanner
contributor cites the bundle's Rule ID and the parsed check text is identical.
Changed check text is Not_Reviewed even if a user file kept the same Rule ID;
error/architecture decisions stay unchanged. Unknown content retains PR 2's
conservative revision policy. Record source hashes and drift reasons per row.

CircleCI's compiled-config limit is lower than the packed-orb limit. The large
CI matrix uses `.circleci/prepare-test-config.sh`: it packs the actual orb, keeps
`smoke-rhel9` on the complete packed includes, and creates a second inline orb
that prepares checkout for staging and changes only the four bundle staging bodies to run their identical scripts
from checkout. It asserts that every other command, parameter, job and guard
is equal after removing the checkout preparation. The full packed smoke scans
without checkout, then checks out only for post-step assertions. All scan paths and both skeleton jobs still feed consumer validation.
Do not duplicate product implementation in the CI adapter or omit the full-orb
smoke. Every matrix job must checkout before bundle staging.
