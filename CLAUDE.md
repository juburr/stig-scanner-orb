# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A CircleCI orb that runs OpenSCAP DISA STIG scans against container images and extracted filesystems. The user-facing surface is `juburr/stig-scanner-orb/scan` (a job) plus `scan` / `summarize` / `load_image` (commands).

## Local working notes

`docs/` is **gitignored on purpose** — it holds the planning trail (`implementation_plan.md`, `spike-results.md`, `chainguard_request.md`). Read these before significant changes; they document why two scanner images, why `oscap-chroot` not `oscap-docker`, why we don't fetch datastreams at runtime, and what the RHEL-host-STIG-on-container result actually means. Update them as decisions evolve, but never reference them from committed files (README, scripts, etc.) — those references would break for cloners.

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
- **RPM targets** (`rhel8`, `rhel9`, `rhel10`, `fedora`) → scanner is `quay.io/compliance-operator/openscap-ocp:1.3.6` (digest-pinned; `:latest` is the same April-2023 build). It has the `probe_rpminfo` family but ships no SCAP content. Before the scan, `scan.sh` "donates" the datastream by `docker run`-ing the Chainguard image with a one-shot `cp` into a host cache dir keyed by the donor's image id (`~/.cache/stig-scanner-orb/datastreams/<donor id>/`), then bind-mounts that into the compliance-operator scanner.

Both defaults are pinned by digest in exactly one place: `DEFAULT_CHAINGUARD_IMAGE` / `DEFAULT_RPM_SCANNER_IMAGE` at the top of `scan.sh` (the YAML `donor_image`/`scanner_image` defaults are `""`, meaning "use the pin"). `tests/pinned_refs_test.sh` fails if a pin loses its digest or the README's pinned-images table drifts from it. Bump procedure: README → "Updating the pinned images". Never reintroduce a floating default. Every container runs from the resolved local image id (`image_id`), and `scan-plan.env` / `provenance.json` record both that id (store-dependent: config digest on Docker's classic store, manifest/index digest on containerd) and the registry `repo_digests` — the latter is what evidence should cite.

This split exists because Chainguard built their `oscap` without `librpm` (Wolfi uses APK), so it silently returns `N/A` for every rpm-state rule. `quay.io/compliance-operator/openscap-ocp` has the rpm probes but no datastreams. They're complementary; neither alone is universal.

The dispatch table lives once in `src/scripts/scan.sh` (the big `case "${TARGET_BASE}"` block) — that's the source of truth.

## Architecture: scan flow

`oscap-chroot` against a host-extracted rootfs, *not* `oscap-docker`. This avoids `--pid=host` and bind-mounting the docker socket into the scanner.

1. Optional `docker load` of an image tarball (load-image.sh).
2. `docker create --entrypoint /placeholder` + `docker export | tar -xf - --exclude='dev/*'` → host tmpdir. The `--entrypoint` placeholder is required for distroless images that ship no default CMD; the container is never started so the value is cosmetic. `--exclude='dev/*'` is required because rootless tar can't `mknod` device nodes.
3. `target_base: auto` reads `/etc/os-release` from the extracted rootfs (parsed field-by-field with `awk` as untrusted data — never `source`d, because the file comes from the target image and could carry arbitrary shell), falling back to filesystem-shape hints (`apk` DB → wolfi, `rpm` DB → rhel9, dpkg `status` or distroless `status.d/` → debian12). `tests/detect_target_base_test.sh` covers the table without docker (stub `docker`/`circleci` on PATH). An os-release that's present but names an unsupported OS/version is authoritative and errors out; the filesystem-shape fallback only runs when there's no os-release at all (e.g. some distroless images).
4. dpkg family only: if the rootfs has `/var/lib/dpkg/status.d/` but no `status` (Google distroless), image mode synthesizes `status` from the stanzas *inside the donor container* (it sees only the scratch rootfs, so a hostile symlink can't redirect the write; a `readlink -f` check refuses a symlinked `var/lib/dpkg`). OpenSCAP's dpkginfo probe reads only `<root>/var/lib/dpkg/status` (`fopen` in `dpkginfo-helper.c`) and treats a final stanza with no trailing blank line as a match for *any* package name, so every synthesized stanza must end in a blank line. rootfs_path trees are never modified — they get `dpkg_status=missing` and a warning.
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

Inside the script, every `PARAM_*` env var goes through a `subst()` shim that calls `circleci env subst` if present, else passes through. This is what lets the scripts run locally as plain bash — no CircleCI runtime dependency for development.

When adding a parameter, edit four places: the command's `parameters:` block, the command's `environment:` block, the corresponding pass-through in `jobs/scan.yml`, and the script's variable read at the top.

## Pitfalls / non-obvious knowledge

- **`pre-steps` and `post-steps` are reserved orb job parameters.** Don't declare them — CircleCI auto-provides them on every orb job.
- **The RHEL host STIG against a container is mostly — not entirely — notapplicable.** With SSG 0.1.82 it evaluates the container-applicable subset (file permissions/ownership, package-removal, crypto policy, umask): ~70 of ~480 selected rules on `ubi9/ubi`, ~50 on `ubi8/ubi`, with real `fail` results. An older note here claimed "0 pass / 0 fail / ~485 N/A"; that is stale, and tests built on it failed (`smoke-rhel9` / `smoke-rhel8-auto` asserted a hollow scan and got 70 / 51 evaluated rules). The ~400 N/A rules are correct OpenSCAP behavior for host controls, not a scanner defect; don't add scanner-side workarounds — the right fix is a container tailoring file. A scan with **zero** evaluated rules is a different thing: it means mis-dispatch (wrong `target_base`, scanner missing a probe family, unreadable package DB), and `summarize.sh` fails it by default (`require_evaluated_rules: true`). Smoke jobs therefore run at the default gate (it is the non-hollow assertion) and assert `Evaluated rules > 0` plus the N/A baseline — never a `pass > N` threshold, which drifts with SSG content. `smoke-hollow` is the negative test: it forces `target_base: rhel9` onto a Wolfi image and asserts the gate fails closed.
- **`debian12` defaults to CIS Level 1 Server, not ANSSI.** No DISA STIG exists for Debian; 2.0.0 moved the default off the legacy `anssi_np_nt28_high` (19 evaluated rules on `debian:12-slim`) to `cis_level1_server` (136). The README's Debian 12 profile table has measured counts for all 13 profiles — refresh it when the pin moves.
- **Don't add backward-compat shims for the deleted `greet`/`hello` scaffolding.** It's gone; references to it should be deleted, not preserved.
- **Don't try to use `registry.access.redhat.com/ubi9/openscap` as a scanner default.** It's not anonymously pullable as of 2026; that's why we use `quay.io/compliance-operator/openscap-ocp` for RPM targets.
- **The CircleCI orb size limit is 8 MB packed.** Tailoring files inline cleanly (~5–20 KB). Full datastreams (~28 MB each) cannot be inlined — but we don't need to, because Chainguard's image bundles them.

## Tests

`.circleci/test-deploy.yml` runs a matrix of integration jobs, each driving the real `stig-scanner-orb/scan` job (so the machine executor and the load → scan → summarize → store_artifacts wiring are exercised, not just the commands): `smoke-wolfi` (real signal — pass and N/A both > 50 against `cgr.dev/chainguard/static`, the summary must not be a hollow scan, and `provenance.json` must record the pinned scanner digest and a hashed datastream), `smoke-gate` (verifies `fail_on_finding` + ignore-list exit codes), `test-scripts` (runs every `tests/*_test.sh`, no docker: summarize gate fixtures, provenance rendering, pinned-image refs), `smoke-ubuntu2204` and `smoke-debian12-auto` (dpkg probes; the latter also exercises `target_base: auto`), `smoke-rhel8-auto` and `smoke-rhel9` (the RPM path — compliance-operator scanner + datastream donation; `smoke-rhel8-auto` also exercises `target_base: auto` on the RPM family; both run at the default `require_evaluated_rules` gate and assert evaluated > 0 plus the host-STIG N/A baseline, never a pass count), `smoke-rhel9-cis` (the `profile_id` override — CIS Level 1, which unlike the host STIG profile yields evaluated pass/fail signal against a container), `smoke-fedora` (second RPM datastream/profile; dispatch + complete-output assertion, no count threshold), `smoke-hollow` (real-scanner negative test: a deliberately mis-dispatched scan must fail `require_evaluated_rules` and pass with the explicit opt-out), `smoke-ubi9-minimal` / `smoke-ubi8-minimal-cis` (ubi-minimal bases via `auto`; STIG and CIS L1 respectively; assert 0 `error`), `smoke-distroless-debian12` (dpkg status synthesis must happen and leave 0 `error`) and `smoke-distroless-rootfs` (the same layout via `rootfs_path` must stay unmodified and warn), `smoke-datastream-path` (`datastream_path` mode with the file in a 0700 directory: the hash container must run as root like the scan, or `datastream.sha256` is silently lost), `smoke-rootfs` (`rootfs_path` mode), and `smoke-tarball` (`image_tarball` load mode). Distroless pulls from `gcr.io`. RHEL/UBI targets pull from `registry.access.redhat.com` and fedora from `quay.io` to dodge Docker Hub anonymous pull-rate limits. All run on every push and gate publish; publish only fires on `v*` tags.

`rhel10` has **no** smoke job yet: RHEL 10 is new enough that the `stig` profile may not exist in `ssg-rhel10-ds.xml` (the orb still defaults `rhel10` → `content_profile_stig`). Before adding `smoke-rhel10`, confirm `oscap info ssg-rhel10-ds.xml` actually lists `content_profile_stig` — if it doesn't, that default in `scan.sh` is itself wrong and needs fixing first.

When debugging a scan-script change, the local end-to-end smoke against `cgr.dev/chainguard/static` is the fastest signal — finishes in ~20 s and exercises the full pipeline.
