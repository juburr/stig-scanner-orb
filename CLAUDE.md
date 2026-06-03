# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A CircleCI orb that runs OpenSCAP DISA STIG scans against container images and extracted filesystems. The user-facing surface is `juburr/stig-scanner-orb/scan` (a job) plus `scan` / `summarize` / `load-image` (commands).

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

- **Non-RPM targets** (`wolfi`, `debian12`, `ubuntu2204`) → scanner is `cgr.dev/chainguard/openscap:latest-dev`. It bundles every major datastream internally, so the scan points `oscap-chroot` at `/usr/share/xml/scap/ssg/content/<ds>` inside the scanner.
- **RPM targets** (`rhel8`, `rhel9`, `rhel10`, `fedora`) → scanner is `quay.io/compliance-operator/openscap-ocp:latest`. It has the `probe_rpminfo` family but ships no SCAP content. Before the scan, `scan.sh` "donates" the datastream by `docker run`-ing the Chainguard image with a one-shot `cp` into a host cache dir (`~/.cache/stig-scanner-orb/datastreams/`), then bind-mounts that into the compliance-operator scanner.

This split exists because Chainguard built their `oscap` without `librpm` (Wolfi uses APK), so it silently returns `N/A` for every rpm-state rule. `quay.io/compliance-operator/openscap-ocp` has the rpm probes but no datastreams. They're complementary; neither alone is universal.

The dispatch table lives once in `src/scripts/scan.sh` (the big `case "${TARGET_BASE}"` block) — that's the source of truth.

## Architecture: scan flow

`oscap-chroot` against a host-extracted rootfs, *not* `oscap-docker`. This avoids `--pid=host` and bind-mounting the docker socket into the scanner.

1. Optional `docker load` of an image tarball (load-image.sh).
2. `docker create --entrypoint /placeholder` + `docker export | tar -xf - --exclude='dev/*'` → host tmpdir. The `--entrypoint` placeholder is required for distroless images that ship no default CMD; the container is never started so the value is cosmetic. `--exclude='dev/*'` is required because rootless tar can't `mknod` device nodes.
3. `target-base: auto` reads `/etc/os-release` from the extracted rootfs (sourced via subshell, can't be skipped because shellcheck), falling back to filesystem-shape hints (`apk` DB → wolfi, `rpm` DB → rhel9, dpkg → debian12).
4. Run scanner via `docker run -v rootfs:/target:ro -v out:/out` → `oscap-chroot /target xccdf eval ... > /out/...`. Always `-u 0:0` inside; results get `chown`-ed back to host UID/GID at the end.
5. `summarize.sh` parses `results.xml` with Python's stdlib `xml.etree`, applies the ignore-list (matches against short DISA id, full XCCDF rule id, and any `<ident>` value — case-insensitive), and enforces `fail-on-finding` exit codes.

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
- **RHEL host STIG against a containerized RHEL image returns 0 pass / 0 fail / ~485 N/A.** This is correct, not a defect — most STIG rules check host services that don't exist in containers. Any future change that surfaces this as a "bug" or adds workarounds in the scanner code is wrong; the right fix lives in tailoring files (queued for v1.1).
- **Don't add backward-compat shims for the deleted `greet`/`hello` scaffolding.** It's gone; references to it should be deleted, not preserved.
- **Don't try to use `registry.access.redhat.com/ubi9/openscap` as a scanner default.** It's not anonymously pullable as of 2026; that's why we use `quay.io/compliance-operator/openscap-ocp` for RPM targets.
- **The CircleCI orb size limit is 8 MB packed.** Tailoring files inline cleanly (~5–20 KB). Full datastreams (~28 MB each) cannot be inlined — but we don't need to, because Chainguard's image bundles them.

## Tests

`.circleci/test-deploy.yml` runs two integration jobs: `smoke-wolfi` (asserts the scan produces real signal — pass and N/A counts both > 50 against `cgr.dev/chainguard/static`) and `smoke-gate` (verifies fail-on-finding + ignore-list exit codes). These run on every push; publish only fires on `v*` tags.

When debugging a scan-script change, the local end-to-end smoke against `cgr.dev/chainguard/static` is the fastest signal — finishes in ~20 s and exercises the full pipeline.
