# Changelog

All notable changes to the STIG Scanner Orb are documented here. Releases use
[Semantic Versioning](https://semver.org/).

## Unreleased — 2.0.0

This is a major release: scans that passed under 1.x can fail under 2.0.0.

### Breaking

- **`require_evaluated_rules` (new, default `true`).** `summarize` fails the
  job when zero rules evaluate to `pass`, `fail`, `fixed`, or `informational`.
  An all-`notapplicable` scan, which 1.x reported as a green build, is what a
  mis-dispatched scan produces (wrong `target_base`, a scanner missing the
  probe family the datastream needs). Set `require_evaluated_rules: false` on a
  job that intentionally records such a baseline; `summary.txt` records the
  opt-out.
- **`fail_on_finding` also counts `error` and `unknown`.** Non-ignored `error`
  and `unknown` results now trip the gate alongside `fail`. `ignore_findings`
  entries apply to them too.
- **`debian12` default profile is now CIS Level 1 Server**
  (`xccdf_org.ssgproject.content_profile_cis_level1_server`, CIS Debian 12
  Benchmark v1.1.0) instead of `anssi_np_nt28_high`. There is no DISA STIG for
  Debian, the ANSSI DAT-NT28 profile is the pre-2022 hand-curated predecessor
  of ANSSI-BP-028 v2.0, and against `debian:12-slim` it evaluated 19 rules
  versus 136 for CIS L1 Server. Expect more `fail` results on Debian targets.
  To keep the old behavior, set
  `profile_id: xccdf_org.ssgproject.content_profile_anssi_np_nt28_high`.
- **`summary.txt` layout.** It now states both gate settings and the evaluated
  rule count, always prints the `pass`/`fail`/`error`/`unknown`/
  `notapplicable`/`notchecked` rows (including zeros), and lists rules under
  separate `Fail`, `Error`, `Unknown`, and `Notchecked` headings. Scripts that
  parsed the old `Failures (...)` heading need updating.

### Added

- **Digest-pinned scanner and donor defaults.** The Chainguard openscap image
  (`latest-dev@sha256:f5e08bc1…`, SSG 0.1.82, OpenSCAP 1.4.4) and the
  compliance-operator scanner (`1.3.6@sha256:4c49e8c1…`) are pinned in one
  place in `scan.sh`, so an orb version always runs the same scanner and
  content. `scanner_image` / `donor_image` still override them; the
  `donor_image` default is now `""`, meaning the pin. The README documents the
  bump procedure, and a test keeps the README's pin table in sync.
- **Provenance.** `summary.txt` opens with a provenance block and `summarize`
  writes `provenance.json`: target image reference, registry digest and image
  id; requested and resolved `target_base` and how it was resolved; profile id
  and title; scanner and donor references, digests and image ids; the
  datastream name, source, sha256 (hashed inside the scanner), benchmark and
  SSG versions; the OpenSCAP version; scan start/end time. `scan-plan.env`
  carries the raw facts.

- **Distroless dpkg support.** Google distroless images keep dpkg metadata as
  per-package stanzas in `/var/lib/dpkg/status.d/`, which OpenSCAP's dpkg
  probe cannot read, so package rules came back `error`. In image mode the orb
  now builds `/var/lib/dpkg/status` from those stanzas in its scratch copy of
  the rootfs and records that in `summary.txt` / `provenance.json`;
  `rootfs_path` trees are left untouched and get a warning instead.
- Smoke coverage for `ubi9/ubi-minimal`, `ubi8/ubi-minimal` (CIS L1), and
  `gcr.io/distroless/cc-debian12` in both image and `rootfs_path` mode.

- **"Info for security teams" README section**: every host a scan contacts
  (measured, including registry blob CDNs: Chainguard's Cloudflare R2 host and
  `cdn01.quay.io`), what each container can see, and what an air-gapped
  install needs per mode. Corrects the old air-gap note: `datastream_path`
  removes the Chainguard image only in `rootfs_path` mode, because image mode
  still uses it as the extraction helper.

### Changed

- Every helper and scanner container now runs with `--network none`; a scan's
  only network traffic is the Docker daemon's image pulls. A test enforces it.
- Every helper and scanner container now runs from the resolved local image
  id, so the recorded image is the one that ran even if a tag moves mid-scan.
- Donated datastreams are cached per donor image id, so a cached file is
  never reused or attributed across donor images.
- With `datastream_path` set, the recorded datastream name is the supplied
  file's name instead of the target's default name.

### Fixed

- Documentation no longer claims the RHEL host STIG yields 0 evaluated rules
  against a container. With current content it evaluates 49–70 rules against
  UBI 8/9 images, with real findings.

## 1.0.0

Initial production release.

- Scan container images, image tarballs, and extracted root filesystems with
  `oscap-chroot`, without mounting the Docker socket into the scanner.
- Resolve Wolfi, Debian 12, Ubuntu 22.04, RHEL 8/9/10, and Fedora scan plans,
  including automatic target detection.
- Use RPM-capable OpenSCAP probes for RHEL-family targets with datastreams
  supplied from the Chainguard scanner image.
- Emit HTML, XCCDF XML, a human-readable summary, and the resolved scan plan as
  persistent CircleCI artifacts.
- Support optional failure gating, auditable ignore lists, profile overrides,
  air-gap image/datastream overrides, and standard `pre-steps`/`post-steps`.
- Exercise Wolfi, Debian/Ubuntu, RHEL 8/9, Fedora, and every input mode in the
  tag-gated release workflow before the production orb is published.
