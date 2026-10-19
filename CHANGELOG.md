# Changelog

All notable changes to the STIG Scanner Orb are documented here. Releases use
[Semantic Versioning](https://semver.org/).

## 2.0.0

This is a major release: scans that passed under 1.x can fail under 2.0.0.

### Added

- Offline Wolfi/Chainguard GPOS SRG V3R2 checklists from the exact pinned vendor
  datastream/profile: 198 native DISA rows, preserved CCIs and attributed vendor
  N/A rationale in both formats. Metadata fingerprints reject altered evidence;
  supplied reference revisions remain Not Reviewed when they differ. Site
  answers retain original evidence and automated finding gates stay independent.
  The Wolfi smoke now feeds STIG Manager and DISA CKLB schema validation.

- Generated, source-hash-verified checklist entry point that stays below Linux's
  single-argument limit when CircleCI launches the packed generator and guard.
  Maintainer checks enforce source equality and command-size headroom.

- Release-bound `checklist_answers` JSON for explicit site status/comments and
  appended evidence, plus literal N/A category wording overrides. Exact snapshot
  hashes, original verdicts/comments and decision history travel with both
  checklist formats; scan findings and gates remain independent. Strict bounded
  validation and pre-cleanup source protection reject unsafe or stale inputs.
- Opt-in `checklist_default_answers: container-host`, reviewed and hash-pinned
  for the RHEL 9 V2R9 manual entropy-gatherer requirement. User answers can
  supersede it while preserving both decisions; other releases and filesystem
  scans require explicit site answers.

- Offline `tailoring_file` support for both scanner paths, with profile
  validation, bounded immutable snapshots and hash-bound provenance. Complete
  DISA checklists retain explicitly deselected requirements as Not Reviewed,
  including partial many-to-one deselections, and record customized values
  in finding details. Stock profile identity and selection checks remain enforced.

- Bundled, checksum-pinned DISA reference data for each verified RHEL 8/9/10
  and Ubuntu 22.04 datastream: complete default checklists with official text,
  CCIs and manual-only rows, offline staging, source attribution and deterministic
  maintenance tooling. Missing or corrupt data fails generation.
- Check-text comparison against the content-matched bundle preserves automated
  verdicts across Rule ID revision changes only when the check is unchanged.
  Changed checks and unverified/mixed revisions remain Not Reviewed with the
  original evidence and comparison hashes retained.

- `stig_xccdf_path` accepts an offline DISA manual XCCDF or bounded ZIP to
  generate complete checklists with official text, CCIs and release identity.
  Validate structure, STIG identity, profile completeness and known release
  inventories. Manual-only/deselected rows and revision-mismatched results
  remain Not Reviewed; per-row and summary provenance records exact source
  hashes. Matching and newer-release RHEL 9 smoke jobs validate both formats.

- Record absent and unusable dpkg databases in both image and rootfs scans, checking rootfs availability with scanner-equivalent root privileges and read-only mounts. RPM inventory must also pass a nonempty query through the exact scanner; unavailable inventory skips checklist generation.
- Offline STIG Viewer `.ckl` and `.cklb` artifacts for verified pinned RHEL
  8/9/10 and Ubuntu 22.04 STIG profiles, with V-ID aggregation, derived N/A
  reasons, architecture-aware applicability, and per-row provenance.
- `generate_checklist` command, which the scan job runs between `scan` and
  `summarize`. Custom jobs can run it there too, passing the same `checklist`
  mode and `output_dir` to it and to `summarize`.
- `checklist` (`auto` / `require` / `none`), `checklist_formats`, and
  `checklist_asset_name`. The scan job and `generate_checklist` default to
  `auto`; standalone summarize defaults to `none`. SSG-only checklists omit
  CCIs and manual-only rows.
- Checklist metadata, summary/provenance reporting, result/file hash validation,
  pre-scan cleanup, and an always-run artifact guard.
  Ordinary evidence uploads even on failure; checklist uploads require a
  successful guard, with policy exits enforced afterwards. Missing dpkg
  databases skip checklists, dash-prefixed asset names remain literal through
  CircleCI substitution, and rootfs N/A wording supports VM and host assets.
- Fault-injection tests and CI validation with pinned STIG Manager parsers and
  DISA's CKLB schema.
- `machine_image` on the `scan` job picks the CircleCI machine image, passed
  through to the orb's machine executor alongside `resource_class`. The
  default stays `ubuntu-2404:current`.

### Breaking

- **`require_evaluated_rules` (new, default `true`).** `summarize` fails the
  job when zero rules evaluate to `pass`, `fail`, `fixed`, or `informational`.
  An all-`notapplicable` scan, which 1.x reported as a green build, is what a
  mis-dispatched scan produces (wrong `target_base`, a scanner missing the
  probe family the datastream needs). Set `require_evaluated_rules: false` on a
  job that intentionally records such a baseline; `summary.txt` records the
  opt-out.
- **`fail_on` replaces `fail_on_finding`, and takes a severity.** The gate
  fails the job on a non-ignored result on a rule at or above `high`, `medium`,
  or `low` (DISA CAT I, II, III), or on any severity with `info`. A rule whose
  severity the content doesn't state counts at every level. The default,
  `never`, keeps the gate off. Replace `fail_on_finding: true` with
  `fail_on: info` for the same behavior, and drop `fail_on_finding: false`.
  `summary.txt` records the setting as `fail-on: <level>` instead of
  `fail-on-finding: <true|false>`.
- **The finding gate also counts `error` and `unknown`.** Non-ignored `error`
  and `unknown` results now trip `fail_on` alongside `fail`. `ignore_findings`
  entries apply to them too.
- **`debian12` default profile is now CIS Level 1 Server**
  (`xccdf_org.ssgproject.content_profile_cis_level1_server`, CIS Debian 12
  Benchmark v1.1.0) instead of `anssi_np_nt28_high`. There is no DISA STIG for
  Debian, the ANSSI DAT-NT28 profile is the pre-2022 hand-curated predecessor
  of ANSSI-BP-028 v2.0, and against `debian:12-slim` it evaluated 19 rules
  versus 136 for CIS L1 Server. Expect more `fail` results on Debian targets.
  To keep the old behavior, set
  `profile_id: xccdf_org.ssgproject.content_profile_anssi_np_nt28_high`.
  CIS L1 is not a DISA-accepted STIG substitute; see the README for what it
  is, and for a known SSG 0.1.82 defect in its banner rules that affects
  `rootfs_path` scans of Debian hosts (container images are unaffected).
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
  the rootfs and records that in `summary.txt` / `provenance.json` (the
  helper also shows up as `donor.used_for: dpkg-status`);
  `rootfs_path` trees are left untouched and get a warning instead, as does
  an image whose file can't be built (no package stanzas in `status.d/`, or a
  symlinked `/var/lib/dpkg`). With no
  `/etc/os-release`, `target_base: auto` now also recognizes the `status.d/`
  layout as `debian12` (it previously failed to detect such images).
- Smoke coverage for `ubi9/ubi-minimal`, `ubi8/ubi-minimal` (CIS L1), and
  `gcr.io/distroless/cc-debian12` in both image and `rootfs_path` mode.
- Smoke coverage for RHEL 10 (`rhel10` has had none since 1.0.0).
  `ubi10/ubi` runs through `target_base: auto` and the RPM path. It checks
  that the pinned `ssg-rhel10-ds.xml` ships the DISA STIG for RHEL 10 as the
  `rhel10` default profile, and that the compliance-operator scanner reads
  RHEL 10's package database: 69 evaluated rules (63 pass, 6 fail), 0
  `error`. The README's measured table adds `ubi10/ubi` and
  `ubi10/ubi-minimal`.

- **"Info for security teams" README section**: every host a scan contacts
  (measured, including registry blob CDNs: Chainguard's Cloudflare R2 host and
  `cdn01.quay.io`), what each container can see, and what an air-gapped
  install needs per mode. Corrects the old air-gap note: `datastream_path`
  removes the Chainguard image only in `rootfs_path` mode, because image mode
  still uses it as the extraction helper.

### Changed

- Error and log messages name parameters as written in YAML (`rootfs_path`,
  `target_base`, `output_dir`, `image_tarball`, `datastream_path`,
  `fail_on`, ...) instead of hyphenated forms such as `rootfs-path`.
  Scripts that match these messages, such as `auto-detected target-base:`, need
  updating. Other than `fail-on:` (see Breaking), `summary.txt` field labels
  such as `target-base:` are unchanged.
- Warnings in the step log and on stderr start with `WARN:` instead of
  `WARNING:`, and a failed image pull attempt that will be retried is now a
  `WARN:` line. The policy failures that fail the build (`fail_on`,
  `require_evaluated_rules`, `checklist`, and the scan job's deferred gate) print
  `ERROR:` lines on stderr instead of `==>` lines on stdout. Scripts that match
  these messages need updating. `summary.txt` keeps its `WARNING:` lines.
- Every helper and scanner container now runs with `--network none`; a scan's
  only network traffic is the Docker daemon's image pulls. A test enforces it.
- A `rootfs_path` that contains a socket, FIFO or device node is refused (exit 2;
  extract trees without `dev/`). A
  read-only bind mount does not stop a process from connecting to a socket,
  so a live tree such as `/` would have exposed `/run/docker.sock` to the
  scanner. Extracted image trees never contain sockets. If the runner user
  can't read the whole tree, the check reruns as root in the helper image
  (`donor.used_for` gains `rootfs-check`) and fails closed if it can't finish.
  A symlinked `rootfs_path` is checked where it points.
- A `rootfs_path` that overlaps `output_dir` (either inside the other) is
  refused before `output_dir` is created, so the orb doesn't write into the
  caller's tree; so is a `TMPDIR` inside it, before any scratch dir is made.
  The comparison is by physical path; a bind-mount alias isn't detected.
- The scanner no longer mounts `output_dir`. It writes into a fresh private
  staging directory, its only writable mount, and the host copies
  `results.xml` and `report.html` out, refusing anything that isn't a
  regular file (a symlink would be followed on the host). A shared `output_dir` (`/tmp`, one
  holding sockets, one containing the scratch rootfs) is never exposed to
  it, and it `chown`s only the two files it writes.
- Mounts nested inside a `rootfs_path` are bound recursively read-only
  (`--mount …,bind-recursive=readonly`, Docker 25+ on kernel 5.12+), as is any
  `rootfs_path` whose mounts can't be inspected; the scan fails on hosts that
  can't, rather than leaving the submounts writable.
- The cleanup trap warns when it cannot remove the scratch rootfs, the
  datastream snapshot or the scanner output staging dir (e.g. the Docker daemon is gone, so the root-privileged
  removal helper can't run) instead of failing silently.
- Every helper and scanner container now runs from the resolved local image
  id, so the recorded image is the one that ran even if a tag moves mid-scan.
- Donated and `datastream_path` datastreams are copied into a private per-scan
  snapshot that both the hash and the scan read, so the recorded sha256 is the
  hash of the bytes `oscap` evaluated. The copy runs as root in a container,
  so a root-only `datastream_path` still works. The old `~/.cache` datastream cache is
  gone: a reused file could be stale or modified and still be attributed to
  the pinned donor.
- `provenance.json` records each image's `platform` (`os/arch`); the pinned
  Chainguard digest is a multi-platform index, so the digest alone does not
  say which build ran.
- Image pulls retry transient registry failures (3 attempts, 10 s / 20 s
  backoff).
- With `datastream_path` set, the recorded datastream name is the supplied
  file's name instead of the target's default name.

### Fixed

- Documentation no longer claims the RHEL host STIG yields 0 evaluated rules
  against a container. With current content it evaluates 49–70 rules against
  UBI 8/9 images, with real findings.
- The usage examples match the recipes CI tests. The extracted-filesystem
  example, renamed `scan-extracted-rootfs`, stages a full UBI 9 rootfs: the
  unpacked payload of a single RPM has no RPM database, so it evaluated no
  rules. The tarball example defines the job that builds the archive and
  attaches the workspace outside the project directory, where it no longer
  breaks the job's checkout.

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
