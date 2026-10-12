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
- **`summary.txt` layout.** It now states both gate settings and the evaluated
  rule count, always prints the `pass`/`fail`/`error`/`unknown`/
  `notapplicable`/`notchecked` rows (including zeros), and lists rules under
  separate `Fail`, `Error`, `Unknown`, and `Notchecked` headings. Scripts that
  parsed the old `Failures (...)` heading need updating.

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
