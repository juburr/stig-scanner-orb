<div align="center">
  <img align="center" width="300" src="assets/logos/stig-scanner-orb-512px.png?v=2" alt="STIG Scanner Orb"><br />
  <h1>STIG Scanner Orb</h1>
  <i>A CircleCI orb that scans for DISA STIG findings using Chainguard's OpenSCAP scanner.</i><br /><br />
</div>

<!---
[![CircleCI Build Status](https://circleci.com/gh/juburr/stig-scanner-orb.svg?style=shield "CircleCI Build Status")](https://circleci.com/gh/juburr/stig-scanner-orb) [![CircleCI Orb Version](https://badges.circleci.com/orbs/juburr/stig-scanner-orb.svg)](https://circleci.com/developer/orbs/orb/juburr/stig-scanner-orb) [![GitHub License](https://img.shields.io/badge/license-MIT-lightgrey.svg)](https://raw.githubusercontent.com/juburr/stig-scanner-orb/master/LICENSE) [![CircleCI Community](https://img.shields.io/badge/community-CircleCI%20Discuss-343434.svg)](https://discuss.circleci.com/c/ecosystem/orbs)
--->


## 📖 Overview
This CircleCI orb uses the same process outlined by Chainguard in their [STIGs for Chainguard Containers](https://edu.chainguard.dev/chainguard/chainguard-images/features/image-stigs/) guide. I've extended it to work with other non-Wolfi operating systems such as UBI8, UBI9, Ubuntu, Debian, Fedora, and certain distroless images.

The orb includes optional failure gates, ignore lists to exclude findings from the failure gates, summarized outputs, and the ability to emit artifacts to use as ATO evidence or to attach to your container as in-toto attestations using Cosign.

Release notes, including the breaking changes in 2.0.0, are in [CHANGELOG.md](CHANGELOG.md).

## 🚀 Getting Started

```yaml
version: 2.1
orbs:
  stig-scanner-orb: juburr/stig-scanner-orb@2.0.0

workflows:
  scan:
    jobs:
      - stig-scanner-orb/scan:
          image: cgr.dev/chainguard/static:latest
          target_base: wolfi
```

That's enough to produce `report.html`, `results.xml`, and `summary.txt` as job artifacts. `fail_on_finding` is off by default, so evaluated `fail` results are reported without failing the build and you can triage a baseline before turning that gate on.

One gate is on by default: a scan in which **zero rules evaluate** to pass or fail fails the job (`require_evaluated_rules: true`). An all-`notapplicable` result is what you get from a mis-dispatched scan (wrong `target_base`, or a scanner without the probes the datastream needs), and before 2.0.0 that was a green build. See [Gates](#-gates).

## 🧰 What it does

1. (Optional) `docker load` an image tarball produced by an upstream job.
2. Host-extract the target image's rootfs via `docker create` + `docker export`. Skipped when you pass `rootfs_path` directly.
3. Resolve `target_base` to a scanner image, datastream, and XCCDF profile. `auto` reads `/etc/os-release` from the extracted rootfs.
4. For RPM-based targets, copy the right `ssg-*-ds.xml` out of the Chainguard openscap image (which bundles every major datastream) into a private per-scan snapshot directory. The compliance-operator scanner is purpose-built for `oscap-chroot` and ships no SCAP content of its own, so we donate the file from Chainguard.
5. Pull the resolved scanner image (pinned by digest) and run `oscap-chroot` against the extracted rootfs.
6. Parse `results.xml`, write `summary.txt` and `provenance.json`, apply the ignore-list, and enforce the gates.
7. `store_artifacts` runs unconditionally so the evidence is always retrievable, even on a failing gate.

`oscap-chroot` is preferred over `oscap-docker` because it doesn't require `--pid=host` or bind-mounting the docker socket into the scanner — the scanner reads a static rootfs the runner already extracted. That keeps the scan container as unprivileged as the rest of the pipeline.

## 🎯 Supported targets

| `target_base` | Scanner image | Datastream | Default profile |
|---|---|---|---|
| `wolfi` | Chainguard openscap | `ssg-chainguard-gpos-ds.xml` | Chainguard GPOS |
| `debian12` | Chainguard openscap | `ssg-debian12-ds.xml` | CIS Level 1 Server ([why](#debian-12-profiles)) |
| `ubuntu2204` | Chainguard openscap | `ssg-ubuntu2204-ds.xml` | DISA STIG |
| `rhel8` | compliance-operator openscap-ocp | `ssg-rhel8-ds.xml` | DISA STIG |
| `rhel9` | compliance-operator openscap-ocp | `ssg-rhel9-ds.xml` | DISA STIG |
| `rhel10` | compliance-operator openscap-ocp | `ssg-rhel10-ds.xml` | DISA STIG |
| `fedora` | compliance-operator openscap-ocp | `ssg-fedora-ds.xml` | standard |
| `auto` | resolved from `/etc/os-release` | resolved | resolved |

Both scanner images are pinned by digest; see [Reproducibility and provenance](#-reproducibility-and-provenance) for the exact references. The Chainguard image also serves as the donor for RPM datastreams and as the root-privileged extraction helper.

`auto` recognizes RHEL, Rocky, Alma, Oracle Linux, Fedora, Debian 12, Ubuntu 22.04, Wolfi, and Chainguard via the target's `/etc/os-release`, with filesystem-shape fallbacks (`apk`, `rpm`, `dpkg` including the distroless `status.d/` layout) for images that lack one. For `scratch` images that ship neither `/etc/os-release` nor a package database, set `target_base` explicitly.

Tested in CI against `ubi9/ubi`, `ubi9/ubi-minimal`, `ubi8/ubi`, `ubi8/ubi-minimal`, `gcr.io/distroless/cc-debian12`, `debian:12-slim`, `ubuntu:22.04`, `fedora`, and `cgr.dev/chainguard/static`.

### Debian 12 profiles

There is no DISA STIG for Debian. `ssg-debian12-ds.xml` (SSG 0.1.82 in the pinned image) ships 13 profiles, and since 2.0.0 the `debian12` default is **CIS Level 1 Server**. Rule results measured with the pinned content (distroless with its dpkg status synthesized, see below):

| Profile (`xccdf_org.ssgproject.content_profile_…`) | Title | Selected rules | `debian:12-slim` pass / fail (evaluated) | `distroless/cc-debian12` pass / fail (evaluated) |
|---|---|---|---|---|
| `anssi_bp28_enhanced` | ANSSI-BP-028 v2.0 (enhanced) | 324 | 38 / 3 (41) | 38 / 1 (39) |
| `anssi_bp28_high` | ANSSI-BP-028 v2.0 (high) | 399 | 38 / 3 (41) | 38 / 1 (39) |
| `anssi_bp28_intermediary` | ANSSI-BP-028 v2.0 (intermediary) | 225 | 37 / 1 (38) | 37 / 0 (37) |
| `anssi_bp28_minimal` | ANSSI-BP-028 v2.0 (minimal) | 36 | 16 / 1 (17) | 16 / 0 (16) |
| `anssi_np_nt28_average` | ANSSI DAT-NT28 Average (legacy) | 44 | 19 / 0 (19) | 18 / 1 (19) |
| `anssi_np_nt28_high` | ANSSI DAT-NT28 High (legacy; default before 2.0.0) | 49 | 19 / 0 (19) | 18 / 1 (19) |
| `anssi_np_nt28_minimal` | ANSSI DAT-NT28 Minimal (legacy) | 24 | 18 / 0 (18) | 17 / 1 (18) |
| `anssi_np_nt28_restrictive` | ANSSI DAT-NT28 Restrictive (legacy) | 48 | 19 / 0 (19) | 18 / 1 (19) |
| `cis_level1_server` | **CIS Debian 12 v1.1.0, Level 1 Server (default)** | 403 | 129 / 7 (136) | 123 / 5 (128) |
| `cis_level1_workstation` | CIS Debian 12 v1.1.0, Level 1 Workstation | 394 | 126 / 7 (133) | 120 / 5 (125) |
| `cis_level2_server` | CIS Debian 12 v1.1.0, Level 2 Server | 507 | 131 / 7 (138) | 125 / 5 (130) |
| `cis_level2_workstation` | CIS Debian 12 v1.1.0, Level 2 Workstation | 504 | 130 / 7 (137) | 124 / 5 (129) |
| `standard` | Standard System Security Profile | 44 | 17 / 0 (17) | 17 / 0 (17) |

Why CIS Level 1 Server:

- **It is the most widely used benchmark with automated content for Debian, not a DISA-accepted substitute.** Where no STIG exists, DoD's fallback is the applicable SRG, which ships no automated content for Debian. The DoD Cloud Computing SRG names CIS Benchmarks directly, but only as an option for cloud service providers at Impact Level 2. That allowance doesn't cover a mission owner's own images, and at IL4 and above a commercial equivalent is assessed case by case. Treat CIS Level 1 results as the best automated evidence available for Debian. Whether they satisfy your control baseline is your authorizing official's call. CIS Level 1 is also the profile paired with the RHEL host STIG elsewhere in this README.
- **It is versioned.** It is generated from the control file for CIS Debian 12 Benchmark v1.1.0 (2024-09-26). The pre-2.0.0 default, `anssi_np_nt28_high`, is a hand-curated rule list for ANSSI's DAT-NT28 guide, the name ANSSI-BP-028 went by before its 2022 v2.0 rewrite. SSG ships v2.0 separately as `anssi_bp28_*`.
- **It evaluates about 7× as many rules:** 136 against `debian:12-slim`, against 19 for the old default.
- **Level 1 Server rather than the alternatives:** containers are servers, and Level 2 mostly adds host controls (`notapplicable` rises from 267 to 369) for two more evaluated rules.

To keep the 1.x result, set `profile_id: xccdf_org.ssgproject.content_profile_anssi_np_nt28_high`. If you need ANSSI for French-government requirements, use the current `anssi_bp28_*` profiles rather than the legacy `anssi_np_nt28_*` ones.

Known content defect: in SSG 0.1.82, the CIS banner rules `banner_etc_issue_cis`, `banner_etc_issue_net_cis` and `banner_etc_motd_cis` pass on Debian's stock `Debian GNU/Linux 12` banners. Their OVAL pattern is case-sensitive and never matches that text ([ComplianceAsCode/content#15150](https://github.com/ComplianceAsCode/content/issues/15150), open). The rules apply only to systems with a kernel package and no `/.dockerenv`, so image scans report them `notapplicable` (measured on `debian:12-slim`) and are unaffected. If you scan a Debian host or VM tree with `rootfs_path`, check those three controls by hand until the pin moves to content with the fix. The legacy ANSSI profile selects no banner rules, so it would not evaluate these controls either.

### Distroless images

Google distroless images (`gcr.io/distroless/*-debian12`) ship `/etc/os-release` (`ID=debian`, `VERSION_ID=12`), so `auto` resolves them to `debian12`. They do not ship `/var/lib/dpkg/status`: each installed package is a stanza in its own file under `/var/lib/dpkg/status.d/`. OpenSCAP's dpkg probe reads only the status file, so without it every package check comes back `error`, and "package X must not be installed" rules are never evaluated.

- **Image mode:** the orb builds `/var/lib/dpkg/status` from the `status.d/` stanzas in its scratch copy of the rootfs (never in the image), adding the `Status: install ok installed` line dpkg would have recorded. `summary.txt` shows `dpkg-status: synthesized … (N packages)`, and `provenance.json` records `target.dpkg_status`. Against `cc-debian12` this turns 27 `error` results into evaluated rules with the default CIS Level 1 Server profile (5 with the legacy `anssi_np_nt28_high`). If the file can't be built (`status.d/` holds no package stanzas, or `/var/lib/dpkg` is a symlink, which the orb won't write through), the scan records `dpkg_status: missing` with the reason and warns, as in `rootfs_path` mode.
- **`rootfs_path` mode:** the orb never modifies your tree. It records `dpkg_status: missing` and prints a warning in the log and `summary.txt`. To fix it, add the file to your extracted tree before the scan (with the same `Status` line image mode adds):
  ```sh
  d=/path/to/rootfs/var/lib/dpkg
  for f in "$d"/status.d/*; do
    case "$f" in *.md5sums) continue ;; esac
    if grep -q '^Status:' "$f"; then awk 1 "$f"
    else awk '{ print } /^Package:/ { print "Status: install ok installed" }' "$f"; fi
    echo
  done > "$d/status"
  ```

## 🚦 Gates

`summarize` applies two independent gates and states both settings in `summary.txt`:

| Gate | Default | Fails the job when |
|---|---|---|
| `require_evaluated_rules` | `true` | Zero rules evaluated to `pass`, `fail`, `fixed`, or `informational`. |
| `fail_on_finding` | `false` | Any non-ignored rule is `fail`, `error`, or `unknown`. |

`error` and `unknown` count as findings because the check did not produce a compliance answer. `notchecked` is listed in the summary but does not trip `fail_on_finding`; a scan that is *only* `notchecked` still fails `require_evaluated_rules`. Ignoring a failure removes it from the `fail_on_finding` count but not from "evaluated": a triaged baseline is still an evaluated scan.

`require_evaluated_rules` exists because an all-`notapplicable` scan looks clean and is not. Each of these produces 0 evaluated rules and, before 2.0.0, a green build:

- `target_base` forced to the wrong OS (e.g. `rhel9` against a Wolfi image): the datastream's platform check never matches, so every rule is `notapplicable`.
- A scanner built without the probe family the datastream needs (e.g. an `oscap` without `librpm` against a RHEL target), which is why RPM targets use a separate scanner image.
- A target whose package database the probes cannot read.

### Recording an intentional notapplicable baseline

Sometimes you need a profile's result on file even though it evaluates nothing against your image: an assessor asks to see that the host STIG was run, and you want the all-`notapplicable` result recorded rather than skipped. Do that with an explicit, per-job opt-out:

- Set `require_evaluated_rules: false` on **that one scan job only**.
- Pair it with a second scan of the same image using a profile that does evaluate rules (CIS Level 1 for RHEL), left at the default `require_evaluated_rules: true`. If the CIS job ever goes hollow, the workflow still fails.
- Check the opted-out job's `summary.txt`. It records `require-evaluated-rules: false` and, when nothing evaluated, says the result is not evidence of compliance.

Only opt out after a baseline run shows `Evaluated rules: 0` for that image. On a scan that does evaluate rules the opt-out changes nothing today, but it switches off the alarm for the day the scan breaks. As the next section shows, against UBI images the RHEL host STIG evaluates 49–70 rules, so a UBI STIG job does not need it.

```yaml
workflows:
  ato-evidence:
    jobs:
      # DISA STIG: DISA-identified (SV-/CCE-) results for the
      # container-applicable subset of the host benchmark.
      - stig-scanner-orb/scan:
          name: ubi9-disa-stig
          image: registry.access.redhat.com/ubi9/ubi-minimal:latest
          target_base: rhel9
          # Add ONLY if this image's summary.txt shows "Evaluated rules: 0"
          # and you still need that baseline on file:
          # require_evaluated_rules: false
      # CIS Level 1 Server: second control set, default gate left on.
      - stig-scanner-orb/scan:
          name: ubi9-cis-l1
          image: registry.access.redhat.com/ubi9/ubi-minimal:latest
          target_base: rhel9
          profile_id: xccdf_org.ssgproject.content_profile_cis_server_l1
```

The same pair is published as the `scan-rhel-stig-with-cis` orb example.

## ⚠️ RHEL host STIGs evaluated against containers

The **DISA STIG for RHEL N profile is a host-level benchmark**. A container image has no sshd, no auditd, no kernel parameters of its own, no firewalld, no bootloader, so most rules in the profile report `notapplicable` regardless of which scanner you use. What remains is the container-applicable subset: file permissions and ownership, package-removal checks, crypto policy, umask defaults, repository GPG settings.

Measured with SSG content 0.1.82 (rule results; `evaluated` = pass + fail):

| Image | Profile | pass | fail | notapplicable | evaluated |
|---|---|---|---|---|---|
| `ubi9/ubi` | DISA STIG | 62 | 8 | 406 | 70 |
| `ubi9/ubi-minimal` | DISA STIG | 60 | 6 | 410 | 66 |
| `ubi9/ubi-minimal` | CIS L1 Server | 64 | 5 | 226 | 69 |
| `ubi8/ubi` | DISA STIG | 44 | 7 | 341 | 51 |
| `ubi8/ubi-minimal` | DISA STIG | 43 | 6 | 343 | 49 |
| `ubi8/ubi-minimal` | CIS L1 Server | 74 | 6 | 260 | 80 |

Two consequences for compliance evidence:

- **A STIG run against a container is not an all-`notapplicable` baseline.** It produces real `fail` results with DISA identifiers (e.g. `configure_crypto_policy`, high severity). Triage them like any other finding.
- **A clean STIG run covers only 10–15% of the profile.** The ~400 `notapplicable` rules are host controls (audit, SSH, kernel, boot), which an assessor will expect to see inherited from the host platform rather than satisfied by the image.

For a second container-relevant control set, override `profile_id` to one of:

- `xccdf_org.ssgproject.content_profile_cis_server_l1` — CIS Level 1 Server; on RHEL 8 images it evaluates more rules than the STIG.
- `xccdf_org.ssgproject.content_profile_pci-dss` — narrower scope, more container-relevant rules per scope.
- `xccdf_basic_profile_.check` (only on Wolfi targets) — purpose-built for container scanning, not a host benchmark.

A container-tailored RHEL STIG tailoring file is on the roadmap.

## 🎛️ Job parameters

| Parameter | Type | Default | Notes |
|---|---|---|---|
| `image` | string | `""` | Image tag to scan. If not already in the local daemon, the orb will `docker pull` it. Mutually exclusive with `rootfs_path`. |
| `rootfs_path` | string | `""` | Path to an offline, pre-extracted filesystem: RPM-extracted trees, mounted VM disks, etc. Never a live filesystem such as `/`. Symlinks are resolved, and a tree containing a Unix socket is refused, as is one that overlaps `output_dir`. |
| `image_tarball` | string | `""` | Optional `docker load` source before scanning. `image` is still required: set it to a tag the archive contains. |
| `target_base` | enum | `auto` | See dispatch table above. |
| `scanner_image` | string | `""` | Override the pinned scanner. For air-gap mirrors; pin overrides by digest too. |
| `datastream_name` | string | `""` | Override the bundled datastream filename. |
| `datastream_path` | string | `""` | Host-local datastream file. Skips the donor flow. |
| `profile_id` | string | `""` | Override the XCCDF profile id (e.g. switch to CIS). |
| `donor_image` | string | `""` (pinned Chainguard openscap) | Root-privileged helper (extraction, distroless dpkg status, the `rootfs_path` socket check) and the image datastreams are copied out of for RPM targets. Override for air-gap; an override needs a shell and a POSIX userland (`tar`, `find`, `awk`, `cp`, …; busybox is enough) plus the SCAP content under `/usr/share/xml/scap/ssg/content`. |
| `fail_on_finding` | boolean | `false` | When true, exit 1 on any non-ignored `fail`, `error`, or `unknown` result. |
| `require_evaluated_rules` | boolean | `true` | Fail the job when zero rules evaluate to pass, fail, fixed, or informational. Set false only on a job that intentionally records an all-notapplicable baseline (see [Gates](#-gates)). |
| `ignore_findings` | string | `""` | Comma-separated rule IDs to subtract from the fail/error/unknown gate count. |
| `output_dir` | string | `build/stig` | Where reports and summary land. In `rootfs_path` mode it must not overlap the scanned tree. |
| `resource_class` | string | `medium` | Pass-through to the machine executor. |
| `no_output_timeout` | string | `30m` | OpenSCAP can be silent for several minutes during evaluation. |
| `checkout` | boolean | `true` | Whether to `checkout` before scanning. |

CircleCI's standard `pre-steps` and `post-steps` job-injection points work as usual — use them for `attach_workspace`, `docker login`, etc.

The orb also exposes `stig-scanner-orb/scan` (command), `stig-scanner-orb/summarize`, and `stig-scanner-orb/load_image` for callers who want to assemble a custom job.

## 📦 Outputs

Under `<output_dir>/`:

- `report.html` — the XCCDF HTML report. CircleCI inlines this in the Artifacts tab so an assessor can open it from the build page.
- `results.xml` — the XCCDF results document, machine-readable.
- `summary.txt` — a provenance block, pass / fail / error / unknown / notapplicable counts, the rule list for fail, error, unknown, and notchecked, and a hollow-scan warning when nothing evaluated. The "ignored" tier appears separately for auditing.
- `provenance.json` — the same provenance, machine-readable (see below).
- `scan-plan.env` — the raw `key=value` facts `scan` recorded (references, image ids, digests, datastream hash) and `summarize` reads.

These are well-suited as ATO evidence and easy to attach to your container as in-toto attestations via Cosign.

## 🔁 Reproducibility and provenance

### Pinned images

The default scanner and donor images are pinned by digest, so a given orb version always runs the same OpenSCAP build against the same SCAP content:

| Role | Pinned reference |
|---|---|
| Scanner for `wolfi`, `debian12`, `ubuntu2204`; donor and extraction helper for all targets | `cgr.dev/chainguard/openscap:latest-dev@sha256:f5e08bc14cc659268a7807d7ec573ff3cc56b62b9358313db8df76909018b55e` |
| Scanner for `rhel8`, `rhel9`, `rhel10`, `fedora` | `quay.io/compliance-operator/openscap-ocp:1.3.6@sha256:4c49e8c1af801051d9dbe5d33e371440948cbffce1dbc4379daf909b1288869a` |

Docker resolves the digest and ignores the tag, which is kept so a reader can see what was pinned. The Chainguard digest is a multi-arch index (linux/amd64, linux/arm64); the compliance-operator image is linux/amd64 only. That image's `:latest` tag points at the same 1.3.6 build, last published April 2023, so the version tag is the more durable pin. Chainguard publishes only `latest`/`latest-dev` tags for this image. Older digests remain pullable in practice (digests from mid-2024 still resolve), but Chainguard does not document a retention guarantee. If a pinned digest ever stops resolving, override `scanner_image`/`donor_image` until the orb is bumped.

`scanner_image` and `donor_image` still override the pins. Pin overrides by digest as well: a tag-only reference is used as found in the local Docker daemon, which may be stale. The provenance below records what actually ran either way.

### What each scan records

`summary.txt` opens with a provenance block, and `provenance.json` carries the same data:

| Field | Meaning |
|---|---|
| `target.image`, `target.repo_digests`, `target.image_id`, `target.platform` | Target image reference as given, the registry digest(s) it is known by, its local image id, and its platform (`os/arch`). `repo_digests` is empty for images that never came from a registry (built or loaded locally). `rootfs_path` replaces these in rootfs mode. |
| `target_base.requested`, `.resolved`, `.resolved_from` | e.g. `auto` → `rhel9`, from `os-release`, `package-db` (filesystem-shape fallback), or `parameter`. |
| `profile.id`, `profile.title` | The XCCDF profile evaluated. |
| `scanner.image`, `.repo_digests`, `.image_id`, `.platform`, `.openscap_version` | The scanner reference, its registry digest, its local id, the platform it ran as (`os/arch`), and the OpenSCAP version that produced `results.xml`. |
| `donor` | Same image fields, plus `used_for` (`extraction`, `datastream`, `rootfs-check`: the root socket check on a `rootfs_path` the runner can't fully read); `null` when no helper image was used. |
| `datastream.name`, `.source`, `.sha256` | The datastream file, where it came from (`bundled` in the scanner, `donated` from the donor, or `datastream_path`), and the sha256 of the exact file `oscap` evaluated, hashed inside the scanner container (from the per-scan snapshot for `donated` and `datastream_path`). |
| `datastream.benchmark_id`, `.benchmark_version`, `.ssg_version` | The XCCDF benchmark and its version; `ssg_version` is the ComplianceAsCode/SSG release when the benchmark is SSG content, otherwise `null` (the Wolfi GPOS datastream is not). |
| `scan.start_time`, `scan.end_time` | From the XCCDF `TestResult`. |

Cite `repo_digests` as the image digest, together with `platform`: the pinned Chainguard digest is a multi-platform index, which names the amd64 and arm64 builds at once, and the platform says which of its manifests ran (`summary.txt` prints it in brackets after each digest). `image_id` is store-dependent: on Docker's classic image store it is the config digest, on the containerd store it is the manifest or index digest. Every helper and scanner container runs from the resolved image id, so the recorded image is the one that ran even if a tag moved mid-scan.

A donated or `datastream_path` datastream is copied into a private per-scan snapshot directory (as root inside a container, so a `datastream_path` only root can read works, as it does for the root-run scan), and both the hash and the scan read that snapshot, so `datastream.sha256` is the hash of the bytes `oscap` evaluated even if the original file changes mid-scan. Donated datastreams are not cached between scans: a reused file could be stale or modified and still be attributed to the pinned donor. Bundled datastreams are read from inside the digest-pinned scanner image.

### Updating the pinned images

The pins live in one place, `DEFAULT_CHAINGUARD_IMAGE` and `DEFAULT_RPM_SCANNER_IMAGE` at the top of `src/scripts/scan.sh`. `tests/pinned_refs_test.sh` fails CI if they are not digest-pinned or if this README's table does not list them verbatim.

1. Resolve the current digests:
   ```sh
   docker buildx imagetools inspect cgr.dev/chainguard/openscap:latest-dev --format '{{.Manifest.Digest}}'
   # compliance-operator: check for a newer version tag before moving off 1.3.6
   curl -fsS 'https://quay.io/api/v1/repository/compliance-operator/openscap-ocp/tag/?onlyActiveTags=true' \
     | jq -r '.tags[] | "\(.name) \(.manifest_digest)"'
   ```
2. Update both constants in `scan.sh` and the table above, keeping the `name:tag@sha256:` form.
3. Run the local smoke from Local development below against a Wolfi image and a UBI image, and compare the provenance block and rule counts with the previous pin: `ssg-version`, `openscap`, and evaluated/fail counts. Update the measured tables in this README if they moved.
4. Record the move in `CHANGELOG.md` with old → new SSG and OpenSCAP versions. A content bump changes scan results, and new `fail` results can trip `fail_on_finding`, so release it as at least a minor version.
5. Push; the `test-deploy` matrix pulls every pin and exercises both scanner paths.

## 🙈 Ignore-list semantics

Entries in `ignore_findings` are matched case-insensitively against:

- the short DISA id (e.g. `SV-257779r925318`),
- the full XCCDF rule id, or
- any `<ident>` or `<reference>` value on the rule (CCE, CVE, CCI, a NIST control such as `AC-2`, and so on). A shared reference waives every rule that cites it.

Ignored `fail`, `error`, and `unknown` results still appear in the summary and the HTML report. They are removed from the `fail_on_finding` count, not the audit trail. Ignoring them does not waive `require_evaluated_rules`: a result that actually failed was evaluated.

## 🔐 Info for security teams

### Required external access

All network access during a scan is image pulls by the runner's Docker daemon. The orb downloads nothing else: no datastreams (they ship inside the pinned Chainguard image), no remote OVAL (`oscap` runs without `--fetch-remote-resources`; the Debian datastream's reference to debian.org security OVAL is skipped and logged), no packages, no telemetry. Every helper and scanner container runs with `--network none`.

Outbound HTTPS (443) from the runner, by host. A host is contacted only to pull an image the Docker daemon doesn't already have: a runner with the pinned images already loaded, or `scanner_image` / `donor_image` overrides pointing at your own mirror, needs none of the public scanner registries below (see [Air-gapped use](#air-gapped-use)).

| Host | Why | Needed when |
|---|---|---|
| `cgr.dev` | Registry and token endpoint (`cgr.dev/token`) for the pinned Chainguard openscap image: scanner for `wolfi`/`debian12`/`ubuntu2204`, root-privileged extraction helper in image mode, and datastream donor for RPM targets. Anonymous pull. | Every scan except `rootfs_path` + RPM target + `datastream_path`, unless the image is already loaded or `donor_image` / `scanner_image` points at a mirror. |
| `9236a389bd48b984df91adc1bc924620.r2.cloudflarestorage.com` | Chainguard's blob storage. `cgr.dev` answers layer downloads with a 307 redirect here. Listed in [Chainguard's network requirements](https://edu.chainguard.dev/chainguard/administration/network-requirements). | Whenever `cgr.dev` is needed. |
| `quay.io` | Registry and token endpoint (`quay.io/v2/auth`) for the pinned compliance-operator scanner. Anonymous pull. | `rhel8`, `rhel9`, `rhel10`, `fedora` targets, unless the image is already loaded or `scanner_image` points at a mirror. |
| `cdn01.quay.io` (Red Hat also documents `cdn.quay.io` and `cdn02`–`cdn06.quay.io`; `*.quay.io` covers all) | quay.io's blob CDN; layer downloads 302-redirect here. `registry.access.redhat.com` blobs are served from the same CDN. | With `quay.io`, and for UBI targets pulled from `registry.access.redhat.com`. |
| The target image's registry, plus its token and blob hosts | Only if the target is not already in the local daemon (`image_tarball` or an earlier `docker pull` avoids it). Measured examples: Docker Hub (e.g. `ubuntu:22.04`, `debian:12-slim`) → registry `registry-1.docker.io`, token at `auth.docker.io`, blobs 307-redirect to `production.cloudfront.docker.com` (see [Docker's allowlist](https://docs.docker.com/desktop/setup/allow-list/)); `registry.access.redhat.com` → blobs from `cdn01.quay.io` (no auth); `gcr.io` → token at `gcr.io/v2/token`, blobs served from `gcr.io` itself; `cgr.dev` → as above. For any other registry, also allow the token host named as `realm` in its `WWW-Authenticate` header and wherever it redirects blob downloads. | `image` mode with a target not yet loaded. |

The default scanner and helper images are pulled by digest (see [Pinned images](#pinned-images)), so Docker rejects any content that doesn't match the pin. A `scanner_image` or `donor_image` override gets that check only if you pin it by digest too (`name:tag@sha256:…`, as in the air-gap example below); a tag-only override is used as is. The target image is pulled by whatever reference you pass. Either way, `provenance.json` records each image's local image id and, for an image that came from a registry, its registry digest (`repo_digests`), target included, so what ran is identifiable after the fact. A locally built image has no registry digest, and one loaded from `image_tarball` may not either. Its `repo_digests` is then empty, and the evidence has only the local image id, which no registry can confirm.

Not the orb's traffic, but present in any CircleCI job: the `checkout` step talks to your VCS host, and `store_artifacts` uploads to CircleCI. Set `checkout: false` if the scan job doesn't need your source tree.

### What runs, and with which privileges

- The scan job needs the **machine executor** (a VM with a local Docker daemon). The orb mounts no Docker socket into any container and uses no `--privileged`, `--pid=host`, or host networking. A `rootfs_path` is bind-mounted into the scanner as given, and a read-only mount still lets a process connect to a Unix socket inside it, so the orb refuses a `rootfs_path` that contains any socket (a live filesystem could hold `/run/docker.sock`). The check runs as the runner user first; if that user can't read the whole tree (root-owned 0700 directories in a mounted disk, say), it reruns as root in the Chainguard helper image, never in the scanner image, and the scan fails if that can't complete either. Image-mode trees come from `docker export` and never contain sockets.
- Every container runs as root (`-u 0:0`) *inside* the container, so the extracted rootfs keeps the image's numeric UIDs/GIDs and OpenSCAP can read every file, including a `datastream_path` only root can read. Each sees only what it needs: the extraction and dpkg-synthesis helpers get the scratch rootfs directory, the datastream snapshot helper gets the per-scan snapshot directory (plus, for `datastream_path`, that one file read-only), the datastream-hashing container gets only the snapshot (read-only), and the scanner gets the rootfs **read-only**, a fresh private output directory (its only writable mount; the host copies `results.xml` and `report.html` into `output_dir` afterwards, only if they are regular files, so `output_dir` itself is never mounted and a planted symlink can't pull a host file into the artifacts), and, for RPM targets or `datastream_path`, the snapshot read-only. Mounts nested inside a `rootfs_path` (a mounted disk's own `/boot` or `/var`) are made read-only too: the scan then requires a recursively read-only bind (Docker 25+ on kernel 5.12+) and fails rather than fall back to writable submounts.
- Results are `chown`ed back to the runner's UID/GID. An `EXIT` trap removes the scratch rootfs and the datastream snapshot, on failure too, and warns if it can't (the rootfs holds root-owned files, so removal needs a root helper container and therefore a working Docker daemon). A step killed outright (`SIGKILL`, a hard timeout) skips the trap: an ephemeral machine executor discards the VM anyway, but on a long-lived runner look for leftover `stig-rootfs.*` / `stig-datastream.*` directories under `$TMPDIR` (default `/tmp`). Nothing is written to the runner's home directory.
- `/etc/os-release` from the target image is parsed as data with `awk`, never sourced, and symlinks that would point outside the extracted rootfs are rejected.

### Air-gapped use

Mirror the pinned images **by digest** (a multi-arch-preserving copy keeps the same digest, so provenance still matches the pins), point the orb at the mirrors, and make the target image available locally:

```sh
# e.g. with crane; `skopeo copy --all --preserve-digests` works too
crane copy cgr.dev/chainguard/openscap@sha256:f5e08bc14cc659268a7807d7ec573ff3cc56b62b9358313db8df76909018b55e \
  registry.internal/chainguard/openscap:latest-dev
crane copy quay.io/compliance-operator/openscap-ocp@sha256:4c49e8c1af801051d9dbe5d33e371440948cbffce1dbc4379daf909b1288869a \
  registry.internal/compliance-operator/openscap-ocp:1.3.6
```

```yaml
- stig-scanner-orb/scan:
    image: registry.internal/myapp:1.2.3              # with image_tarball, a tag the archive contains
    image_tarball: /tmp/workspace/myapp.tar           # optional: docker load the target instead of pulling it
    target_base: rhel9
    scanner_image: registry.internal/compliance-operator/openscap-ocp:1.3.6@sha256:4c49e8c1af801051d9dbe5d33e371440948cbffce1dbc4379daf909b1288869a
    donor_image: registry.internal/chainguard/openscap:latest-dev@sha256:f5e08bc14cc659268a7807d7ec573ff3cc56b62b9358313db8df76909018b55e
```

Which images a scan needs, by mode (`datastream_path` replaces only the *datastream* role of the Chainguard image, never the extraction-helper role):

| Mode | Chainguard openscap (`donor_image` / `scanner_image`) | compliance-operator (`scanner_image`) | `datastream_path` |
|---|---|---|---|
| `image`, non-RPM target | scanner + extraction helper | — | optional |
| `image`, RPM target | extraction helper + datastream donor | scanner | optional; drops only the donor role |
| `rootfs_path`, non-RPM target | scanner (+ socket-check helper\*) | — | optional |
| `rootfs_path`, RPM target | datastream donor (+ socket-check helper\*) | scanner | supply it to need **no** Chainguard image at all\* |

\* Unless the runner user can't read the whole `rootfs_path` tree: then the socket check runs as root in the Chainguard helper image.

With `datastream_path`, the file you supply is evaluated as-is, and its sha256 and benchmark/SSG version land in `provenance.json`, so record where it came from in your evidence. A non-RPM `scanner_image` mirror must keep the Chainguard layout (datastreams under `/usr/share/xml/scap/ssg/content/`), or set `datastream_path`. On CircleCI server, also import the orb into your installation.

## 🛠️ Local development

```sh
# pack and validate
circleci orb pack src/ > /tmp/packed-orb.yml
circleci orb validate /tmp/packed-orb.yml

# lint shell
shellcheck src/scripts/*.sh

# end-to-end smoke against a known target
docker pull cgr.dev/chainguard/static:latest
PARAM_IMAGE=cgr.dev/chainguard/static:latest \
PARAM_TARGET_BASE=auto \
PARAM_OUTPUT_DIR=/tmp/orb-smoke \
bash src/scripts/scan.sh

PARAM_OUTPUT_DIR=/tmp/orb-smoke \
bash src/scripts/summarize.sh
```

The same scripts CircleCI runs in pipeline are runnable directly via `bash` — the `subst` shim no-ops outside CircleCI, so literal parameter values pass through unchanged.

## 🚧 Not yet supported

- `oscap-docker container` mode (live process / runtime inspection). Use `image` mode for now; `container` mode lands when there's a concrete consumer use case.
- A container-tailored RHEL STIG tailoring file (see ⚠️ above).
- A `harden-check` companion command (checksec / SUID enumeration / shell-presence assertions for `scratch` and Google-distroless targets).
- SARIF emission for GitHub code scanning.
- arm64 verification — the scan path works on amd64; arm64 may produce surprising probe results we haven't validated.

## ⚖️ Legal
This project is released under an [MIT license](LICENSE) and as such is **provided without warranty of any kind**. I make no promises as to its correctness or accuracy. 