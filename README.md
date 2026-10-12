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
| `debian12` | Chainguard openscap | `ssg-debian12-ds.xml` | ANSSI-NP-NT28 high |
| `ubuntu2204` | Chainguard openscap | `ssg-ubuntu2204-ds.xml` | DISA STIG |
| `rhel8` | compliance-operator openscap-ocp | `ssg-rhel8-ds.xml` | DISA STIG |
| `rhel9` | compliance-operator openscap-ocp | `ssg-rhel9-ds.xml` | DISA STIG |
| `rhel10` | compliance-operator openscap-ocp | `ssg-rhel10-ds.xml` | DISA STIG |
| `fedora` | compliance-operator openscap-ocp | `ssg-fedora-ds.xml` | standard |
| `auto` | resolved from `/etc/os-release` | resolved | resolved |

Both scanner images are pinned by digest; see [Reproducibility and provenance](#-reproducibility-and-provenance) for the exact references. The Chainguard image also serves as the donor for RPM datastreams and as the root-privileged extraction helper.

`auto` recognizes RHEL, Rocky, Alma, Oracle Linux, Fedora, Debian 12, Ubuntu 22.04, Wolfi, and Chainguard via the target's `/etc/os-release`, with filesystem-shape fallbacks (`apk`, `rpm`, `dpkg`) for distroless images that lack one. For `scratch` images that ship neither `/etc/os-release` nor a package database, set `target_base` explicitly.

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
| `rootfs_path` | string | `""` | Path to a pre-extracted filesystem. Use for RPM-extracted trees, mounted VM disks, etc. |
| `image_tarball` | string | `""` | Optional `docker load` source before scanning. |
| `target_base` | enum | `auto` | See dispatch table above. |
| `scanner_image` | string | `""` | Override the pinned scanner. For air-gap mirrors; pin overrides by digest too. |
| `datastream_name` | string | `""` | Override the bundled datastream filename. |
| `datastream_path` | string | `""` | Host-local datastream file. Skips the donor flow. |
| `profile_id` | string | `""` | Override the XCCDF profile id (e.g. switch to CIS). |
| `donor_image` | string | `""` (pinned Chainguard openscap) | Extraction helper, and the image datastreams are copied out of for RPM targets. Override for air-gap. |
| `fail_on_finding` | boolean | `false` | When true, exit 1 on any non-ignored `fail`, `error`, or `unknown` result. |
| `require_evaluated_rules` | boolean | `true` | Fail the job when zero rules evaluate to pass, fail, fixed, or informational. Set false only on a job that intentionally records an all-notapplicable baseline (see [Gates](#-gates)). |
| `ignore_findings` | string | `""` | Comma-separated rule IDs to subtract from the fail/error/unknown gate count. |
| `output_dir` | string | `build/stig` | Where reports and summary land. |
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
| `donor` | Same image fields, plus `used_for` (`extraction`, `datastream`); `null` when no helper image was used (rootfs mode with a bundled datastream). |
| `datastream.name`, `.source`, `.sha256` | The datastream file, where it came from (`bundled` in the scanner, `donated` from the donor, or `datastream_path`), and the sha256 of the exact file `oscap` evaluated, hashed inside the scanner container (from the per-scan snapshot for `donated` and `datastream_path`). |
| `datastream.benchmark_id`, `.benchmark_version`, `.ssg_version` | The XCCDF benchmark and its version; `ssg_version` is the ComplianceAsCode/SSG release when the benchmark is SSG content, otherwise `null` (the Wolfi GPOS datastream is not). |
| `scan.start_time`, `scan.end_time` | From the XCCDF `TestResult`. |

Cite `repo_digests` as the image digest, together with `platform`: the pinned Chainguard digest is a multi-platform index, which names the amd64 and arm64 builds at once, and the platform says which of its manifests ran (`summary.txt` prints it in brackets after each digest). `image_id` is store-dependent: on Docker's classic image store it is the config digest, on the containerd store it is the manifest or index digest. Every helper and scanner container runs from the resolved image id, so the recorded image is the one that ran even if a tag moved mid-scan.

A donated or `datastream_path` datastream is copied into a private per-scan snapshot directory, and both the hash and the scan read that snapshot, so `datastream.sha256` is the hash of the bytes `oscap` evaluated even if the original file changes mid-scan. Donated datastreams are not cached between scans: a reused file could be stale or modified and still be attributed to the pinned donor. Bundled datastreams are read from inside the digest-pinned scanner image.

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

## 🛡️ Air-gap

Every image and content reference is parameterized:

- `scanner_image` overrides the runtime scanner (point at a mirror; mirror by digest so the pinned content carries over).
- `donor_image` overrides the extraction helper and where datastreams are copied out of.
- `datastream_path` skips the donor flow entirely; mount your own datastream into the runner first.

For RHEL-only consumers who don't want a Chainguard dependency at all, mirror `quay.io/compliance-operator/openscap-ocp` and supply datastreams via `datastream_path`.

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