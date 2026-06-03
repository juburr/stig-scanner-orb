<div align="center">
  <img align="center" width="300" src="assets/logos/stig-scanner-orb-512px.png?v=2" alt="STIG Scanner Orb"><br /><br />
  <h1>STIG Scanner Orb</h1>
  <i>A CircleCI orb that scans for DISA STIG findings using Chainguard's OpenSCAP scanner.</i><br /><br />
</div>

<!---
[![CircleCI Build Status](https://circleci.com/gh/juburr/stig-scanner-orb.svg?style=shield "CircleCI Build Status")](https://circleci.com/gh/juburr/stig-scanner-orb) [![CircleCI Orb Version](https://badges.circleci.com/orbs/juburr/stig-scanner-orb.svg)](https://circleci.com/developer/orbs/orb/juburr/stig-scanner-orb) [![GitHub License](https://img.shields.io/badge/license-MIT-lightgrey.svg)](https://raw.githubusercontent.com/juburr/stig-scanner-orb/master/LICENSE) [![CircleCI Community](https://img.shields.io/badge/community-CircleCI%20Discuss-343434.svg)](https://discuss.circleci.com/c/ecosystem/orbs)
--->


## 📖 Overview
This CircleCI orb uses the same process outlined by Chainguard in their [STIGs for Chainguard Containers](https://edu.chainguard.dev/chainguard/chainguard-images/features/image-stigs/) guide. I've extended it to work with other non-Wolfi operating systems such as UBI8, UBI9, Ubuntu, Debian, Fedora, and certain distroless images.

The orb includes optional failure gates, ignore lists to exclude findings from the failure gates, summarized outputs, and the ability to emit artifacts to use as ATO evidence or to attach to your container as in-toto attestations using Cosign.

## 🚀 Getting Started

```yaml
version: 2.1
orbs:
  stig-scanner-orb: juburr/stig-scanner-orb@1.0.0

workflows:
  scan:
    jobs:
      - stig-scanner-orb/scan:
          image: cgr.dev/chainguard/static:latest
          target-base: wolfi
```

That's enough to produce `report.html`, `results.xml`, and `summary.txt` as job artifacts. The gate is off by default — the scan reports findings without failing the build, so you can establish a triaged baseline before turning the gate on.

## 🧰 What it does

1. (Optional) `docker load` an image tarball produced by an upstream job.
2. Host-extract the target image's rootfs via `docker create` + `docker export`. Skipped when you pass `rootfs-path` directly.
3. Resolve `target-base` to a scanner image, datastream, and XCCDF profile. `auto` reads `/etc/os-release` from the extracted rootfs.
4. For RPM-based targets, copy the right `ssg-*-ds.xml` out of the Chainguard openscap image (which bundles every major datastream) into a runner-side cache. The compliance-operator scanner is purpose-built for `oscap-chroot` and ships no SCAP content of its own, so we donate the file from Chainguard.
5. Pull the resolved scanner image and run `oscap-chroot` against the extracted rootfs.
6. Parse `results.xml`, write `summary.txt`, apply the ignore-list, and enforce the gate.
7. `store_artifacts` runs unconditionally so the evidence is always retrievable, even on a failing gate.

`oscap-chroot` is preferred over `oscap-docker` because it doesn't require `--pid=host` or bind-mounting the docker socket into the scanner — the scanner reads a static rootfs the runner already extracted. That keeps the scan container as unprivileged as the rest of the pipeline.

## 🎯 Supported targets

| `target-base` | Scanner image | Datastream | Default profile |
|---|---|---|---|
| `wolfi` | `cgr.dev/chainguard/openscap:latest-dev` | `ssg-chainguard-gpos-ds.xml` | Chainguard GPOS |
| `debian12` | `cgr.dev/chainguard/openscap:latest-dev` | `ssg-debian12-ds.xml` | ANSSI-NP-NT28 high |
| `ubuntu2204` | `cgr.dev/chainguard/openscap:latest-dev` | `ssg-ubuntu2204-ds.xml` | DISA STIG |
| `rhel8` | `quay.io/compliance-operator/openscap-ocp:latest` | `ssg-rhel8-ds.xml` | DISA STIG |
| `rhel9` | `quay.io/compliance-operator/openscap-ocp:latest` | `ssg-rhel9-ds.xml` | DISA STIG |
| `rhel10` | `quay.io/compliance-operator/openscap-ocp:latest` | `ssg-rhel10-ds.xml` | DISA STIG |
| `fedora` | `quay.io/compliance-operator/openscap-ocp:latest` | `ssg-fedora-ds.xml` | standard |
| `auto` | resolved from `/etc/os-release` | resolved | resolved |

`auto` recognizes RHEL, Rocky, Alma, Oracle Linux, Fedora, Debian 12, Ubuntu 22.04, Wolfi, and Chainguard via the target's `/etc/os-release`, with filesystem-shape fallbacks (`apk`, `rpm`, `dpkg`) for distroless images that lack one. For Wolfi static distroless or scratch images, set `target-base` explicitly.

## ⚠️ RHEL host STIGs evaluated against containers

Heads up: the **DISA STIG for RHEL N profile is a host-level benchmark**. A typical container image has no sshd, no auditd, no kernel parameters of its own, no firewalld, no `/etc/login.defs` modifications — so the majority of rules in the profile will report `notapplicable` regardless of which scanner you use.

Concretely, scanning `rockylinux:9` with the DISA STIG for RHEL 9 profile produces roughly **0 pass / 0 fail / 485 notapplicable / 1045 notselected**. That is the *correct* OpenSCAP result, not a defect in the orb.

If you want more container-applicable signal against a RHEL-family image, override `profile-id` to one of:

- `xccdf_org.ssgproject.content_profile_cis_server_l1` — CIS Level 1, more file-permission and package rules that actually apply to containers.
- `xccdf_org.ssgproject.content_profile_pci-dss` — narrower scope, more container-relevant rules per scope.
- `xccdf_basic_profile_.check` (only on Wolfi targets) — purpose-built for container scanning, not a host benchmark.

A v1.1 container-tailored RHEL STIG tailoring file is on the roadmap; until then, document the N/A baseline in your compliance evidence and pair the scan with CIS for actionable signal.

## 🎛️ Job parameters

| Parameter | Type | Default | Notes |
|---|---|---|---|
| `image` | string | `""` | Image tag to scan. If not already in the local daemon, the orb will `docker pull` it. Mutually exclusive with `rootfs-path`. |
| `rootfs-path` | string | `""` | Path to a pre-extracted filesystem. Use for RPM-extracted trees, mounted VM disks, etc. |
| `image-tarball` | string | `""` | Optional `docker load` source before scanning. |
| `target-base` | enum | `auto` | See dispatch table above. |
| `scanner-image` | string | `""` | Override resolved scanner. For air-gap mirrors. |
| `datastream-name` | string | `""` | Override the bundled datastream filename. |
| `datastream-path` | string | `""` | Host-local datastream file. Skips the donor flow. |
| `profile-id` | string | `""` | Override the XCCDF profile id (e.g. switch to CIS). |
| `donor-image` | string | `cgr.dev/chainguard/openscap:latest-dev` | Image to copy datastreams out of for RPM targets. Override for air-gap. |
| `fail-on-finding` | boolean | `false` | When true, exits 1 on any non-ignored failure. |
| `ignore-findings` | string | `""` | Comma-separated rule IDs to subtract from the gate count. |
| `output-dir` | string | `build/stig` | Where reports and summary land. |
| `resource-class` | string | `medium` | Pass-through to the machine executor. |
| `no-output-timeout` | string | `30m` | OpenSCAP can be silent for several minutes during evaluation. |
| `checkout` | boolean | `true` | Whether to `checkout` before scanning. |

CircleCI's standard `pre-steps` and `post-steps` job-injection points work as usual — use them for `attach_workspace`, `docker login`, etc.

The orb also exposes `stig-scanner-orb/scan` (command), `stig-scanner-orb/summarize`, and `stig-scanner-orb/load-image` for callers who want to assemble a custom job.

## 📦 Outputs

Under `<output-dir>/`:

- `report.html` — the XCCDF HTML report. CircleCI inlines this in the Artifacts tab so an assessor can open it from the build page.
- `results.xml` — the XCCDF results document, machine-readable.
- `summary.txt` — pass / fail / notapplicable counts and the failed-rule list. The "ignored" tier appears separately for auditing.
- `scan-plan.env` — the resolved scanner / datastream / profile, so a later consumer of the artifacts knows exactly what produced them.

These are well-suited as ATO evidence and easy to attach to your container as in-toto attestations via Cosign.

## 🙈 Ignore-list semantics

Entries in `ignore-findings` are matched case-insensitively against:

- the short DISA id (e.g. `SV-257779r925318`),
- the full XCCDF rule id, or
- any `<ident>` value on the rule (CCE, CVE, CCI, etc.).

Ignored failures still appear in the summary and the HTML report — they are removed from the gate count, not the audit trail.

## 🛡️ Air-gap

Every image and content reference is parameterized:

- `scanner-image` overrides the runtime scanner (point at a mirror).
- `donor-image` overrides where datastreams are copied out of.
- `datastream-path` skips the donor flow entirely; mount your own datastream into the runner first.

For RHEL-only consumers who don't want a Chainguard dependency at all, mirror `quay.io/compliance-operator/openscap-ocp` and supply datastreams via `datastream-path`.

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

## 🚧 What's not in v1

- `oscap-docker container` mode (live process / runtime inspection). Use `image` mode for now; `container` mode lands when there's a concrete consumer use case.
- A container-tailored RHEL STIG tailoring file (see ⚠️ above).
- A `harden-check` companion command (checksec / SUID enumeration / shell-presence assertions for `scratch` and Google-distroless targets).
- SARIF emission for GitHub code scanning.
- arm64 verification — the scan path works on amd64; arm64 may produce surprising probe results we haven't validated.

## ⚖️ Legal
This project is released under an [MIT license](LICENSE) and as such is **provided without warranty of any kind**. I make no promises as to its correctness or accuracy. 