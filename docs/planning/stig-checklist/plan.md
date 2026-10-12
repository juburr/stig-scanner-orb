# Plan: STIG Viewer checklists with container N/A justifications

Status: **proposed**, 2026-10-12. Owner: TBD.

Inputs:
- [spike.md](spike.md): measured on real ubi9, ubi8, ubuntu:22.04 and
  Chainguard scans; prototype in [`spike/`](spike/).
- Research report:
  [`../reports/STIG checklist output for containers.md`](../reports/STIG%20checklist%20output%20for%20containers.md).
  It covers checklist formats and consumers, prior-art converters, DISA
  source data, and container N/A practice.

## Goal

A scan whose profile maps to a DISA STIG also produces a STIG Viewer
checklist (`checklist.ckl` and `checklist.cklb`). An ISSM can import it into
STIG Viewer 3, STIG Manager or eMASS without re-keying anything. Every
Not_Applicable row carries a short, factual reason:

- host-level control,
- no GUI installed,
- package not installed, or
- the automated check itself said N/A.

That replaces ~370 bare N/A rows the ISSM would otherwise have to explain.
On ubi9 the 366 N/A rows split into 330 host, 23 GUI, 11 package, 1 generic and 1
check-level.

### Non-goals

- **No hand-curated "container STIG" tailoring file that deselects host
  rules.** XCCDF tailoring can only make a rule `notselected` (dropped from
  results) or `notchecked`; it cannot make it `notapplicable`. Deselected
  rules then show up as Not Reviewed, or not at all. Iron Bank scans UBI
  with the stock `stig` profile, and Chainguard keeps all rules and
  explains N/A per rule. The reasons can be derived exactly without a
  curated list (spike findings 2, 10).
- **Not asserting control inheritance.** STIG Viewer has four statuses
  (Open, Not A Finding, Not Applicable, Not Reviewed). "Inherited" is an
  RMF/eMASS control-level relationship with a common control provider.
  Only the ISSM can record it.
- **Not changing scan results, gates or network posture.** The generator
  runs offline on the runner, after the scan, from `results.xml`.
- **Not pushing to eMASS.** eMASS has a `container-scan-results` API keyed
  on STIG benchmark id + DISA Rule ID that fits this orb well; it is a
  candidate follow-on, not part of this plan.

## Decisions

| # | Decision | Why |
|---|---|---|
| D1 | Write our own generator: Python stdlib, run on the runner like `summarize.sh`. | `oscap --stig-viewer` emits zero rule-results on OpenSCAP 1.3.6 (all RPM targets; fixed only in 1.3.13/1.4.3). It keeps one result per DISA id and writes XCCDF, not a checklist; STIG Manager rejects its SSG benchmark id. MITRE SAF writes one row per *SSG* rule (no V-ID aggregation, no CCIs, CKL only) and would add a Node toolchain. PyPI has no maintained CKL/CKLB library. `results.xml` has everything needed (spike 1, 8). |
| D2 | Emit **both** `.ckl` and `.cklb` from one internal model; `checklist_formats` can pick one. | STIG Viewer 3.8.1 (current) imports CKL and exports both. DISA hosts no 2.x packages any more, but there is no end-of-support notice and CKL is still everywhere. eMASS device-scan upload takes either (`disaStigViewerCklCklb`). STIG Manager imports both. |
| D3 | Rows are keyed on **V-ID**. V-ID comes from SSG's `#vulnerability_id` reference, or, for content older than SSG 0.1.82, from the SV number. Each `SV-n…_rule` pairs with `V-n` by number. When a rule has V-ID references, **only matched pairs become rows**: a `V-n` with no `SV-n` on the same rule, or an `SV-n` with no `V-n`, names no DISA rule. It is listed under "unpaired references" in the meta and summary instead. The SV-derived fallback applies only when a rule has no V-ID reference at all. | V-IDs are stable across releases; rule-revision suffixes and even STIG IDs are not. The mapping is many-to-many (spike 4). The pinned content has no unpaired reference (measured on ubi9, ubi8, ubuntu), but an unpaired V-ID in custom content would otherwise become a row with no Rule ID. In the spike that crashed SSG-only generation. |
| D4 | All Rule IDs in a checklist come from **one** DISA release, and the checklist claims exactly that release. In SSG-only mode the release comes from a **release table** shipped with the generator, keyed by the **sha256 of the datastream the scan evaluated**: `datastream_sha256` in `scan-plan.env`, which `scan.sh` hashes from the same snapshot oscap reads. Each entry also names the datastream's benchmark id and version and its accepted STIG profile ids (D11). The `results.xml` benchmark and evaluated profile must match them. Anything else falls back to the profile label, marked `unverified` in the meta and summary: a newer or edited `datastream_path` that reuses the pinned ids, a hash not in the table, or a run with no recorded hash. Smoke jobs assert the pinned scans resolve through the table, so a pin bump that forgets the table fails CI. | STIG Viewer 3 matches on STIG ID + the *full* Rule ID including revision; "loose" matching is opt-in. The profile label is wrong for Ubuntu (says V2R7, is V2R8) (spike 5). Benchmark and profile ids alone can't tell pinned content from a later SSG build that reuses them. A fingerprint computed from `results.xml` can't cover everything that decides an evaluation, and two review rounds each found a new hole in one: hashing only the base `stig` selection let an edited `stig_gui` match, and local selects miss profile `extends`. Effective selection also depends on Rule/Group `selected` defaults and `requires`/`conflicts`: on ubi9, 4 of the 481 rules the `stig` profile selects are deselected by `conflicts`, so OpenSCAP evaluated 477. What a check enforces depends on `Value` definitions and OVAL content, and `results.xml` doesn't carry the OVAL at all. The datastream's exact bytes cover all of that, and `scan.sh` already records their hash for provenance. Measured:<ul><li>each spike scan's recorded `datastream_sha256` equals its pinned file's;</li><li>the amd64 and arm64 variants of the pinned Chainguard image ship byte-identical datastreams, so one entry per datastream serves both runner architectures. The RPM path uses the same bytes, donated from that image.</li><li>Entries: RHEL 8 `b0c25f6e…`, RHEL 9 `27fc84bb…`, RHEL 10 `58b6e4cb…`, Ubuntu 22.04 `5ee6c1d4…`.</li></ul> |
| D5 | **N/A reasons are derived** from OpenSCAP's platform evaluation. Compare the rule's gates with the `TestResult` platforms, walking outermost group → rule. The result maps to fixed category wording (below). A false *compound* gate (`a_and_b`) doesn't say which term failed, so terms are looked up individually as standalone platforms:<ul><li>**known true:** listed in `TestResult`;</li><li>**known false:** the platform sits on some processed rule's deciding level. OpenSCAP evaluated every platform at that level and none was true.</li><li>otherwise unknown.</li></ul>A known-false term decides the category. If no term is known false, the row gets the generic wording, with no host or package claim. Arch terms are decided separately (`arch` row). | Exact, needs no per-release list. The top-down walk prevents false "not installed" claims (spike 3). Term-level lookups stop a compound like `package_pam_and_system_with_kernel` from claiming "host" on a bootc image where the kernel term held and PAM was the missing piece. Measured: on ubi9, `#system_with_kernel` is known false and `#package_pam` known true, so those rows stay `host`. Only 1 ubi9 row (`not_container_and_wifi-iface`, neither term known) moves to generic wording. |
| D6 | DISA metadata in steps: **SSG-only** (PR 1) → **user-supplied DISA manual XCCDF** (PR 2) → **bundled compact DISA data** for each pinned datastream's release (PR 3, pending the redistribution decision). | Ship value with no new inputs first. SSG-only lacks CCIs (removed on purpose upstream in 2025), DISA wording, and manual-only rows (9 on RHEL 9 V2R9). CCIs must come from each STIG's own idents: deriving them from SRG ids matches only 60–89%. |
| D7 | **Release drift.** With a DISA skeleton newer than the content, every row whose Rule ID revision differs from the content's defaults to **Not_Reviewed**. For a many-to-one V-ID, *every* contributing rule must cite the skeleton's Rule ID: a mixed set (`SV-nr1` and `SV-nr2` against an `r2` skeleton) still evaluates part of the older requirement, so it is a mismatch too, and FINDING_DETAILS names the stale ones. The automated result for the older revision is kept in FINDING_DETAILS as evidence, not as the verdict. Once matched-release check text is available (PR 3), a result is carried forward only where the check text is unchanged; rows whose check changed stay Not_Reviewed with "check changed in VxRy". | DISA is a quarter ahead of SSG 0.1.82 on every product today. Of 206 RHEL 9 V2R9→V2R10 revision bumps, 153 changed no visible text, but ~26 changed the check (spike 6). Without the old text there's no way to tell which is which. An annotation doesn't stop STIG Viewer or STIG Manager treating a carried NotAFinding as assessed, so carrying could report a changed requirement compliant. The cost before PR 3 is measured: a V2R10 skeleton on ubi9 gives 209 Not_Reviewed rows, 200 of them revision mismatches. |
| D8 | A new `checklist` step runs between `scan` and `summarize` and **never fails the step**. <ul><li>**Before the scan**, any `checklist.ckl`, `checklist.cklb` and `checklist-meta.json` in `output_dir` are deleted. A failed scan stops the job before the checklist step, but `store_artifacts` still runs (`when: always`), so cleanup can't wait for the checklist step. Where it happens depends on the mode, so cleanup can never touch the scanned tree:<ul><li>*Image mode:* in the "Reserve output directory" step (`reserve-output.sh`); there is no caller tree to overlap.</li><li>*`rootfs_path` mode:* `reserve-output.sh` keeps doing nothing, because it can't yet rule out `output_dir` lying inside the tree. `scan.sh` deletes the files immediately after its physical-path overlap check, before `mkdir` and before any container runs. The only path that skips this cleanup is a parameter error that aborts before the overlap check. No scan happened then, and stale files can be uploaded exactly as a stale `results.xml` already can. `summarize` never runs on that path, and the hash binding below keeps a later run from reporting them.</li></ul></li><li>The checklist step deletes them again before deciding whether, and in which formats, to generate. That covers custom jobs that call the commands directly.</li><li>It writes every requested format to a staging path (`checklist.ckl.partial`, …) and renames them into place only after **all** of them succeeded. The renames are inside the same cleanup handler: on any failure, including the second rename failing after the first succeeded, it deletes the staged **and** any already-published files, so a half-written or half-published checklist is never left for `store_artifacts` to upload. SIGTERM and SIGHUP are turned into an exception, so the handler also runs on a polite termination (Python's default handling exits without unwinding). Only an outright kill (SIGKILL) skips it. The meta is written last, so such a run leaves no `generated` meta, and `summarize` fails it under `auto`/`require`. Leftover `*.partial` files are part of the pre-run cleanup.</li><li>It always writes a fresh `checklist-meta.json` recording the outcome (`generated` / `skipped` + reason / `failed` + error) and the sha256 of the `results.xml` it read.</li></ul>`summarize` gets a `checklist` parameter that **defaults to `none`**, so the documented `scan` → `summarize` command sequence keeps working unchanged. The `scan` *job* passes its own value (default `auto`, D11) explicitly. `summarize` enforces it: <ul><li>`auto` fails on `failed` and accepts `skipped`;</li><li>`require` fails on anything but `generated`;</li><li>`none` enforces nothing, but still reports a meta whose `results.xml` hash matches.</li></ul>Under `auto`/`require`, a meta that is missing or has a mismatched hash counts as `failed`. | `summarize` stays the single writer of `summary.txt`/`provenance.json` and the single gatekeeper. A gate failure never suppresses the checklist, and a checklist bug never hides the summary. Pre-scan cleanup plus binding the meta to `results.xml` means a reused `output_dir` can't publish or report a previous scan's checklist, even when the new scan fails. |
| D9 | Asset: in image mode `HOST_NAME` defaults to a sanitized image reference (`repo:tag`, ≤255 chars), overridden by `checklist_asset_name`. `TARGET_COMMENT` gets the digest and platform. **`rootfs_path` scans require `checklist_asset_name`.** Without it the checklist is skipped under `auto`, with the reason and the fix in the meta and summary, and fails under `require`. Header comment is neutral (`<!--stig-scanner-orb :: <version>-->`), not "DISA STIG Viewer". | STIG Manager requires a non-empty host name and keys the asset on it; containers have none. A `rootfs_path` basename collides: `/tmp/build-a/rootfs` and `/tmp/build-b/rootfs` would both be `rootfs`, and their reviews would merge into one asset. A path hash would be unique but change every CI run, creating a new asset each time. Only the caller knows the stable identity. No consumer checks the header comment. |
| D10 | No shipped container tailoring file. PR 4 adds a `tailoring_file` passthrough, and the generator tells "deselected by tailoring" apart from "no automated check". | Tailoring is still useful for values, the ~66 ungated rules, and site-specific additions. |
| D11 | **Gate on the evaluated profile, not on the presence of SV ids.** A checklist is generated only when the `TestResult` profile is a recognized DISA STIG profile. For pinned content, that means the scanned datastream's sha256 (D4) is in the table, and the profile is one of that entry's accepted STIG profiles. Every pinned RHEL entry (8, 9, 10) lists both `…_profile_stig` and `…_profile_stig_gui`, the same DISA STIG with GUI rules selected; the Ubuntu 22.04 entry lists `…_profile_stig` only. An edited datastream never matches an entry (D4), so no edited `stig` or `stig_gui` profile can borrow the verified release. PR 4's tailored profiles resolve through `extends`. Otherwise the step skips with a reason. For content not in the table (`datastream_path`), the profile id must end in `_profile_stig` or `_profile_stig_gui`, and the release is marked `unverified`. A STIG profile name alone proves nothing about the mapping, so **at least one selected rule must map to a DISA V-ID**, or the step skips with that reason (a skip fails under `require`). With a DISA skeleton (PR 2), at least one must match a skeleton row, or the checklist fails (wrong file). Mode: `checklist: auto` (default) / `require` / `none`, passed to both the checklist step and `summarize`. | DISA references live on the *rules*, not the profile. In the pinned RHEL 9 content, CIS L1 selects 160 rules with DISA references (152 V-IDs) and PCI-DSS selects 145. "Any SV id present" would emit a partial, mislabeled `RHEL_9_STIG` checklist on the supported `profile_id: …cis_server_l1` path. `require` lets a pipeline insist on the artifact, e.g. to catch a `profile_id` typo. The mapping minimum stops an empty checklist from passing as generated if upstream moves the reference URL again; row-count checks can't catch that, since zero rows matches zero V-IDs. |

### N/A categories and wording

`COMMENTS` holds the reason; `FINDING_DETAILS` holds the evidence. The
evidence is each mapped SSG rule, its result and the unmet gate, then a
provenance line (scanner digest, datastream sha256, target digest and
platform, scan time). The texts are a synthesis of DISA, MITRE SAF and
Chainguard phrasing. No source says any phrase is "accepted", so ISSM
review is open question 1. Sites can replace them in PR 5.

| Category | Trigger (gate terms at the outermost unmet level) | COMMENTS (draft) |
|---|---|---|
| `host` | `system_with_kernel`, `machine`, `not_container`, `not_bootc_and_not_container`, `bootc`, `grub2`, `uefi`, any other `*kernel*` term (e.g. `not_runtime_kernel_fips_enabled`), For a compound like `package_pam_and_system_with_kernel` or `not_s390x_arch_and_system_with_kernel`, the row lands here only when a host term is **known false** (D5). If it's unknown which term failed, the row gets the generic wording instead. `package_*` terms never count as host terms, even when the package name contains "kernel" (`package_kernel-tools` → `package`). Ids containing `_or_` hide their logical structure, because `results.xml` carries no CPE platform-specification. One with **no** architecture term gets the generic `platform` wording; one with an architecture term inside (e.g. `aarch64_arch_or_x86_64_arch`) follows the opaque-id rule in the `arch` row: OpenSCAP's verdict stands only when runner and target agree on every arch term in it, otherwise Not_Reviewed. | "Not Applicable to the container image. This requirement configures the host operating system (kernel, boot loader, audit subsystem, partitions or system services), which a container receives from its host and cannot implement itself. OpenSCAP determined this automatically: platform check `<gate>` was false for the scanned image. Assess it on the container host's / platform's STIG checklist. Ref: DISA Container Hardening Process Guide V1R2, Appendix B." |
| `gui` | only `package_<gui>` terms (`gdm`, …) | "Not Applicable. This requirement configures a graphical-interface component (`<pkg>`) that is not installed in this image (OpenSCAP platform check `<gate>` was false). That establishes only that `<pkg>` is absent; if the image provides a different graphical interface, assess this requirement manually." Component-specific on purpose: a false `package_gdm` proves gdm is absent, not that the image has no GUI (KDE/LightDM would pass it). So the text doesn't assert DISA's "no graphical user interface installed" condition. |
| `package` | only `package_<name>` terms | "Not Applicable. The `<pkg>` package is not installed in this image, so the configuration this requirement checks does not exist (OpenSCAP platform check `<gate>` was false). If `<pkg>` is added, this requirement applies and must be re-evaluated." Never used for a rule whose requirement *is* to install a package (audit, aide, openssh-server). In SSG those are kernel-gated, so they land in `host`. |
| `arch` | Any unmet gate level containing an `*_arch` term, alone or in a compound. A false compound like `not_s390x_arch_and_system_with_kernel` doesn't say which term failed. | OpenSCAP evaluates arch terms against the scanning host's `/proc`, not the target. So the generator decides each arch term itself, from its name (`[not_](x86_64\|aarch64\|ppc64le\|s390x)_arch`), for both the runner and the target. The target architecture is the arch component of the recorded `os/arch[/variant]` platform: `linux/arm64/v8` → `arm64`. The full platform stays in provenance.<br><br>**N/A rows.** A known-false non-arch term in the compound decides the row first (e.g. `host`), whatever the architecture. Otherwise:<ul><li>**Same known value on runner and target** (always the case when the architectures match; `not_s390x_arch` also matches across amd64/arm64): OpenSCAP's verdict holds. If an arch term is false for the target: "Not Applicable. This requirement applies only to another CPU architecture (`<gate>`)."</li><li>**Values differ, target unknown** (every `rootfs_path` scan), **or term unrecognized:** **Not_Reviewed**, "OpenSCAP marked a contributing check notapplicable on a CPU-architecture condition it evaluated against the scanning host (`<runner>`); the target's architecture is `<unknown/X>`; verify applicability manually".</li><li>**Opaque ids** (`_or_` inside the id, e.g. `aarch64_arch_or_x86_64_arch`, which the pinned RHEL 8/9/10 content defines): the logic can't be rebuilt from `results.xml`, so only OpenSCAP's verdict on the whole id exists. It carries over when every arch term found inside the id has the same known value on runner and target; otherwise **Not_Reviewed**, as above. An arch term false for the target proves nothing about an OR.</li></ul>Such an undecided N/A rule counts as **not reviewed before the V-ID's rules are combined**, so a passing sibling rule can't carry the row to NotAFinding.**Evaluated rules** (pass/fail past every gate on the runner) are recomputed for the target, not just annotated:<ul><li>if every platform on some gate level has an arch term false for the *target*, the rule's effective result is **notapplicable** (`arch`). Example: an amd64 runner scanning an s390x image passes `not_s390x_arch`, and the target fails it.</li><li>if some gate level has no alternative known to hold for the target (e.g. its only platform has an arch term that can't be decided), the effective result is **not reviewed**.</li><li>Platforms on one level are alternatives (XCCDF OR). One that holds for the target, such as a known-true non-arch platform beside `aarch64_arch`, keeps OpenSCAP's verdict.</li></ul>The original OpenSCAP result stays in FINDING_DETAILS either way. On real ubi9 results, image mode is unchanged and a `rootfs_path` run now matches it, because the kernel term is known false. PR 1 may optionally infer a `rootfs_path` target's architecture read-only from an ELF header in the tree (e.g. `/bin/sh`'s `e_machine`, never executing it). |
| `platform` | any other gate | "Not Applicable. OpenSCAP platform check `<gate>` was false for the scanned image." |
| `check` | no gate unmet; the OVAL check returned notapplicable | "Not Applicable per OpenSCAP: the automated check itself returned notapplicable for this image." |

`fail` results are never turned into N/A automatically. DISA's guide
requires each failing result to be judged on its merits. That is the
answer file's job (PR 5), and the override stays visible in the evidence.

### Status mapping (per V-ID, over all mapped SSG rules)

A rule with several `rule-result`s (XCCDF `multi-check`, or several
instances) is first combined into one result with the same precedence: any
`fail`, else any unevaluated result, else all `notapplicable`, else pass.
An unrecognized result string counts as `unknown`, never as a pass. (The
pinned content has neither: no `multi-check`, no repeated `idref`.)

Rules whose OpenSCAP result doesn't carry over to the target (the `arch`
row above: an undecided arch N/A, or an evaluated rule with an undecidable
arch gate) enter this mapping as `notchecked`; one recomputed to N/A for
the target enters as `notapplicable`.

1. any `fail` → **Open**
2. else any `error`, `unknown`, `notchecked`, `informational` → **Not_Reviewed** (FINDING_DETAILS says which)
3. else all `notapplicable` → **Not_Applicable** (+ reason)
4. else (`pass`/`fixed`, possibly mixed with `notapplicable`) → **NotAFinding**

`notselected` results are ignored. This deliberately differs from
`--stig-viewer`, which reports pass+notapplicable as notapplicable. A V-ID
with no evaluated SSG rule is omitted in SSG-only mode. With a DISA skeleton
it is Not_Reviewed: "no automated check in the scanner content" or
"deselected by profile/tailoring `<id>`".

### Format requirements (from the research; enforced by tests)

- **CKL:**
  - element order as in genuine STIG Viewer files;
  - `STIG_INFO` with `version`, `stigid`, `releaseinfo` (`Release: N Benchmark Date: DD Mon YYYY`);
  - non-empty `HOST_NAME`;
  - every `VULN` has `STATUS`, `FINDING_DETAILS`, `COMMENTS`, `SEVERITY_OVERRIDE` and `SEVERITY_JUSTIFICATION` elements, empty or not. STIG Manager throws on a missing one.
- **CKLB:**
  - `cklb_version: "1.0"`, `title`, `id`;
  - per STIG `stig_name`, `display_name`, `stig_id`, `release_info`, `uuid`, `size`, plus `version`. Without `version`, STIG Manager records `V0R…`.
  - every rule has `rule_id_src` (the full `SV-…_rule`; STIG Manager ignores `rule_id`) and a lowercase status (`not_a_finding`, `open`, `not_applicable`, `not_reviewed`). Rows with a wrong status or no `rule_id_src` are silently dropped.
  - severity override, if ever used: `overrides.severity = {severity, reason}`.
- **SSG-only text:** `Rule_Title` ← SSG title; `Vuln_Discuss` ← SSG rationale; `Fix_Text` ← SSG description (ComplianceAsCode's own convention; OCIL text is not in `results.xml`); `Check_Content` ← "Automated OpenSCAP check: <rule ids>"; `Group_Title` ← SRG id; CCIs empty. When several SSG rules map to one V-ID, the text comes from **every** contributing rule, not one of them:
  - titles are joined with " / ";
  - discussion and fix text are labelled per rule (`[rule] text`), with failing rules first, so the fix for what actually failed is never missing.
- **Provenance** in every row's FINDING_DETAILS and in `TARGET_COMMENT`: target digest **and** platform (`os/arch[/variant]`), because a digest can name a multi-platform index. Also the runner architecture. A locally built or loaded image has no registry digest; the target and scanner are then identified by the captured `image_id` that ran, with the tag only for readability, never by the mutable tag alone.

## Delivery: pull requests

Each PR can be released on its own. PR 1 is a minor release: it adds output
files and parameters and changes no existing behaviour.

### PR 1: checklist core, SSG-only (M)

- **New** `src/scripts/checklist.sh`: bash wrapper with `subst()` and an
  embedded stdlib Python heredoc, like `summarize.sh`. Port from
  `spike/xccdf2ckl.py`, keeping:
  - the top-down gate walk;
  - V-ID keying and number pairing;
  - the combining rule;
  - category wording;
  - CKL + CKLB writers;
  - a release table for the pinned STIG datastreams (RHEL 8 → V2R8 01 Jul 2026, RHEL 9 → V2R9 01 Jul 2026, RHEL 10 → V1R2 01 Jul 2026, Ubuntu 22.04 → V2R8 01 Apr 2026).

  The table is keyed by the datastream sha256 exactly as D4 defines it.
  Each entry holds the datastream file name, its benchmark id and version,
  the accepted STIG profile ids, and the DISA benchmark id, title,
  version, release and benchmark date. It ships in the generator itself.
  The README bump procedure gains a step: record each new pinned
  datastream's sha256 (the bump already pulls the image) and re-run
  `spike/fingerprint.py`'s SV-id match against the DISA releases to pick
  each entry's release.
- **New** command `src/commands/checklist.yml`. `src/jobs/scan.yml` calls it
  between `scan` and `summarize`. Parameters, using the CLAUDE.md
  four-place convention:
  - `checklist`: enum `auto` | `require` | `none`, default `auto` (D11).
    - `auto` generates for a recognized STIG profile and skips (exit 0,
      logged, reason in the meta) otherwise.
    - `require` makes a skip fail the job too.
    - `summarize` gets a matching `checklist` parameter that defaults to
      `none`, for existing standalone callers. `src/jobs/scan.yml` passes the
      job's value to both commands explicitly (D8).
  - `checklist_formats`: string, default `ckl,cklb`.
  - `checklist_asset_name`: string, default `""`. Image mode derives a
    name; `rootfs_path` requires one (D9).
- **Pre-scan cleanup** (D8):
  - image mode: `reserve-output.sh` deletes stale checklist outputs, and
    `src/jobs/scan.yml` moves the "Reserve output directory" step ahead of
    `load_image`. Today it runs after, so a missing or corrupt
    `image_tarball` would fail the job before cleanup while
    `store_artifacts` still uploads. The step touches only `output_dir`, and
    `load_image` doesn't depend on it.
  - `rootfs_path` mode: `scan.sh` deletes them right after its physical-path
    overlap check, never before it.
- **Outputs** in `output_dir`. All three are deleted at the start of every
  run, whatever the mode (D8).
  - `checklist.ckl`, `checklist.cklb`;
  - `checklist-meta.json`, always written:
    - outcome (`generated`/`skipped`/`failed`), reason, mode;
    - sha256 of the `results.xml` it read;
    - profile id; STIG id, version, release, benchmark date;
    - release source (`table`/`label`) and the datastream sha256 it was looked up by;
    - formats written, row counts by status, N/A counts by category;
    - unpaired V-ID/SV references (D3), if any;
    - generator version.

  `summarize.sh` checks the meta's `results.xml` hash, enforces the mode, and
  adds a `Checklist:` block to `summary.txt` and a `checklist` object to
  `provenance.json` (update `tests/provenance_test.sh`).
- **Tests** (`tests/checklist_test.sh`, no docker, runs in `test-scripts`).
  Small synthetic `results.xml` fixtures cover:
  - the top-down gate walk (the shadow-utils case) and compound gate ids;
  - each N/A category;
  - many-to-one and one-to-many mapping;
  - V-ID derived from SV when `#vulnerability_id` is absent;
  - every status-mapping branch and the `notselected` skip;
  - the profile gate: a CIS-profile fixture whose selected rules *do* carry
    SV references must skip, and an unknown `_profile_stig` must generate
    with release `unverified`;
  - mode enforcement in `summarize`:
    - `auto` + skipped passes; `auto` + failed fails;
    - `require` + skipped fails;
    - under `auto`/`require`, a missing meta, or one whose `results.xml` hash
      doesn't match, fails;
    - the default (`none`) with no meta passes, i.e. the existing
      `scan` → `summarize` sequence is unchanged;
  - stale outputs:
    - a pre-seeded `checklist.ckl`/`.cklb`/meta from an earlier "scan" is
      gone after a skip, after `none`, and after a run with
      `checklist_formats: cklb`;
    - in image mode, `reserve-output.sh` removes them before a scan that
      then fails;
    - in `rootfs_path` mode with `output_dir` inside the tree, the overlap
      is refused and nothing in the tree is deleted, including a pre-seeded
      `checklist.ckl` there;
  - architecture, asserted on **arch-term values**, not CPU names: an N/A
    decided by an `*_arch` gate stays Not_Applicable only when every arch
    term at the deciding level has the same known value on the runner and
    the target. That includes different CPUs that agree, e.g. `s390x_arch`
    on an amd64 runner and an arm64 target. A term whose value differs, or
    an unknown target (e.g. `rootfs_path`), gives Not_Reviewed;
  - escaping of hostile strings in the asset name and rule text;
  - golden CKL/CKLB output for one tiny fixture, with UUIDs and timestamps injected;
  - the release table: an entry is used only when the plan's
    `datastream_sha256` matches it **and** the `results.xml` benchmark id,
    version and evaluated profile match the entry. Each of these comes out
    `unverified` with the label release, never the table's:
    - a matching hash with another benchmark version or a non-accepted
      profile;
    - an unknown hash;
    - a plan with no hash;
    - a fixture that reuses the pinned benchmark and profile ids with
      edited content (different bytes, hence a different hash);
  - SSG-only text mapping: `Vuln_Discuss` ← rationale, `Fix_Text` ←
    description;
  - compound and arch gates, with container-like and bootc-like
    true-platform sets, across five setups:
    - amd64 runner + amd64 image;
    - amd64 runner + s390x image;
    - arm64 runner + `linux/arm64/v8` image (variant parsing);
    - `rootfs_path` with the target unknown;
    - a kernel-present target where `package_pam_and_system_with_kernel`
      fails on PAM, which must give `package`, not `host`.

    Cover N/A rows and evaluated rules. An evaluated `not_s390x_arch` rule
    on an s390x target must become notapplicable, and on an unknown target
    Not_Reviewed. The spike fixture in this PR's review already produces the
    expected tables;
  - multi-rule V-IDs: title, discussion and fix text include every
    contributing rule, failing rules first;
  - provenance includes the target platform, and falls back to the image
    id for an image without registry digests;
  - an evaluated rule whose gate level is `aarch64_arch` OR a known-true
    platform keeps its verdict on a foreign-architecture target;
  - a mixed package compound (`package_gdm_and_package_pam`) is `package`,
    not `gui`;
  - a V-ID combining a passing rule with an undecided arch N/A rule (amd64
    runner, s390x or unknown target) is Not_Reviewed, not NotAFinding; with
    a failing rule instead it stays Open;
  - an opaque id with an arch term inside (`s390x_arch_or_package_foo`,
    `aarch64_arch_or_x86_64_arch`) keeps OpenSCAP's verdict when the
    term's value is the same on runner and target, and is Not_Reviewed
    otherwise, both as an N/A gate and as an evaluated rule's gate;
  - a `_profile_stig` fixture whose rules carry no DISA references is
    skipped under `auto` and fails under `require`;
  - a writer failure after the first format leaves neither final nor
    staged checklist files, and so does a failure of the second rename
    after the first succeeded, or a SIGTERM between the two renames;
  - repeated rule-results: a rule with `fail` and `pass` results is Open,
    not NotAFinding; `pass` + `notapplicable` is a pass; an unrecognized
    result string gives Not_Reviewed;
  - unpaired references: a rule with `V-n` and an extra `V-m` (no
    `SV-m`), or an extra `SV-k` (no `V-k`), yields only the `V-n` row,
    lists the others as unpaired, and doesn't crash SSG-only mode;
  - (PR 2) a many-to-one V-ID whose contributors cite `r1` and `r2`
    against an `r2` skeleton is Not_Reviewed, naming `r1` as stale;
  - `rootfs_path` without `checklist_asset_name`: `auto` skips with a reason,
    `require` fails;
- **CI** (`.circleci/test-deploy.yml`):
  - `smoke-rhel9`, `smoke-rhel8-auto`, `smoke-ubuntu2204`: both files exist
    and parse. The meta's release source is `table` and its release equals the table's (this fails if a pin bump forgot the table). Every
    Not_Applicable row has non-empty COMMENTS. Row count equals the number
    of distinct V-IDs in the results. No hard-coded counts (CLAUDE.md
    smoke rule).
  - `smoke-debian12-auto`, `smoke-rhel9-cis`, `smoke-fedora`: checklist
    skipped, not failed, and no checklist files in `output_dir`.
    `smoke-rhel9-cis` is the regression test for D11, since its rules carry
    SV references. `smoke-wolfi`: skipped until PR 6.
  - Negative test (like `smoke-hollow`): `checklist: require` on the CIS
    profile must fail `summarize`.
  - `smoke-rootfs`: with no `checklist_asset_name`, the checklist is skipped
    with the D9 reason. A second `rootfs_path` smoke sets the name and
    asserts the checklist is generated, with arch-gated N/A rows Not_Reviewed
    (the target architecture is unknown).
  - `smoke-tarball`: also covers the reordered "Reserve output directory"
    step running before `load_image`.
  - New `checklist-validator` job (docker `cimg/node`; pinned versions via
    a committed lockfile; smoke artifacts via workspace). It runs three
    checks:
    1. STIG Manager's `reviewsFromCkl`/`reviewsFromCklb` (as in
       `spike/validate.mjs`) with `unreviewed: 'always'` and
       `unreviewedCommented: 'notchecked'`, so every Not_Reviewed row imports
       as `notchecked`. The check fails on:
       - any parser-reported error or a missing revision;
       - a parsed `benchmarkId` or `revisionStr` (e.g. `RHEL_9_STIG`,
         `V2R9`) that differs from the STIG id and release in
         `checklist-meta.json`. Every row can import while the checklist
         still lands on the wrong STIG or release;
       - parsed reviews ≠ rows written;
       - a parsed `result` tally (pass / fail / notapplicable / notchecked)
         that differs from the status counts in `checklist-meta.json`. This
         catches a writer regression that changes outcomes without changing
         the row count.
    2. DISA's CKLB schema, downloaded at test time with its sha256 pinned
       (`8b88205d…`), as in `spike/cklb_schema_check.py`. It fails on any
       error against the patched schema, and on any raw-schema error other
       than the documented extension fields.
    3. *Optional, non-blocking at first:* MITRE `sv3-runner`, which opens
       the `.cklb` in real STIG Viewer 3 headless.

    CI-only tooling: the scan's egress table is unchanged.
- **Docs**:
  - README "Outputs" and a "STIG Viewer checklists" section: statuses, N/A
    categories, SSG-only limits (no CCIs, SSG wording, no manual-only rows,
    release = content's release), and how to import into STIG Viewer 3
    and STIG Manager.
  - CHANGELOG.
- **Manual acceptance** (PR description): import a CI-produced `.ckl` and
  `.cklb` into STIG Viewer 3.8.x; screenshot the N/A comments.

### PR 2: DISA skeleton from a user-supplied file (S–M)

- **Parameter** `stig_xccdf_path`: a DISA `*_Manual-xccdf.xml`, or the DISA
  zip (member read in memory with `zipfile`, never extracted to disk;
  size-capped). It is snapshotted and hashed like `datastream_path` and
  parsed with `xml.etree` as untrusted data.
- **Validation:** `Benchmark/@id` must match the expected STIG for the
  resolved `target_base` (`RHEL_9_STIG` for `rhel9`, …), and at least one
  selected rule must map to one of its V-IDs (D11). On a mismatch the
  checklist fails and `summarize` reports it.
- **Behaviour:**
  - Every DISA Vuln becomes a row with DISA text and CCIs, and every Rule
    ID comes from the skeleton (D4).
  - Manual-only Vulns are Not_Reviewed.
  - Rows whose content revision differs from the skeleton's are
    Not_Reviewed (D7). The automated result for the older revision stays in
    FINDING_DETAILS. PR 3 later carries the unchanged checks.
  - Meta and provenance record the file's sha256, release and mismatch count.
- **Tests:** a tiny hand-made DISA-format XCCDF fixture (no DISA files in
  the repo before the PR 3 decision); revision-mismatch, added/removed-Vuln
  and wrong-STIG cases.
- **CI:** a `smoke-rhel9` variant that fetches the DISA zip in CI, pinned
  by sha256 from `dl.dod.cyber.mil` (no login; older releases persist
  there, e.g. RHEL 9 V2R4–V2R10).

### PR 3: bundled DISA data for the pinned content (M)

Gated on open question 2.

- **Maintainer script** (`tools/refresh-stig-data.py`, not shipped in the
  orb). It turns each DISA zip matching a pinned datastream's
  release (D4 table) into compact JSON: V-ID → rule id, STIG id,
  severity, title, discussion, check, fix, CCIs, legacy ids.
  - The JSON is committed gzip+base64 as `src/scripts/stig-data/<stig>.sh`
    heredocs, ~150 KB each (less for Ubuntu).
  - A separate `run` step writes it out. It's an included script, so no
    128 KB env-var limit applies and orb-tools RC009 is not tripped.
  - The packed orb stays well under 8 MB. The four raw XCCDFs would be ~5 MB.
- **Default behaviour:** "DISA skeleton from bundled data" for content in
  the table. A user file newer than the bundle (PR 2) gets D7 precisely:
  carry the result where `check_content` is unchanged; otherwise
  Not_Reviewed with "check changed in VxRy".
- **Tests:** `tests/pinned_refs_test.sh` asserts the bundled release equals
  each pinned datastream's table entry and the bundle's source-zip sha256
  matches the recorded one. The README bump procedure gains the refresh
  step.
- **Fallback if bundling full text is declined:** bundle only V-ID → CCI
  maps (~3 KB per STIG). These are factual identifiers, and they fill the
  biggest SSG-only gap.

### PR 4: `tailoring_file` passthrough (S)

- **Parameter** `tailoring_file`: snapshotted and hashed like
  `datastream_path` and passed as `--tailoring-file`. `profile_id` must
  name the tailored profile, which is checked before the scan.
  Provenance records the sha256 and tailored profile id.
- **Checklist:** tailoring-deselected rules show as "deselected by
  tailoring `<profile>`": Not_Reviewed with a skeleton, omitted SSG-only.
  Refined values are listed in the affected rows' FINDING_DETAILS.
- **README:** use tailoring for values and additions. Don't deselect host
  rules to tidy the report, because the checklist already explains them.

### PR 5: answer file (M)

- **Parameter** `checklist_answers`: JSON, snapshotted and hashed. It
  holds per-row overrides keyed by V-ID (`status`, `comments`,
  `finding_details_append`) and category text overrides (e.g. a site whose
  eMASS record has the host as a common control provider can say
  "inherited from `<CCP>`").
  - Applied after the automatic result.
  - The automated result stays in FINDING_DETAILS ("Automated result:
    Open; set to Not_Applicable by answer file sha256:…").
  - Modeled on Evaluate-STIG answer files.
- **Curated default answer set (opt-in, reviewed per release):** only for
  manual-only Vulns that are plainly host-level in the bundled releases
  (e.g. RHEL 9 V-257782, hardware RNG entropy gatherer). This is the one
  hand-maintained "container STIG" artefact that earns its keep.

### PR 6: Wolfi / Chainguard GPOS SRG checklist (S–M)

Chainguard's GPOS datastream uses DISA GPOS SRG rule ids as XCCDF rule ids
(`xccdf_mil.disa.stig_rule_SV-263651r982555_rule`). Every rule carries CCIs,
and N/A rules are gated on `cpe:/o:notapplicable` with a per-rule rationale.

- Emit a GPOS SRG checklist: 198 rows on `chainguard/static`.
  - Add the Chainguard benchmark/profile pair
    (`xccdf_basic_profile_.check`) to the D11 table, so the profile gate
    admits it.
  - STIG id and release come from an SV-id match against the GPOS SRG releases (as `spike/fingerprint.py` does for the STIGs). The
    content says v3r2; DISA's current GPOS SRG is V3R4.
  - N/A COMMENTS use Chainguard's rationale, labelled as the vendor's.
- README states plainly that this is an SRG checklist and Chainguard's
  vendor profile, not a DISA STIG.

### Independent: `smoke-rhel10`

The spike confirmed `ssg-rhel10-ds.xml` in the pin has `content_profile_stig`
(V1R2). That is CLAUDE.md's precondition, so the job can be added any time;
PR 1's assertions then cover RHEL 10.

## Risks

| Risk | Mitigation |
|---|---|
| A consumer rejects files that STIG Manager's parser accepts (STIG Viewer 3, eMASS). | Format requirements above; DISA CKLB schema check; optional headless SV3 run (`sv3-runner`); human import acceptance in PR 1. eMASS's own import rules need a CAC to read, so ask the customer for a test upload. |
| Assessors reject the default wording. | ISSM review before PR 1 merges; overridable in PR 5; wording quotes DISA where DISA has wording (GUI). |
| Release drift: SSG one DISA quarter behind, and STIG Viewer 3 matches revisions strictly. | D4 keeps each checklist internally consistent and honest about its release. PR 2/3 let users target the current release, with per-row drift handling (D7). Pin bumps refresh. Document SV3's "loose" match option. |
| `rootfs_path` trees built from image layers lack `/.dockerenv`, so the ~35 RHEL 9 rules gated on the container marker (partitions, mounts, sniffer, wireless) evaluate and likely fail. | Existing scan behaviour, not checklist logic. Document it in the README's `rootfs_path` notes. FINDING_DETAILS shows the gate evaluation, so the cause is visible. |
| An image with `kernel-core` (bootc) turns ~348 host rules back on. | Correct behaviour: such an image is a host. The checklist just reflects it. |
| Arch gates read the runner's kernel (`/proc`), not the target. A foreign-architecture bootc image or `rootfs_path` tree with `kernel-core` passes the kernel gate, and its arch gates are then judged by the runner. | `scan.sh` records `runner_arch` (`uname -m`, normalized) in `scan-plan.env`. Image mode already records the target `platform`; `rootfs_path` has none, so its target architecture is unknown. The generator decides each arch term for the target itself (category table):<ul><li>an arch-decided N/A stands only when the runner and target agree on that term (for an opaque `_or_` id, on every arch term inside it); otherwise the rule counts as not reviewed before its V-ID's rules are combined.</li><li>An **evaluated** rule's verdict is recomputed, not annotated. It becomes notapplicable when every alternative on some gate level is false for the target, and Not_Reviewed when no alternative is known to hold. An alternative that holds for the target, such as a known-true non-arch platform on the same level, keeps OpenSCAP's verdict.</li></ul>Covered by the PR 1 architecture tests. |
| Hostile content in `results.xml` or user DISA files. | Stdlib parsers, expat defaults (no external entities), size caps, writers that escape everything (`ElementTree`, `json`), writes only inside `output_dir`. |
| Checklist size (RHEL 9 CKL ~2 MB, CKLB ~1.3 MB). | Fine as artifacts; `checklist_formats` can drop one. |

## Open questions

1. **Wording sign-off.** Can a customer ISSM review the category texts
   above, especially `host`?
2. **Redistribution.** The research found no Distribution Statement A or
   licence terms on DISA STIG files. They are UNCLASSIFIED and downloadable
   without a CAC, but RHEL/Ubuntu STIGs are "Developed by Red Hat/Canonical
   and DISA", so public-domain status isn't clean. Prior art:
   ComplianceAsCode (BSD-3) commits DISA XCCDFs to its repo. Decide: full
   bundle, CCI-only bundle, or none (PR 3).
3. **Asset defaults.** `MARKING` (`CUI`?), `ROLE`, `TECH_AREA` for container
   images: what does the customer's STIG Manager / eMASS workflow expect?
4. **On by default?** `checklist: auto` adds ~3 MB of artifacts per STIG scan.
   Proposed: on by default in the next minor release.
5. **Planning trail.** The trail that motivated this (P6.1b / "09 §6") isn't
   in this repo. Reconcile its deliverable definition with this plan.
6. **DISA oddity.** RHEL 8 V2R9 downloads on its own but is missing from the
   October 2026 library compilation, which lists it as "sunset/removed".
   Confirm before targeting it in PR 2/3.
