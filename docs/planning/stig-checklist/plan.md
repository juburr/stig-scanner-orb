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
On ubi9 the 366 N/A rows split into 331 host, 23 GUI, 11 package and 1
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
| D3 | Rows are keyed on **V-ID**. V-ID comes from SSG's `#vulnerability_id` reference, or, for content older than SSG 0.1.82, from the SV number. Each `SV-n…_rule` pairs with `V-n` by number. | V-IDs are stable across releases; rule-revision suffixes and even STIG IDs are not. The mapping is many-to-many (spike 4). |
| D4 | All Rule IDs in a checklist come from **one** DISA release, and the checklist claims exactly that release. In SSG-only mode the release comes from a **fingerprint table** for the pinned content, checked by a test. Unknown content falls back to the profile label, marked `unverified` in the meta and summary. | STIG Viewer 3 matches on STIG ID + the *full* Rule ID including revision; "loose" matching is opt-in. The profile label is wrong for Ubuntu (says V2R7, is V2R8) (spike 5). |
| D5 | **N/A reasons are derived** from OpenSCAP's platform evaluation. Compare the rule's gates with the `TestResult` platforms, walking outermost group → rule. Compound gate ids are split on `_and_`. The result maps to fixed category wording (below). | Exact, needs no per-release list. The top-down walk prevents false "not installed" claims (spike 3). |
| D6 | DISA metadata in steps: **SSG-only** (PR 1) → **user-supplied DISA manual XCCDF** (PR 2) → **bundled compact DISA data** for each pinned datastream's release (PR 3, pending the redistribution decision). | Ship value with no new inputs first. SSG-only lacks CCIs (removed on purpose upstream in 2025), DISA wording, and manual-only rows (9 on RHEL 9 V2R9). CCIs must come from each STIG's own idents: deriving them from SRG ids matches only 60–89%. |
| D7 | **Release drift.** With a DISA skeleton newer than the content, a result is carried forward only where the check text is unchanged (needs PR 3's matched-release data); otherwise the row is Not_Reviewed with a note. Before PR 3, results are carried and every bumped row is annotated. | DISA is a quarter ahead of SSG 0.1.82 on every product today. Of 206 RHEL 9 V2R9→V2R10 revision bumps, 153 changed no visible text; ~26 changed the check (spike 6). |
| D8 | A new `checklist` step runs between `scan` and `summarize` and **never fails the step**. It writes `checklist.ckl`/`.cklb` plus `checklist-meta.json`. `summarize` reports the outcome and fails the job only if a checklist was required and not produced. | `summarize` stays the single writer of `summary.txt`/`provenance.json` and the single gatekeeper. A gate failure never suppresses the checklist; a checklist bug never hides the summary. |
| D9 | Asset: `HOST_NAME` defaults to a sanitized image reference (`repo:tag`, ≤255 chars) or the `rootfs_path` basename, overridden by `checklist_asset_name`. `TARGET_COMMENT` gets the digest and platform. Header comment is neutral (`<!--stig-scanner-orb :: <version>-->`), not "DISA STIG Viewer". | STIG Manager requires a non-empty host name and keys the asset on it; containers have none. No consumer checks the header comment. |
| D10 | No shipped container tailoring file. PR 4 adds a `tailoring_file` passthrough, and the generator tells "deselected by tailoring" apart from "no automated check". | Tailoring is still useful for values, the ~66 ungated rules, and site-specific additions. |

### N/A categories and wording

`COMMENTS` holds the reason; `FINDING_DETAILS` holds the evidence. The
evidence is each mapped SSG rule, its result and the unmet gate, then a
provenance line (scanner digest, datastream sha256, target digest and
platform, scan time). The texts are a synthesis of DISA, MITRE SAF and
Chainguard phrasing. No source says any phrase is "accepted", so ISSM
review is open question 1. Sites can replace them in PR 5.

| Category | Trigger (gate terms at the outermost unmet level) | COMMENTS (draft) |
|---|---|---|
| `host` | `system_with_kernel`, `machine`, `not_container`, `not_bootc_and_not_container`, `bootc`, `grub2`, `uefi`, any `*kernel*` term, including compounds like `package_pam_and_system_with_kernel` and every arch gate in current content | "Not Applicable to the container image. This requirement configures the host operating system (kernel, boot loader, audit subsystem, partitions or system services), which a container receives from its host and cannot implement itself. OpenSCAP determined this automatically: platform check `<gate>` was false for the scanned image. Assess it on the container host's / platform's STIG checklist. Ref: DISA Container Hardening Process Guide V1R2, Appendix B." |
| `gui` | only `package_<gui>` terms (`gdm`, …) | "Not Applicable. No graphical user interface is installed in the image (`<pkg>` not installed; OpenSCAP platform check `<gate>` was false). DISA: 'If the system does not have any graphical user interface installed, this requirement is Not Applicable.'" (DISA's own wording; 23 RHEL 9 rules use it.) |
| `package` | only `package_<name>` terms | "Not Applicable. The `<pkg>` package is not installed in this image, so the configuration this requirement checks does not exist (OpenSCAP platform check `<gate>` was false). If `<pkg>` is added, this requirement applies and must be re-evaluated." Never used for a rule whose requirement *is* to install a package (audit, aide, openssh-server). In SSG those are kernel-gated, so they land in `host`. |
| `arch` | only `*_arch` terms (none observed in the pinned STIG content) | "Not Applicable. This requirement applies only to another CPU architecture (`<gate>`)." |
| `platform` | any other gate | "Not Applicable. OpenSCAP platform check `<gate>` was false for the scanned image." |
| `check` | no gate unmet; the OVAL check returned notapplicable | "Not Applicable per OpenSCAP: the automated check itself returned notapplicable for this image." |

`fail` results are never turned into N/A automatically. DISA's guide
requires each failing result to be judged on its merits. That is the
answer file's job (PR 5), and the override stays visible in the evidence.

### Status mapping (per V-ID, over all mapped SSG rules)

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
- **SSG-only text:** `Rule_Title` ← SSG title; `Vuln_Discuss` ← SSG rationale; `Fix_Text` ← SSG description (ComplianceAsCode's own convention; OCIL text is not in `results.xml`); `Check_Content` ← "Automated OpenSCAP check: <rule ids>"; `Group_Title` ← SRG id; CCIs empty.

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
  - a fingerprint table for the pinned STIG datastreams (RHEL 8 → V2R8 01 Jul 2026, RHEL 9 → V2R9 01 Jul 2026, RHEL 10 → V1R2 01 Jul 2026, Ubuntu 22.04 → V2R8 01 Apr 2026).

  The table holds DISA benchmark id, title, version, release and benchmark date.
- **New** command `src/commands/checklist.yml`. `src/jobs/scan.yml` calls it
  between `scan` and `summarize`. Parameters, using the CLAUDE.md
  four-place convention:
  - `checklist`: enum `auto` | `none`, default `auto`. `auto` emits when the
    results carry DISA SV ids and skips (exit 0, logged) otherwise.
  - `checklist_formats`: string, default `ckl,cklb`.
  - `checklist_asset_name`: string, default `""` (D9).
- **Outputs** in `output_dir`:
  - `checklist.ckl`, `checklist.cklb`;
  - `checklist-meta.json`: STIG id, version, release, benchmark date, release source `fingerprint`/`label`, row counts by status, N/A counts by category, generator version.

  `summarize.sh` reads the meta and adds a `Checklist:` block to
  `summary.txt` and a `checklist` object to `provenance.json` (update
  `tests/provenance_test.sh`).
- **Tests** (`tests/checklist_test.sh`, no docker, runs in `test-scripts`).
  Small synthetic `results.xml` fixtures cover:
  - the top-down gate walk (the shadow-utils case) and compound gate ids;
  - each N/A category;
  - many-to-one and one-to-many mapping;
  - V-ID derived from SV when `#vulnerability_id` is absent;
  - every status-mapping branch and the `notselected` skip;
  - the non-STIG skip;
  - escaping of hostile strings in the asset name and rule text;
  - golden CKL/CKLB output for one tiny fixture, with UUIDs and timestamps injected;
  - the fingerprint table matching every pinned STIG datastream. It reads
    SV-id lists from a committed fixture regenerated on pin bumps; add that
    step to the README bump procedure.
- **CI** (`.circleci/test-deploy.yml`):
  - `smoke-rhel9`, `smoke-rhel8-auto`, `smoke-ubuntu2204`: both files exist
    and parse. The meta's release equals the fingerprint table's. Every
    Not_Applicable row has non-empty COMMENTS. Row count equals the number
    of distinct V-IDs in the results. No hard-coded counts (CLAUDE.md
    smoke rule).
  - `smoke-debian12-auto`, `smoke-rhel9-cis`, `smoke-fedora`: checklist
    skipped, not failed. `smoke-wolfi`: skipped until PR 6.
  - New `checklist-validator` job (docker `cimg/node`; pinned versions via
    a committed lockfile; smoke artifacts via workspace). It runs three
    checks:
    1. STIG Manager's `reviewsFromCkl`/`reviewsFromCklb` (as in
       `spike/validate.mjs`) with `unreviewed: 'always'`, asserting parsed
       reviews == rows written.
    2. DISA's CKLB schema, downloaded at test time with its sha256 pinned
       (`8b88205d…`), validated raw-minus-`version` and patched (as in
       `spike/cklb_schema_check.py`).
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
  resolved `target_base` (`RHEL_9_STIG` for `rhel9`, …). On a mismatch the
  checklist fails and `summarize` reports it.
- **Behaviour:**
  - Every DISA Vuln becomes a row with DISA text and CCIs, and every Rule
    ID comes from the skeleton (D4).
  - Manual-only Vulns are Not_Reviewed.
  - Rows whose content revision differs get D7's annotation.
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
  fingerprinted release into compact JSON: V-ID → rule id, STIG id,
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
  each pinned datastream's fingerprint and the bundle's source-zip sha256
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
  - STIG id and release come from a fingerprint against the GPOS SRG. The
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
| Arch gates read the runner's kernel (`/proc`), not the image. | Every arch gate in current STIG content is also kernel-gated, so it falls under `host`. Provenance records the image platform. |
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
