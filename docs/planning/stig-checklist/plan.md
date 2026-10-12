# Plan: STIG Viewer checklists with container N/A justifications

Status: **proposed**, 2026-10-12. Owner: TBD.
Inputs: [spike.md](spike.md) (measured on real scans) and the research report
[`../reports/STIG checklist output for containers.md`](../reports/STIG%20checklist%20output%20for%20containers.md).

## Goal

A scan whose profile is a DISA STIG also produces a STIG Viewer checklist
(`checklist.ckl` and `checklist.cklb`). An ISSM can load it into STIG Viewer,
STIG Manager or eMASS without re-keying anything. Every Not_Applicable row
carries a justification that says *why*: host-level control, package not
installed, wrong architecture. That replaces ~370 bare N/A rows the ISSM
would otherwise have to explain.

### Non-goals

- Shipping a hand-curated "container STIG" tailoring file that deselects
  ~400 host rules. Deselected rules vanish from the evidence, and the N/A
  reasons can be derived exactly without one (spike findings 2, 10).
- Asserting control inheritance. That is an RMF/eMASS decision made at the
  control level by the ISSM, not something a scan can know (see "Wording").
- Checklists for non-STIG profiles (Wolfi GPOS/basic, Debian CIS, Fedora
  standard, a CIS `profile_id` override). They are skipped with a log line.
- Changing scan results, gates or the network posture. The generator runs
  offline on the runner, after the scan, from `results.xml`.

## Decisions

| # | Decision | Why |
|---|---|---|
| D1 | Write our own generator: Python stdlib, run on the runner like `summarize.sh`. Not `oscap --stig-viewer`, not MITRE SAF CLI. | `--stig-viewer` emits zero rule-results on OpenSCAP 1.3.6 (all RPM targets) and doesn't produce a checklist anyway. SAF would add a Node toolchain and image pull to every scan. `results.xml` already has everything needed (spike 1, 8). |
| D2 | Emit **both** `.ckl` (STIG Viewer 2 XML) and `.cklb` (STIG Viewer 3 JSON) from one internal model; a parameter can pick one. | Both are cheap from one model and consumers differ. See the research report for each consumer's support. |
| D3 | N/A justification is **derived** from OpenSCAP's platform evaluation (rule gates vs `TestResult` true platforms, walked outermost group → rule), mapped to a small category set with fixed wording. | Exact, not heuristic. Needs no per-RHEL-release list. The top-down walk prevents false "not installed" claims (spike 3). |
| D4 | The DISA release a checklist claims comes from a **fingerprint table** keyed by the pinned content, checked by a test. Content not in the table falls back to the profile label, marked `unverified`. | The profile label is wrong for Ubuntu (says V2R7, is V2R8) (spike 5). A wrong release breaks row matching in STIG Manager. |
| D5 | DISA metadata in three steps: SSG-only (PR 1) → user-supplied DISA manual XCCDF (PR 2) → bundled compact DISA data for the release each pinned datastream targets (PR 3). | Ship value first with no new inputs. SSG-only lacks CCIs, DISA wording and manual-only rows; a user file fixes that today; bundling makes it zero-config. Size is ~150 KB per STIG (spike 7). Bundling depends on the redistribution check in the research report. |
| D6 | Release drift: when the DISA skeleton is newer than the content, carry a result forward only where the check text didn't change; otherwise Not_Reviewed with a note. Without the matched-release data, carry it and annotate. | 153 of 206 RHEL 9 V2R9→V2R10 revision bumps changed no check, fix or other field; ~26 changed the check (spike 6). |
| D7 | No shipped container tailoring file. Add a `tailoring_file` passthrough (PR 4), and the generator tells "deselected by tailoring" apart from "no automated check". | See non-goals. A passthrough is generally useful and costs little. |
| D8 | A checklist step runs between `scan` and `summarize`. It **never fails the step**: it writes `checklist.ckl`/`.cklb` plus `checklist-meta.json`. `summarize` reports the outcome and, if a checklist was required and not produced, fails the job. | Keeps `summarize` the single writer of `summary.txt`/`provenance.json` and the single gatekeeper. A gate failure never prevents the checklist, and a checklist bug never hides the summary. |
| D9 | Asset identity: `HOST_NAME` defaults to a sanitized image reference (`repo:tag`, ≤255 chars) or the `rootfs_path` basename; `checklist_asset_name` overrides it. `TARGET_COMMENT` records the digest. | STIG Manager requires `host_name` and keys the asset on it. Containers have no hostname. |

### Wording (N/A categories)

The text is short, factual, and states only what the scan observed. It
says where the requirement must be assessed, not that it is satisfied.

| Category | Trigger (unmet gate at the outermost failing level) | COMMENTS text (draft) |
|---|---|---|
| `host` | `system_with_kernel`, `machine`, `not_container`, `not_bootc_and_not_container`, `grub2*`, any gate combined with `…_and_system_with_kernel` | "Not applicable to the container image: host-level requirement (applies only to a system that boots its own kernel). OpenSCAP platform check `<gate>` was false for this image. Assess on the host platform's checklist." |
| `package` | only `package_<name>` gates | "Not applicable: applies only when `<name>` is installed; it is not installed in this image (OpenSCAP platform check `package_<name>` was false)." |
| `arch` | `*_arch` gates | "Not applicable: specific to a CPU architecture other than this image's (`<gate>`)." |
| `platform` | any other gate | "Not applicable: OpenSCAP platform check `<gate>` was false for this image." |
| `check` | no gate unmet; the OVAL check itself returned notapplicable | "OpenSCAP's automated check reported this requirement not applicable to the image." |

`FINDING_DETAILS` always lists each mapped SSG rule with its result and the
unmet gate, then the provenance line (scanner digest, datastream sha256,
target digest, scan time). Users can replace the category texts in PR 5. An
ISSM should approve the default wording before PR 1 merges (open question 1).

### Status mapping (per DISA Vuln, over all mapped SSG rules)

1. any `fail` → **Open**
2. else any `error`, `unknown`, `notchecked`, `informational` → **Not_Reviewed** (FINDING_DETAILS says which)
3. else all `notapplicable` → **Not_Applicable** (+ justification)
4. else (`pass`/`fixed`, possibly mixed with `notapplicable`) → **NotAFinding**

`notselected` results are ignored. A Vuln with no evaluated SSG rule is
dropped in SSG-only mode. With a DISA skeleton it becomes Not_Reviewed,
saying "no automated check" or "deselected by profile/tailoring".

## Delivery: pull requests

Each PR is independently releasable. PR 1 is a minor release (adds output
files and parameters; changes no existing behaviour).

### PR 1: checklist core, SSG-only (M)

- **New** `src/scripts/checklist.sh`: bash wrapper with the `subst()` shim and
  an embedded stdlib Python heredoc, like `summarize.sh`. Port from
  `spike/xccdf2ckl.py`, keeping: top-down gate walk, many-to-many V-ID pairing
  by number, combining rule, category wording, CKL + CKLB writers, and a release
  fingerprint table for the four pinned STIG datastreams.
- **New** command `src/commands/checklist.yml`. Job `src/jobs/scan.yml` calls it
  between `scan` and `summarize`. Parameters, using the CLAUDE.md four-place
  convention:
  - `checklist`: enum `auto` | `none`, default `auto`. `auto` emits when the
    profile carries DISA SV references and skips (exit 0) otherwise.
  - `checklist_formats`: string, default `ckl,cklb`.
  - `checklist_asset_name`: string, default `""` (D9).
- **Outputs** in `output_dir`: `checklist.ckl`, `checklist.cklb`, and
  `checklist-meta.json` (STIG id, version, release, benchmark date, release
  source `fingerprint`/`label`, row counts by status, N/A counts by category,
  generator version). `summarize.sh` reads the meta and adds a `Checklist:`
  block to `summary.txt` and a `checklist` object to `provenance.json`
  (update `tests/provenance_test.sh`).
- **Tests** (`tests/checklist_test.sh`, no docker, runs in `test-scripts`):
  small synthetic `results.xml` fixtures for: top-down gate walk (the
  shadow-utils case), package/arch/check categories, many-to-one and
  one-to-many mapping, every status-mapping branch, `notselected` skip,
  non-STIG profile skip, XML/JSON escaping of hostile strings in asset
  name and rule text, and a byte-for-byte golden CKL/CKLB for one tiny
  fixture (UUIDs and timestamps injected for determinism). Also a test
  that the fingerprint table names a release for every pinned STIG
  datastream. It reads the datastream SV-id list from a committed
  fixture regenerated on pin bumps; the README bump procedure gets that
  step.
- **CI** (`.circleci/test-deploy.yml`):
  - `smoke-rhel9`, `smoke-rhel8-auto`, `smoke-ubuntu2204`: assert both files
    exist and parse (`xmllint --noout`, `python3 -m json.tool`). Assert the
    release in `checklist-meta.json` equals the fingerprint table's, and that
    every Not_Applicable row has non-empty COMMENTS. No exact row counts:
    they drift with SSG content (CLAUDE.md smoke-test rule).
  - `smoke-wolfi`, `smoke-debian12-auto`, `smoke-rhel9-cis`: assert the
    checklist was skipped, not failed.
  - New `checklist-validator` job (docker `cimg/node`, pinned
    `@nuwcdivnpt/stig-manager-client-modules` via a committed lockfile):
    runs STIG Manager's `reviewsFromCkl`/`reviewsFromCklb` over the smoke
    artifacts (persisted via workspace), as `spike/validate.mjs` does. This is
    CI-only tooling, so the scan's egress table is unchanged.
- **Docs**: README "Outputs" + a short "STIG Viewer checklists" section
  (what each status means, the N/A categories, SSG-only limits: no CCIs, SSG
  wording, no manual-only rows, release = content's release). CHANGELOG.
- **Manual acceptance** (in the PR description): import a CI-produced
  `.ckl` and `.cklb` into STIG Viewer 3, plus 2.18 if still in use, and
  screenshot. Check that the N/A comments show in the expected column.

### PR 2: DISA skeleton from a user-supplied file (S–M)

- Parameter `stig_xccdf_path`: a DISA manual XCCDF (`*_Manual-xccdf.xml`) or
  the DISA zip. The file is snapshotted and hashed like `datastream_path`. The
  zip member is read in memory with `zipfile`, never extracted to disk, and
  entries are size-capped. Parse with `xml.etree` as untrusted data.
- Validation: the XCCDF `Benchmark/@id` must match the expected STIG for
  the resolved `target_base` (`RHEL_9_STIG` for `rhel9`, …). On a mismatch,
  the checklist fails and `summarize` reports it.
- Behaviour: every DISA Vuln becomes a row with DISA text and CCIs.
  Manual-only Vulns are Not_Reviewed. Rows whose `Rule_ID` revision differs
  from the content's get the D6 annotation. `checklist-meta.json` and
  provenance record the file's sha256, release, and mismatch count.
- Tests: fixtures with a tiny hand-made DISA XCCDF (never commit DISA
  files to the test suite, to keep the repo free of DISA content until PR
  3's decision); revision-mismatch and wrong-STIG cases.
- CI: `smoke-rhel9` variant with a DISA zip fetched *in CI only* from
  `dl.dod.cyber.mil` (pin the zip's sha256), or a cached copy if the
  egress policy for CI forbids it.

### PR 3: bundled DISA data for the pinned content (M)

Gated on the redistribution check (open question 2).

- Maintainer script (`tools/refresh-stig-data.py`, not shipped in the orb)
  turns the DISA zip(s) matching each pinned datastream's fingerprinted
  release into a compact JSON per STIG (V-ID → DISA rule id, STIG id,
  severity, titles, discussion, check, fix, CCIs, legacy ids). The JSON is
  committed gzip+base64 as `src/scripts/stig-data/<stig>.sh` heredocs, each
  ~150 KB. A separate `run` step writes it to a temp dir. It's an included
  script, so no 128 KB env-var limit applies and orb-tools RC009 is not
  tripped. Keeps the packed orb well under 8 MB.
- Default behaviour becomes "DISA skeleton from bundled data" for content in
  the table. With PR 2's user file newer than the bundle, D6 is applied
  precisely: carry the result where `check_content` is unchanged; otherwise
  Not_Reviewed with "check changed in VxRy".
- `tests/pinned_refs_test.sh` gains: the bundled release equals the
  fingerprinted release of each pinned datastream, and the bundle's sha256
  matches the recorded source zip sha256. The README bump procedure gains the
  refresh step.

### PR 4: `tailoring_file` passthrough (S)

- Parameter `tailoring_file`: an XCCDF tailoring file, snapshotted and hashed
  like `datastream_path`, passed as `--tailoring-file`. `profile_id` must
  then name the tailored profile, which is validated before the scan.
  Provenance records the file's sha256 and the tailored profile id.
- Checklist: rules made `notselected` by the tailoring show as "deselected
  by tailoring `<profile>`" (Not_Reviewed with a DISA skeleton, omitted in
  SSG-only mode). Refine-values and refine-rules are listed in
  FINDING_DETAILS of the affected rows.
- README guidance: use tailoring to adjust values or add rules; don't
  deselect host rules to "clean up" the report, because the checklist
  already explains them.

### PR 5: answer file (M)

- Parameter `checklist_answers`: a JSON file, snapshotted and hashed. It
  holds per-row overrides keyed by V-ID or SV-id (`status`, `comments`,
  `finding_details_append`) and category text overrides. Applied after the
  automatic result. The original automated result is kept in
  FINDING_DETAILS ("Automated result: Open; set to Not_Applicable by answer
  file sha256:…"). Provenance records the hash. Modeled on Evaluate-STIG
  answer files.
- Ship a tiny curated default answer set **only for manual-only Vulns that
  are plainly host-level** in the bundled releases (e.g. RHEL 9 V-257782,
  hardware RNG entropy gatherer). It is opt-in and reviewed per release. This
  is the one piece of hand-maintained "container STIG" content that earns
  its keep.

### Independent: `smoke-rhel10`

The spike confirmed `ssg-rhel10-ds.xml` in the pin has `content_profile_stig`
(V1R2), which is CLAUDE.md's precondition. Add the smoke job any time; PR
1's checklist assertions then cover RHEL 10 too.

## Risks

| Risk | Mitigation |
|---|---|
| Consumers reject our files in ways STIG Manager's parser doesn't (STIG Viewer 3, eMASS). | Golden files modeled on real DISA-tool output (research report); human import acceptance in PR 1; field-for-field comparison with a STIG Viewer–saved file. |
| Default wording rejected by assessors. | ISSM review before PR 1 merges; texts overridable in PR 5. |
| Release drift (SSG one DISA quarter behind). | Fingerprint states the real release; PR 3's D6 handles newer skeletons per row; pin bumps refresh. |
| DISA changes zip/XCCDF layout. | Parser tolerant of 1.1/1.2 namespaces; PR 2 validation errors are explicit; CI fixture from a real zip. |
| Hostile content in `results.xml`/DISA files. | Stdlib parsers only, no entity expansion beyond expat defaults, size caps, writers that escape everything (ElementTree / `json`), outputs written only into `output_dir`. |
| Checklist size (RHEL 9 CKL ~2 MB). | Fine for artifacts; `checklist_formats` can drop one. |

## Open questions

1. **Wording sign-off**: can a customer ISSM review the category texts above?
2. **Redistribution**: are DISA STIG XCCDFs OK to bundle in an MIT-licensed
   orb? See the research report. If not, PR 3 becomes "CCIs only" or is dropped.
3. **Asset defaults**: `MARKING` (`CUI`?), `ROLE`, `TECH_AREA` for container
   images. What does the customer's STIG Manager / eMASS workflow expect?
4. **Default on?** `checklist: auto` adds ~3 MB of artifacts per STIG scan.
   The proposal is on by default in the next minor release.
5. The planning trail that motivated this (P6.1b / "09 §6") isn't in this
   repo. Reconcile its deliverable definition with this plan.
