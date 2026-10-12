# Spike: STIG Viewer checklist from OpenSCAP results

Date: 2026-10-12. Pinned content: SSG 0.1.82 (Chainguard openscap
`latest-dev@sha256:f5e08bc1…`), scanners OpenSCAP 1.3.6 (compliance-operator,
RPM targets) and 1.4.4 (Chainguard, everything else). Prototype code is in
[`spike/`](spike/); it is spike quality, not the implementation.

## What was run

| Step | Command / input | Result |
|---|---|---|
| Real scan | `scan.sh` against `registry.access.redhat.com/ubi9/ubi:latest` (RHEL 9.8) | 62 pass / 8 fail / 406 notapplicable / 1 notchecked, same as the README table |
| Real scan | `scan.sh` against `ubuntu:22.04` | 23 pass / 7 fail / 198 notapplicable / 2 notchecked |
| Real scan | `scan.sh` against `cgr.dev/chainguard/static` | GPOS SRG rule ids + CCIs, a different shape (see "Out of scope") |
| Generator | `spike/xccdf2ckl.py` on each `results.xml`, with and without DISA's manual XCCDF | `.ckl` + `.cklb` per run, ~2 s for a 19 MB `results.xml` |
| Validator | `spike/validate.mjs` = STIG Manager's own parsers, `@nuwcdivnpt/stig-manager-client-modules` 1.6.8 (`reviewsFromCkl`, `reviewsFromCklb`) | every output parses, right revision string and row count, no parser errors |
| Fingerprint | `spike/fingerprint.py`: SSG `stig` profile SV-ids vs each DISA manual XCCDF | each pinned datastream matches exactly one DISA release |
| Schema | `spike/cklb_schema_check.py`: DISA's `SV3_CKLB_1_0_JSON_SCHEMA.json` (sha256 `8b88205d…`), raw and patched to allow `stigs[].version`, `rules[].srg_id`, `target_data.classification` (fields STIG Viewer 3.7+ itself writes) | 0 errors patched; raw schema rejects only `stigs[].version` and `target_data.classification` |

DISA files came from `https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_<STIG>_V<v>R<r>_STIG.zip`
(no login; older releases still download). The manual XCCDF inside is ~1.4 MB
(RHEL 9), 131 KB gzipped.

## Results

### Checklist rows (ubi9/ubi, RHEL 9)

| Mode | Rows | NotAFinding | Open | Not_Applicable | Not_Reviewed | Revision mismatches |
|---|---|---|---|---|---|---|
| SSG only (no DISA file) | 436 | 62 | 7 | 366 | 1 | n/a |
| DISA V2R9 skeleton (matches the content) | 445 | 62 | 7 | 366 | 10 | 0 |
| DISA V2R10 skeleton (newest, 30 Sep 2026) | 445 | 62 | 7 | 366 | 10 | 200 |

Ubuntu 22.04: 188 rows SSG-only; DISA V2R8 skeleton 188 rows, 0 mismatches;
DISA V2R10 skeleton 191 rows (3 new, uncovered), 47 mismatches.
ubi8/ubi (RHEL 8): 362 rows SSG-only; DISA V2R8 skeleton 369 rows
(37 NotAFinding / 10 Open / 314 Not_Applicable / 8 Not_Reviewed), 0 mismatches;
DISA V2R9 skeleton 371 rows, 56 mismatches.

N/A rows by justification category (DISA skeleton matching the content):

| Image | Not_Applicable | host | GUI | package not installed | other |
|---|---|---|---|---|---|
| ubi9/ubi | 366 | 331 | 23 | 11 | 1 (OVAL check returned notapplicable) |
| ubi8/ubi | 314 | 292 | 12 | 8 | 2 |
| ubuntu:22.04 | 158 | 147 | 5 | 6 | 0 |

The 23 GUI rows on RHEL 9 match the 23 DISA rules whose own check text says
"If the system does not have any graphical user interface installed, this
requirement is Not Applicable." The checklist can quote DISA there.

### Example rows (V2R9 skeleton, from the `.cklb`)

```
V-257796 SV-257796r1044847_rule RHEL-09-212055 [low] not_applicable  CCI-000130 … CCI-002884
  finding_details: Automated result from OpenSCAP (1 SSG rule):
                   grub2_audit_argument: notapplicable (platform not met: system_with_kernel)
  comments:        Not Applicable to the container image. This requirement configures the host
                   operating system (kernel, boot loader, audit subsystem, partitions or system
                   services), which a container receives from its host … platform check
                   system_with_kernel was false … Assess it on the container host's / platform's
                   STIG checklist. Ref: DISA Container Hardening Process Guide V1R2, Appendix B.

V-258012 SV-258012r1014855_rule RHEL-09-271010 [medium] not_applicable
  finding_details: dconf_gnome_banner_enabled: notapplicable (platform not met: package_gdm)
  comments:        Not Applicable. No graphical user interface is installed in the image (gdm not
                   installed; OpenSCAP platform check package_gdm was false). DISA: "If the system
                   does not have any graphical user interface installed, this requirement is Not
                   Applicable."

V-258241 SV-258241r1184293_rule RHEL-09-215105 [high] open
  finding_details: Automated result from OpenSCAP (3 SSG rules):
                   configure_crypto_policy: fail
                   fips_crypto_subpolicy: notapplicable (platform not met: system_with_kernel)
                   fips_custom_stig_sub_policy: notapplicable (platform not met: system_with_kernel)

V-257782 SV-257782r991589_rule RHEL-09-211035 [low] not_reviewed   (manual-only in DISA; no SSG rule)
  comments:        No automated check for this requirement in the scanner content; manual review required.
```

Each `finding_details` also carries the provenance line (scanner digest,
datastream sha256, target digest, scan time).

## Findings

1. **`results.xml` is self-sufficient.** OpenSCAP writes the full resolved
   Benchmark (rules, references, platform gates) ahead of the `TestResult`,
   and the `TestResult` lists the platforms that evaluated true. The generator
   needs no datastream and no extra container. It runs after the scan, on the host.

2. **N/A reasons are exact, not heuristic.** Comparing each rule's platform
   gates with the `TestResult` platform list says *why* a rule was
   notapplicable. No hand-curated list of ~400 host rules is needed.

3. **Pitfall, caught in the spike: walk the gates top-down.** OpenSCAP checks
   applicability from the outermost group inward and stops at the first
   false gate. `TestResult` therefore lists only gates it actually
   evaluated. A rule-first walk blamed `package_shadow-utils` /
   `package_libpwquality` on 17 ubi9 rules. Both packages *are* installed
   (`rpm -q` confirms); the real cause was the enclosing group's
   `system_with_kernel`. That bug would have written a false "not installed"
   statement into assessor evidence. Walking from the outermost group to the
   rule fixes it, and fixture tests must pin this behaviour.

4. **The SSG→DISA mapping is many-to-many.** 17 RHEL 9 V-IDs are covered by
   2–7 SSG rules, and 8 SSG rules each cite 2+ V-IDs (e.g.
   `dconf_gnome_disable_restart_shutdown` → V-258029 and V-258030). Pair each
   `SV-n…_rule` with its `V-n` by number, never take "the" reference. Combining
   rule: any fail → Open; else any error/unknown/notchecked/informational →
   Not_Reviewed; else all notapplicable → Not_Applicable; else NotAFinding.
   STIG IDs (`RHEL-09-xxxxxx`) can't be paired by number, so a
   multi-mapped rule's `Rule_Ver` is ambiguous in SSG-only mode.

5. **The profile title's release label is not reliable.** Matching SSG's SV
   rule revisions against each DISA release:

   | Datastream | Label in profile | Exact SV-id match | DISA newest (2026-10-12) | SV-ids that differ from newest |
   |---|---|---|---|---|
   | `ssg-rhel8-ds.xml` | V2R8 | **V2R8** (01 Jul 2026), 366/366 | V2R9 (30 Sep 2026) | 57 |
   | `ssg-rhel9-ds.xml` | V2R9 | **V2R9** (01 Jul 2026), 440/440 | V2R10 (30 Sep 2026) | 204 |
   | `ssg-rhel10-ds.xml` | V1R2 | **V1R2** (01 Jul 2026), 434/434 | V1R3 (30 Sep 2026) | 133 |
   | `ssg-ubuntu2204-ds.xml` | **V2R7** | **V2R8** (01 Apr 2026), 188/188 | V2R10 (30 Sep 2026) | 47 |

   The release a checklist claims must come from a fingerprint that a test
   checks against the pin, not from the profile title. Today every pinned
   product is one DISA quarter behind.

6. **Most revision bumps don't change the check.** Of 206 RHEL 9 V2R9→V2R10
   rule-revision bumps, 153 changed none of the title, discussion,
   check, fix, severity or CCI fields; ~26 changed check or fix text. V2R10 also
   added 2 Vulns and removed 2. With the matching-release DISA data on hand,
   the generator can carry a result forward where the check text is unchanged
   and mark it Not_Reviewed where it changed.

7. **SSG 0.1.82 carries no CCIs** (zero `CCI-` strings in `ssg-rhel9-ds.xml`).
   DISA's manual XCCDF has them for every rule (161 distinct CCIs across RHEL 9
   V2R9). A V-ID→CCI map is 2.7 KB gzipped+base64; the full compact DISA data
   is ~150 KB per STIG. Bundling both fits easily under the 8 MB orb limit.

8. **`oscap --stig-viewer` can't be the mechanism.** OpenSCAP 1.4.4 maps to
   DISA ids (440 rule-results), but 1.3.6, the scanner for every RPM target,
   emits a results file with *zero* rule-results against SSG 0.1.82. It
   only knows the old `iase.disa.mil` reference href. It also produces XCCDF
   results rather than a checklist, so it wouldn't remove the combining or N/A
   work anyway.

9. **Manual-only rows exist and some are plainly host-level.** RHEL 9 V2R9 has
   9 Vulns with no SSG rule (e.g. V-257782, hardware RNG entropy gatherer).
   The generator can only mark them Not_Reviewed. A small curated answer set
   for these rows is the one piece of hand-maintained container content that
   still earns its keep.

10. **A tailoring file that deselects host rules works against the
    checklist.** Deselected rules become `notselected`, which drops them
    from SSG-only checklists. With a DISA skeleton they would show as
    "no automated check" Not_Reviewed rows, which is wrong. The N/A
    justification therefore belongs in the generator, and any tailoring
    support has to tell "deselected by tailoring" apart from "no SSG rule".

## Out of scope / not applicable

- **Wolfi is a different shape, not out of reach.** Chainguard's GPOS
  datastream (`ssg-chainguard-gpos-ds.xml`; the XCCDF benchmark is
  "Datastream XCCDF Checklist Beta GPOS v3r2p17") has no `<reference>`
  elements. Instead the DISA ids are the rule ids themselves
  (`xccdf_mil.disa.stig_rule_SV-263651r982555_rule`), and every rule carries
  CCI idents. Against `cgr.dev/chainguard/static`: 198 rules, 85 pass / 6
  fail / 107 notapplicable. The N/A rules are gated on the always-false
  platform `cpe:/o:notapplicable` with a per-rule rationale. That maps to a
  **GPOS SRG** checklist, not an OS STIG, and the SRG release it targets
  (v3r2) is behind DISA's current GPOS SRG (V3R4). Planned as its own PR.
- `debian12` (CIS, no STIG) and `fedora` (`standard`) have nothing to map. So
  does any `profile_id` override with no DISA ids, e.g. the RHEL CIS
  profile. The checklist step must skip these cleanly.

## Not yet verified

- Import into **STIG Viewer 3** itself (desktop app; not runnable here) and
  into **eMASS**. STIG Manager's parser is the automated check; a human
  STIG Viewer import is an acceptance step in the first implementation PR.
- RHEL 10 end-to-end scan (fingerprint only; RHEL 8 was run end to end).
