# Bundled DISA reference content

The orb's original code is covered by [LICENSE](LICENSE). The bundled STIG
reference content is reproduced from DISA's official Cyber Exchange downloads
under its published reuse policy; this notice does not relicense that content
under MIT or claim that every vendor contribution is a U.S. Government work.

[Cyber Exchange — Privacy and Security](https://www.cyber.mil/privacy-security)
states:

> Information presented on Cyber Exchange is considered public information and may be distributed or copied. Use of appropriate byline/photo/image credits is requested.

Policy checked on 2026-10-14. The current site renders this policy in its public
[Privacy and Security page asset](https://www.cyber.mil/webruntime/view/2bdcbb936c3b2fd57051d314a2e5204c/prod/en-US/privacy_and_Security_view).
The policy asset's SHA-256 is recorded below so the reviewed evidence can be
identified even if the site changes:

`b49c91ff93fb99b82e39b035b8957c9da3700b08a315df830cc9dd5fc0754bf1`

| Reference content | Release | Credits from the release overview | Official source |
|---|---|---|---|
| Red Hat Enterprise Linux 8 STIG | V2R8, 01 Jul 2026 | DISA | [DISA ZIP](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_8_V2R8_STIG.zip) |
| Red Hat Enterprise Linux 9 STIG | V2R9, 01 Jul 2026 | Red Hat and DISA | [DISA ZIP](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R9_STIG.zip) |
| Red Hat Enterprise Linux 10 STIG | V1R2, 01 Jul 2026 | Red Hat and DISA | [DISA ZIP](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_10_V1R2_STIG.zip) |
| Canonical Ubuntu 22.04 LTS STIG | V2R8, 01 Apr 2026 | Canonical Ltd. and DISA | [DISA ZIP](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_22-04_LTS_V2R8_STIG.zip) |

The bundles retain official rule identifiers, severity, requirement discussion,
check procedures, fix text, CCIs and legacy identifiers as compact JSON. They
are compressed and encoded for inclusion in the orb. Their source ZIP, XCCDF
and generated JSON checksums are recorded in `tools/stig-sources.json`, the
bundle payloads and `BUNDLE_TABLE` in `src/scripts/checklist.sh`. Generated
checklists identify their source releases, source hashes and credits in each
row's finding details and in `checklist-meta.json`/`provenance.json`.

The four pinned packages were reviewed, including XML notices, readmes,
overviews and release memos; no conflicting redistribution restriction was
found. This review covers these public packages. Separately supplied material
and future releases require their own review. DoD/DISA logos and other image
assets from the source archives are not bundled.

Product names identify the applicable benchmarks. This project is not endorsed
by or affiliated with DISA, the Department of Defense, Red Hat or Canonical.
The upstream overviews' trademark and non-endorsement statements remain
applicable; automated checklist output is evidence, not a certification.
