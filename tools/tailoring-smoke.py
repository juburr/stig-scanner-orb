"""Real scanner assertions shared by CI and local tailoring acceptance."""

import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

out, source = map(Path, sys.argv[1:3])
meta = json.loads((out / "checklist-meta.json").read_text())
tailoring = meta["tailoring"]
assert tailoring["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
plan = dict(line.split("=", 1) for line in (out / "scan-plan.env").read_text().splitlines() if "=" in line)
assert tailoring["profile_id"] == plan["profile"] == plan["tailoring_profile"]
assert tailoring["datastream_sha256"] == plan["datastream_sha256"]
assert plan["tailoring_meta_sha256"] == hashlib.sha256((out / "tailoring-meta.json").read_bytes()).hexdigest()
assert meta["outcome"] == "generated" and meta["release_source"] == "bundle"
rows = {r["group_id"]: r for r in json.loads((out / "checklist.cklb").read_text())["stigs"][0]["rules"]}
assert len(rows) == 445
# A partial many-to-one deselection must withhold the remaining check's N/A.
assert rows["V-258134"]["status"] == "not_reviewed"
assert "aide_build_database: notapplicable" in rows["V-258134"]["finding_details"]
assert "Deselected by tailoring" in rows["V-258134"]["comments"]
assert meta["not_reviewed_by_reason"]["tailoring_deselected"] >= 2
for vid, value in [("V-258107", "'18'"), ("V-258075", "'077'")]:
    assert "Tailored value" in rows[vid]["finding_details"]
    assert value + " (resolved by OpenSCAP)" in rows[vid]["finding_details"]
for row in rows.values():
    assert tailoring["sha256"] in row["finding_details"]
ckl = ET.parse(out / "checklist.ckl")
assert len(ckl.findall(".//VULN")) == len(rows)
for v in ckl.findall(".//VULN"):
    vid = next(
        a.findtext("ATTRIBUTE_DATA") for a in v.findall("STIG_DATA") if a.findtext("VULN_ATTRIBUTE") == "Vuln_Num"
    )
    if rows[vid]["status"] == "not_reviewed":
        assert v.findtext("STATUS") == "Not_Reviewed"
print("Tailored RHEL 9: complete release, deselection safety, resolved values and provenance verified")
