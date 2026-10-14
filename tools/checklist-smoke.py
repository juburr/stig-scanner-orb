"""CI assertions against the production release table and real scan output."""

import hashlib
import io
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

out = Path(sys.argv[1])
expected = sys.argv[2]
meta = json.loads((out / "checklist-meta.json").read_text())
results = (out / "results.xml").read_bytes()
assert meta["results_sha256"] == hashlib.sha256(results).hexdigest()
assert meta["outcome"] == expected, meta
if expected == "skipped":
    assert not (out / "checklist.ckl").exists() and not (out / "checklist.cklb").exists()
    assert meta["reason"]
else:
    plan = dict(
        line.split("=", 1) for line in (out / "scan-plan.env").read_text().splitlines() if "=" in line
    )
    if plan.get("family") == "rpm":
        assert plan.get("rpm_status") == "available", plan
        assert int(plan["rpm_status_packages"]) > 0
        provenance = json.loads((out / "provenance.json").read_text())
        assert provenance["target"]["rpm_status"]["state"] == "available"
        assert provenance["target"]["rpm_status"]["packages"] == int(plan["rpm_status_packages"])
    script = Path("src/scripts/checklist.sh").read_text()
    code = script.split("<<'PY_CHECKLIST'\n", 1)[1].split("\nPY_CHECKLIST\n", 1)[0]
    generator = {"__name__": "smoke"}
    exec(compile(code, "checklist.sh", "exec"), generator)
    entry = generator["RELEASE_TABLE"][meta["datastream_sha256"]]
    res = generator["parse_results"](io.BytesIO(results))
    if meta["release_source"] == "skeleton":
        disa = generator["read_disa"](meta["skeleton_path"], meta["stig"]["benchmark_id"])
        assert meta["skeleton_completeness"] == "inventory"
        assert meta["skeleton_sha256"] == disa["sha256"]
        assert meta["skeleton_source_sha256"] == disa["source_sha256"]
        assert meta["vulns"] == len(disa["groups"])
        assert (meta["stig"]["version"], meta["stig"]["releaseinfo"]) == (
            disa["version"],
            disa["releaseinfo"],
        )
        rows = json.loads((out / "checklist.cklb").read_text())["stigs"][0]["rules"]
        official = {g["vid"]: g for g in disa["groups"]}
        mismatches = 0
        for row in rows:
            group = official[row["group_id"]]
            assert row["rule_id_src"] == group["rule_id"]
            assert row["ccis"] == group["ccis"] and row["ccis"]
            assert row["check_content"] == group["check_content"]
            assert meta["skeleton_sha256"] in row["finding_details"]
            refs = {
                sv
                for rid, rule in res["rules"].items()
                if res["results"][rid] != "notselected"
                for sv in rule["svs"].get(row["group_id"][2:], ())
            }
            if refs and refs != {group["rule_id"]}:
                assert row["status"] == "not_reviewed"
                mismatches += 1
        assert mismatches == meta["not_reviewed_by_reason"].get("revision_mismatch", 0)
        if (disa["version"], disa["releaseinfo"]) == entry[3]:
            assert mismatches == 0
        else:
            assert mismatches > 0
    else:
        assert meta["release_source"] == "table"
        assert (meta["stig"]["version"], meta["stig"]["releaseinfo"]) == entry[3]
        res = generator["parse_results"](io.BytesIO(results))
        vids = set()
        for rid, result in res["results"].items():
            if result == "notselected":
                continue
            r = res["rules"][rid]
            vids.update(v for v in r["vids"] if v.startswith("V-") and v[2:] in r["svs"])
        assert (
            meta["vulns"]
            == len(vids)
            == entry[4]["profiles"][res["profile_id"].replace(generator["_P"], "", 1)]["vids"]
        )
    ckl = ET.parse(out / "checklist.ckl")
    assert len(ckl.findall(".//VULN")) == meta["vulns"]
    for row in ckl.findall(".//VULN"):
        if row.findtext("STATUS") == "Not_Applicable":
            assert row.findtext("COMMENTS"), "N/A reason missing"
    cklb = json.loads((out / "checklist.cklb").read_text())
    assert len(cklb["stigs"][0]["rules"]) == meta["vulns"]
    for ext, digest in meta["formats"].items():
        assert hashlib.sha256((out / ("checklist." + ext)).read_bytes()).hexdigest() == digest
print(f"{out}: {expected}; checklist contracts hold")
