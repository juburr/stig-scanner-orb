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
    script = Path("src/scripts/checklist.sh").read_text()
    code = script.split("<<'PY_CHECKLIST'\n", 1)[1].split("\nPY_CHECKLIST\n", 1)[0]
    generator = {"__name__": "smoke"}
    exec(compile(code, "checklist.sh", "exec"), generator)
    entry = generator["RELEASE_TABLE"][meta["datastream_sha256"]]
    assert meta["release_source"] == "table"
    assert (meta["stig"]["version"], meta["stig"]["releaseinfo"]) == entry[3]
    res = generator["parse_results"](io.BytesIO(results))
    vids = set()
    for rid, result in res["results"].items():
        if result == "notselected":
            continue
        r = res["rules"][rid]
        vids.update(v for v in r["vids"] if v.startswith("V-") and v[2:] in r["svs"])
    assert meta["vulns"] == len(vids) == entry[4]["profiles"][res["profile_id"].removeprefix(generator["_P"])]["vids"]
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
