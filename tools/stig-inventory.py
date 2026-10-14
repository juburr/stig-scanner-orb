"""Print identifier-only inventory entries from locally supplied DISA files.

Usage: python3 tools/stig-inventory.py path/to/*_STIG.zip
Download releases separately from DISA. No DISA text is written to the repo.
The production parser verifies identity, profiles and known release inventories.
Review these entries and update STIG_INVENTORY when supporting new releases.
"""

import argparse
import hashlib
import io
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="+", type=Path)
    a = ap.parse_args()
    script = Path(__file__).resolve().parents[1] / "src/scripts/checklist.sh"
    code = script.read_text().split("<<'PY_CHECKLIST'\n", 1)[1].split("\nPY_CHECKLIST\n", 1)[0]
    generator = {"__name__": "inventory"}
    exec(compile(code, str(script), "exec"), generator)
    for path in a.files:
        raw = generator["read_capped"](path, generator["MAX_DISA_BYTES"], "DISA file")
        data = raw
        if zipfile.is_zipfile(io.BytesIO(raw)):
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                members = [
                    m
                    for m in archive.infolist()
                    if not m.is_dir() and m.filename.lower().endswith("manual-xccdf.xml")
                ]
                if len(members) != 1 or members[0].file_size > generator["MAX_DISA_BYTES"]:
                    raise ValueError(f"{path}: expected one bounded manual XCCDF member")
                with archive.open(members[0]) as member:
                    data = member.read(generator["MAX_DISA_BYTES"] + 1)
        if len(data) > generator["MAX_DISA_BYTES"]:
            raise ValueError(f"{path}: oversized XCCDF")
        expected = ET.fromstring(data).get("id")
        disa = generator["read_disa"](path, expected)
        pairs = sorted(f"{g['vid']} {g['rule_id']}" for g in disa["groups"])
        key = (disa["benchmark_id"], disa["version"], disa["releaseinfo"].split()[1])
        value = (len(pairs), hashlib.sha256("\n".join(pairs).encode()).hexdigest(), disa["releaseinfo"])
        print(f'# {path.name}; source SHA-256 {disa["source_sha256"]}')
        print(f"{key!r}: {value!r},")


if __name__ == "__main__":
    main()
