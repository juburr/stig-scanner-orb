"""Fetch DISA's schema for CI validation and verify the exact JSON bytes."""

import hashlib
import io
from pathlib import Path
import sys
import urllib.request
import zipfile

URL = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/SV3_CKLB_1_0_JSON_SCHEMA.zip"
SHA256 = "8b88205de07662006e1660b1decad677d344828d6687b1dd26bca15105b7bb37"
with urllib.request.urlopen(URL, timeout=60) as response:
    data = response.read((16 << 20) + 1)
if len(data) > 16 << 20:
    sys.exit("schema archive exceeds 16 MiB")
with zipfile.ZipFile(io.BytesIO(data)) as archive:
    with archive.open("SV3_CKLB_1_0_JSON_SCHEMA.json") as member:
        schema = member.read((1 << 20) + 1)
if hashlib.sha256(schema).hexdigest() != SHA256:
    sys.exit("DISA schema sha256 changed; review the schema before changing the pin")
Path(sys.argv[1]).write_bytes(schema)
