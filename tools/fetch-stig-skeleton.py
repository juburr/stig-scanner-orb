"""CI-only: download a checksum-pinned DISA manual ZIP, never during a scan."""

import argparse
import hashlib
import os
from pathlib import Path
import tempfile
import urllib.request

RELEASES = {
    "9": ("U_RHEL_9_V2R9_STIG.zip", "1875de2543d01695c5a346c51888cc336113e9199bfe6726d74a08de286ca1ae"),
    "10": ("U_RHEL_9_V2R10_STIG.zip", "a9a212444ac39060c6d6ecd3d8113c4e51ce4094ce50f760aaec792945c3d111"),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("release", choices=RELEASES)
    ap.add_argument("destination", type=Path)
    a = ap.parse_args()
    name, sha = RELEASES[a.release]
    with urllib.request.urlopen(
        "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/" + name, timeout=60
    ) as response:
        data = response.read((16 << 20) + 1)
    if len(data) > 16 << 20 or hashlib.sha256(data).hexdigest() != sha:
        raise ValueError("DISA ZIP does not match its pinned SHA-256 or exceeds 16 MiB")
    a.destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=a.destination.parent, delete=False) as f:
            temporary = f.name
            f.write(data)
        os.replace(temporary, a.destination)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
    print(f"{name}: verified sha256 {sha}")


if __name__ == "__main__":
    main()
