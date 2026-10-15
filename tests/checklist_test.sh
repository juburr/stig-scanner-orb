#!/usr/bin/env bash
# Run the production generator against small fixtures and injected I/O failures.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 tests/checklist_test.py
python3 tests/skeleton_test.py
python3 tests/bundle_test.py
python3 tests/tailoring_test.py
