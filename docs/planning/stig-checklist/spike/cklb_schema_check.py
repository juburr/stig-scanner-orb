"""Validate .cklb files against DISA's SV3 CKLB 1.0 schema, raw and patched.

    cklb_schema_check.py SV3_CKLB_1_0_JSON_SCHEMA.json FILE.cklb [...]

Patched = DISA's schema plus the fields STIG Viewer 3.7+ itself writes
(stigs[].version, rules[].srg_id, target_data.classification). Exit status is
non-zero if any file has an error against the patched schema, or an error
against the raw schema other than one of those extension fields.
"""
import copy
import json
import sys

import jsonschema

EXTENSIONS = {"version", "srg_id", "classification"}


def objects(node):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from objects(v)
    elif isinstance(node, list):
        for v in node:
            yield from objects(v)


def expected_raw_error(e):
    """additionalProperties errors naming only the documented extensions."""
    if e.validator != "additionalProperties" or not isinstance(e.instance, dict):
        return False
    extra = set(e.instance) - set(e.schema.get("properties", {}))
    return bool(extra) and extra <= EXTENSIONS


def describe(e):
    return f"/{'/'.join(str(p) for p in e.path)}: {e.message[:160]}"


schema = json.load(open(sys.argv[1], encoding="utf-8"))
patched = copy.deepcopy(schema)
added = []
for obj in objects(patched):
    props = obj.get("properties")
    if not isinstance(props, dict):
        continue
    if "stig_name" in props and "version" not in props:
        props["version"] = {"type": "string"}
        added.append("stigs[].version")
    if "rule_id_src" in props and "srg_id" not in props:
        props["srg_id"] = {"type": "string"}
        added.append("rules[].srg_id")
    if "host_name" in props and "classification" not in props:
        props["classification"] = {"type": ["string", "null"]}
        added.append("target_data.classification")
print("patched:", added)

failed = False
for f in sys.argv[2:]:
    doc = json.load(open(f, encoding="utf-8"))
    patched_errs = list(jsonschema.Draft201909Validator(patched).iter_errors(doc))
    raw_errs = list(jsonschema.Draft201909Validator(schema).iter_errors(doc))
    unexpected_raw = [e for e in raw_errs if not expected_raw_error(e)]
    ok = not patched_errs and not unexpected_raw
    failed |= not ok
    print(f"{'ok  ' if ok else 'FAIL'} {f.split('/')[-1]}: patched errors={len(patched_errs)}, "
          f"raw errors={len(raw_errs)} ({len(raw_errs) - len(unexpected_raw)} expected extension fields)")
    for e in (patched_errs + unexpected_raw)[:10]:
        print("    " + describe(e))
sys.exit(1 if failed else 0)
