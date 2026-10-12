"""Validate .cklb files against DISA's SV3 CKLB 1.0 schema, raw and patched
(patched = also allow stigs[].version, rules[].srg_id, target_data.classification,
which STIG Viewer 3.7+ itself writes)."""
import copy, json, sys
import jsonschema
schema = json.load(open(sys.argv[1]))
def find(node, key):
    """Yield every object that has properties[key] or is the definition named key."""
    if isinstance(node, dict):
        yield node
        for v in node.values(): yield from find(v, key)
    elif isinstance(node, list):
        for v in node: yield from find(v, key)
patched = copy.deepcopy(schema)
added = []
for obj in find(patched, None):
    props = obj.get("properties")
    if not isinstance(props, dict): continue
    if "stig_name" in props and "version" not in props: props["version"] = {"type": "string"}; added.append("stigs[].version")
    if "rule_id_src" in props and "srg_id" not in props: props["srg_id"] = {"type": "string"}; added.append("rules[].srg_id")
    if "host_name" in props and "classification" not in props: props["classification"] = {"type": ["string", "null"]}; added.append("target_data.classification")
print("patched:", added)
for f in sys.argv[2:]:
    doc = json.load(open(f))
    for name, sch in (("patched", patched), ("raw", schema)):
        v = jsonschema.Draft201909Validator(sch)
        errs = sorted(v.iter_errors(doc), key=lambda e: list(e.path))
        uniq = sorted({(e.message[:140], "/".join(str(p) for p in list(e.path)[:2] + (["*"] if len(e.path) > 3 else []) + list(e.path)[-1:])) for e in errs})
        print(f"{f.split('/')[-1]:22s} {name:7s} errors={len(errs)}", "; ".join(f"{p}: {m}" for m, p in uniq[:6]))
