#!/usr/bin/env python3
"""Validates JSON lines on stdin against a schema file (the subset belay's
schemas use: type, enum, required, properties, additionalProperties,
minimum, items). Stdlib only: CI images need no extra package.

    check-json-schema.py schema/checkpoint.v1.json < output.ndjson
"""
import json
import sys

TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


def check(v, s, where, errs):
    t = s.get("type")
    if t == "integer":
        if not (isinstance(v, int) and not isinstance(v, bool)):
            errs.append(f"{where}: not an integer: {v!r}")
            return
    elif t is not None and not isinstance(v, TYPES[t]):
        errs.append(f"{where}: not {t}: {v!r}")
        return
    if "enum" in s and v not in s["enum"]:
        errs.append(f"{where}: {v!r} not one of {s['enum']}")
    if "minimum" in s and isinstance(v, (int, float)) and v < s["minimum"]:
        errs.append(f"{where}: {v} below {s['minimum']}")
    if isinstance(v, dict):
        for k in s.get("required", []):
            if k not in v:
                errs.append(f"{where}: missing {k}")
        props = s.get("properties", {})
        for k, x in v.items():
            if k in props:
                check(x, props[k], f"{where}.{k}", errs)
            elif s.get("additionalProperties") is False:
                errs.append(f"{where}: unexpected {k}")
    if isinstance(v, list) and "items" in s:
        for i, x in enumerate(v):
            check(x, s["items"], f"{where}[{i}]", errs)


def main():
    schema = json.load(open(sys.argv[1]))
    errs, n = [], 0
    for line in sys.stdin:
        if not line.strip():
            continue
        n += 1
        try:
            v = json.loads(line)
        except ValueError as e:
            errs.append(f"line {n}: not JSON: {e}")
            continue
        check(v, schema, f"line {n}", errs)
    if n == 0:
        errs.append("no JSON lines")
    for e in errs:
        print(e, file=sys.stderr)
    sys.exit(1 if errs else 0)


main()
