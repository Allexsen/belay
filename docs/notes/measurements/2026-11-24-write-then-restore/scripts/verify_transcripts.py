"""Compare local transcripts with the HF tree listing at the pinned revision by git blob SHA-1.
Usage: python3 -I verify_transcripts.py tree.json transcripts_dir"""
import json, sys, hashlib, os
t = json.load(open(sys.argv[1])); d = sys.argv[2]; ok = bad = 0
for e in t:
    n = os.path.basename(e["path"]); p = os.path.join(d, n)
    b = open(p, "rb").read()
    h = hashlib.sha1(b"blob %d\0" % len(b) + b).hexdigest()
    if h == e["oid"]: ok += 1
    else: bad += 1; print("mismatch", n)
print("transcripts identical to the pinned revision (git blob sha1):", ok, "mismatch:", bad, "listed:", len(t))
