"""Content-only torn detector, for workloads whose content is deterministic
per path (npm ci from a lockfile). A clean hash (sha256, no unstable/raced/
unreadable) that differs from the ground truth's hash for the same path is a
hash of bytes the file never held once written.
usage: oracle_content.py <truth.ndjson> <manifest>..."""
import json, sys, base64, collections
def entries(p):
    with open(p) as f:
        for line in f:
            d = json.loads(line)
            if 'type' not in d: continue
            yield (d.get('path') or base64.b64decode(d['path_b64']).decode('latin1')), d
truth = {p: d.get('sha256') for p, d in entries(sys.argv[1]) if d['type'] == 'reg'}
tot = collections.Counter(); bad = collections.Counter(); ex = []
for m in sys.argv[2:]:
    for p, d in entries(m):
        if d['type'] != 'reg' or 'sha256' not in d: continue
        if d.get('unstable') or d.get('raced') or d.get('unreadable'): continue
        tot['clean'] += 1
        t = truth.get(p)
        if t is None: tot['no_truth'] += 1; continue
        tot['compared'] += 1
        if t != d['sha256']:
            bad[p] += 1
            if len(ex) < 12: ex.append((p, d['size'], d['sha256'][:12], t[:12]))
print(json.dumps({**tot, 'mismatch': sum(bad.values()), 'files': len(bad), 'examples': ex}, indent=1))
