#!/usr/bin/env python3
"""Ground truth for torn reads.

usage: torn_check.py <tree> <truth.ndjson> <manifest.ndjson>...

For workloads whose final content is deterministic per path (npm ci from a
lockfile, a reproducible build), take a manifest of the quiet tree when the
workload is over (measure --keep DIR --tag truth) and keep the manifests taken
during it (measure --keep DIR). Every clean hash (sha256, none of unstable,
raced, unreadable) that differs from the truth is then either
  - a prefix of the final file: a real intermediate state of a file written
    front to back, or
  - not a prefix: bytes the file never held -- a torn read that passed.
<tree> is the workload's directory as it is now (the final files).
"""
import base64, collections, hashlib, json, os, sys

def entries(path):
    with open(path) as f:
        for line in f:
            d = json.loads(line)
            if 'type' not in d:
                continue
            p = d.get('path')
            if p is None:
                p = base64.b64decode(d['path_b64']).decode('latin1')
            yield p, d

def main():
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    tree, truth_path, manifests = sys.argv[1], sys.argv[2], sys.argv[3:]
    truth = {p: d.get('sha256') for p, d in entries(truth_path) if d['type'] == 'reg'}
    n = collections.Counter()
    torn = []
    for m in manifests:
        for p, d in entries(m):
            if d['type'] != 'reg' or 'sha256' not in d:
                continue
            if d.get('unstable') or d.get('raced') or d.get('unreadable'):
                continue
            n['clean_hashes'] += 1
            t = truth.get(p)
            if t is None:
                n['no_truth'] += 1
                continue
            n['compared'] += 1
            if t == d['sha256']:
                continue
            try:
                with open(os.path.join(tree, p), 'rb') as f:
                    data = f.read()
            except OSError:
                n['final_file_gone'] += 1
                continue
            if d['size'] <= len(data) and hashlib.sha256(data[:d['size']]).hexdigest() == d['sha256']:
                n['partial_real_state'] += 1
            else:
                n['torn'] += 1
                torn.append({'manifest': os.path.basename(m), 'path': p,
                             'size': d['size'], 'final_size': len(data)})
    print(json.dumps({**n, 'torn_examples': torn[:20]}, indent=1))
    return 1 if n['torn'] else 0

if __name__ == '__main__':
    sys.exit(main())
