#!/usr/bin/env python3
"""Ground truth for torn reads.

usage: torn_check.py <tree> <truth.ndjson> <manifest.ndjson>...

For workloads whose final content is deterministic per path (npm ci from a
lockfile, a reproducible build), take a manifest of the quiet tree when the
workload is over (measure --keep DIR --tag truth) and keep the manifests taken
during it (measure --keep DIR). Every clean hash (sha256, none of unstable,
raced, unreadable) that differs from the truth is then one of:
  - partial_real_state: a prefix of the final file -- a real intermediate
    state of a file written front to back;
  - complete_earlier_version: an earlier file at this path, read whole.
    Either it was later replaced whole (its inode differs from the final
    file's: a rename over it, or delete and create), or the same inode,
    size, mtime and hash were recorded clean by two or more checks (the file
    held exactly those bytes for a while, then was rewritten);
  - torn: none of these -- bytes the file never held, as far as this oracle
    can tell. One sighting of an earlier version rewritten in place on the
    same inode also lands here: the oracle cannot tell it from a tear.
<tree> is the workload's directory as it is now (the final files).
Exits 1 if anything is torn.
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

def clean(d):
    return (d['type'] == 'reg' and 'sha256' in d and
            not (d.get('unstable') or d.get('raced') or d.get('unreadable')))

def main():
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    tree, truth_path, manifests = sys.argv[1], sys.argv[2], sys.argv[3:]
    truth = {p: d for p, d in entries(truth_path) if d['type'] == 'reg'}
    # How many checks recorded each exact clean state of a path.
    seen = collections.Counter()
    for m in manifests:
        for p, d in entries(m):
            if clean(d):
                seen[(p, d['ino'], d['size'], d['mtime_ns'], d['sha256'])] += 1
    n = collections.Counter()
    torn = []
    for m in manifests:
        for p, d in entries(m):
            if not clean(d):
                continue
            n['clean_hashes'] += 1
            t = truth.get(p)
            if t is None or 'sha256' not in t:
                n['no_truth'] += 1
                continue
            n['compared'] += 1
            if t['sha256'] == d['sha256']:
                continue
            if (d['ino'], d['dev']) != (t['ino'], t['dev']):
                n['complete_earlier_version'] += 1          # replaced whole later
                continue
            try:
                with open(os.path.join(tree, p), 'rb') as f:
                    data = f.read()
            except OSError:
                n['final_file_gone'] += 1
                continue
            if d['size'] <= len(data) and hashlib.sha256(data[:d['size']]).hexdigest() == d['sha256']:
                n['partial_real_state'] += 1
            elif seen[(p, d['ino'], d['size'], d['mtime_ns'], d['sha256'])] >= 2:
                n['complete_earlier_version'] += 1          # held for a while, then rewritten
            else:
                n['torn'] += 1
                torn.append({'manifest': os.path.basename(m), 'path': p,
                             'size': d['size'], 'final_size': len(data)})
    print(json.dumps({**n, 'torn_examples': torn[:20]}, indent=1))
    return 1 if n['torn'] else 0

if __name__ == '__main__':
    sys.exit(main())
