"""Torn-read oracle for one in-place-written file.
States: initial bytes, then every logged write/truncate applied in order
(after skipping `skip` records that precede the initial copy). Each state has
a signature from per-page digests, kept incrementally.
  1. replay check: the last state must equal the final file;
  2. reader images: each passing image must equal some state (membership);
  3. belay's clean hashes: each must equal the SHA-256 of some state whose
     time interval overlaps the check's window.
"""
import glob, hashlib, json, os, sys, bisect
sys.path.insert(0, os.path.dirname(__file__))
from replay import records, apply
O, final, skip = sys.argv[1], sys.argv[2], int(sys.argv[3])
PG = 4096
def pdig(b): return hashlib.blake2b(b, digest_size=16).digest()
def sig(digs, n): return hashlib.blake2b(b''.join(digs) + n.to_bytes(8, 'little'), digest_size=16).digest()

buf = bytearray(open(f'{O}/initial.db', 'rb').read())
digs = [pdig(bytes(buf[i:i + PG])) for i in range(0, len(buf), PG)]
sigs = {sig(digs, len(buf)): 0}
times = [0]            # state k exists from times[k] (t1 of the write that made it)
recs = list(records(f'{O}/w.log'))[skip:]
print(f"{len(recs)} writes after skipping {skip}")
for k, (t0, t1, off, ln, kind, data) in enumerate(recs, 1):
    apply(buf, off, ln, kind, data)
    lo = off // PG if kind == 1 else min(off, len(buf)) // PG
    hi = (off + ln - 1) // PG if kind == 1 and ln else lo
    npg = (len(buf) + PG - 1) // PG
    del digs[npg:]
    while len(digs) < npg: digs.append(b'')
    for p in range(lo, min(hi, npg - 1) + 1): digs[p] = pdig(bytes(buf[p * PG:(p + 1) * PG]))
    if kind == 2:
        for p in range(max(0, npg - 1), npg): digs[p] = pdig(bytes(buf[p * PG:(p + 1) * PG]))
    sigs.setdefault(sig(digs, len(buf)), k)
    times.append(t1)
print("replay equals final file:", bytes(buf) == open(final, 'rb').read())
print(f"{len(sigs)} distinct states")

# 2. reader images
imgs = sorted(glob.glob(f'{O}/imgs/*.img')); real = torn = 0; torn_ex = []
for p in imgs:
    b = open(p, 'rb').read()
    s = sig([pdig(b[i:i + PG]) for i in range(0, len(b), PG)], len(b))
    if s in sigs: real += 1
    else:
        torn += 1
        if len(torn_ex) < 10: torn_ex.append(os.path.basename(p))
    os.unlink(p)
print(f"reader images: {len(imgs)}: {real} a real state, {torn} TORN {torn_ex}")

# 3. belay's clean hashes on this file, by full SHA-256 over the states in the window
lines = [json.loads(l) for l in open(f'{O}/belay.ndjson')]
win = {}
for d in lines:
    if d.get('rc') == 0:
        win[round(d['realtime'] * 1000)] = (int((d['realtime'] - d['wall_s'] - 0.5) * 1e9), int((d['realtime'] + 0.1) * 1e9))
checked = matched = 0; unmatched = []
states_cache = None
for m in sorted(glob.glob(f'{O}/keep/or.*.ndjson')):
    ms = int(m.split('.')[-3]); key = min(win, key=lambda k: abs(k - ms)) if win else None
    if key is None or abs(key - ms) > 2000: continue
    a, z = win[key]
    for l in open(m):
        d = json.loads(l)
        if d.get('path') != 'db.sqlite3' or 'sha256' not in d or d.get('raced') or d.get('unstable'): continue
        checked += 1
        # rebuild the states in [a, z]: replay to the first state at or before a, then on
        b2 = bytearray(open(f'{O}/initial.db', 'rb').read())
        first = max(0, bisect.bisect_right(times, a) - 1)
        for (t0, t1, off, ln, kind, data) in recs[:first]: apply(b2, off, ln, kind, data)
        found = hashlib.sha256(b2).hexdigest() == d['sha256'] and len(b2) == d['size']
        k = first
        while not found and k < len(recs) and times[k] <= z:
            t0, t1, off, ln, kind, data = recs[k]; apply(b2, off, ln, kind, data); k += 1
            if len(b2) == d['size'] and hashlib.sha256(b2).hexdigest() == d['sha256']: found = True
        matched += found
        if not found: unmatched.append((os.path.basename(m), d['size']))
print(f"belay clean hashes of db.sqlite3: {checked} checked, {matched} equal a real state in their window, unmatched {unmatched}")
