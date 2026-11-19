"""Second oracle: reads logged as (t0, t1, size, signature); states rebuilt
from the write log. Membership, and how many passing reads overlapped a
write in progress (the precondition of a torn read)."""
import bisect, hashlib, os, sys
sys.path.insert(0, os.path.dirname(__file__))
from replay import records, apply
O, final = sys.argv[1], sys.argv[2]
PG = 4096
def pdig(b): return hashlib.blake2b(b, digest_size=16).digest()
def sig(digs, n): return hashlib.blake2b(b''.join(digs) + n.to_bytes(8, 'little'), digest_size=16).hexdigest()
buf = bytearray(open(f'{O}/initial.db', 'rb').read())
digs = [pdig(bytes(buf[i:i + PG])) for i in range(0, len(buf), PG)]
sigs = {sig(digs, len(buf))}
wins = []
for (t0, t1, off, ln, kind, data) in records(f'{O}/w.log'):
    apply(buf, off, ln, kind, data); wins.append((t0, t1))
    npg = (len(buf) + PG - 1) // PG
    del digs[npg:]
    while len(digs) < npg: digs.append(b'')
    lo = (off if kind == 1 else min(off, len(buf))) // PG
    hi = (off + ln - 1) // PG if kind == 1 and ln else lo
    for p in range(max(0, min(lo, npg - 1)), min(hi, npg - 1) + 1): digs[p] = pdig(bytes(buf[p * PG:(p + 1) * PG]))
    sigs.add(sig(digs, len(buf)))
print(len(wins), "writes; replay equals final file:", bytes(buf) == open(final, 'rb').read(), "|", len(sigs), "states")
starts = [w[0] for w in wins]
reads = [l.split() for l in open(f'{O}/reads2.txt')]
real = torn = overlap = overlap_real = 0
for t0, t1, size, s in reads:
    t0, t1 = int(t0), int(t1)
    i = bisect.bisect_left(starts, t1)            # writes starting before the read ended
    ov = any(w1 >= t0 for (w0, w1) in wins[max(0, i - 50):i])
    ok = s in sigs
    real += ok; torn += not ok; overlap += ov; overlap_real += ov and ok
print(f"passing reads: {len(reads)}; a real state: {real}; TORN: {torn}")
print(f"passing reads that overlapped a write in progress: {overlap} (of which a real state: {overlap_real})")
