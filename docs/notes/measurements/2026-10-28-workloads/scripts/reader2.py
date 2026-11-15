"""As reader.py, but each passing read's page signature is computed in memory
and logged with its time window; no image is kept."""
import hashlib, os, sys, time
path, out, dur = sys.argv[1], sys.argv[2], float(sys.argv[3])
PG = 4096
def sig(b):
    d = b''.join(hashlib.blake2b(b[i:i + PG], digest_size=16).digest() for i in range(0, len(b), PG))
    return hashlib.blake2b(d + len(b).to_bytes(8, 'little'), digest_size=16).hexdigest()
key = lambda s: (s.st_ino, s.st_dev, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
end = time.monotonic() + dur; n = passed = 0
with open(out, 'w') as log:
    while time.monotonic() < end:
        time.sleep(0.02); n += 1
        t0 = time.time_ns()
        try: st = os.lstat(path); fd = os.open(path, os.O_RDONLY)
        except OSError: continue
        try:
            a = os.fstat(fd)
            if key(a) != key(st): continue
            chunks = []
            while True:
                b = os.read(fd, 65536)
                if not b: break
                chunks.append(b)
            z = os.fstat(fd)
        finally: os.close(fd)
        t1 = time.time_ns(); data = b''.join(chunks)
        if key(z)[2:] != key(a)[2:] or len(data) != a.st_size: continue
        passed += 1
        log.write(f"{t0} {t1} {len(data)} {sig(data)}\n")
print(f"reader: {n} attempts, {passed} passed the stability check")
