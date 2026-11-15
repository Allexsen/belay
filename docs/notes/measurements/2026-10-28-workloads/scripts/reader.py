"""belay's read-pass check, every 20 ms, on one file; passing images saved.
Conditions as consistency.c: the opened fd is the stat'ed file, unchanged
(ino, dev, size, mtime, ctime); after reading, size and times unchanged and
every byte the size promised was read."""
import os, sys, time
path, outdir, dur = sys.argv[1], sys.argv[2], float(sys.argv[3])
os.makedirs(outdir, exist_ok=True)
end = time.monotonic() + dur; n = passed = 0
key = lambda s: (s.st_ino, s.st_dev, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
while time.monotonic() < end:
    time.sleep(0.02); n += 1
    t0 = time.time_ns()
    try:
        st = os.lstat(path); fd = os.open(path, os.O_RDONLY)
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
    finally:
        os.close(fd)
    t1 = time.time_ns(); data = b''.join(chunks)
    if key(z)[2:] != key(a)[2:] or len(data) != a.st_size: continue
    passed += 1
    with open(f"{outdir}/{t0}_{t1}.img", "wb") as f: f.write(data)
print(f"reader: {n} attempts, {passed} passed the stability check")
