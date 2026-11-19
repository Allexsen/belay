"""Traffic and edits against the two dev servers for DUR seconds."""
import json, os, random, sys, threading, time, urllib.request
DUR = float(sys.argv[1]); DJ, NX = sys.argv[2], sys.argv[3]
stop = time.monotonic() + DUR
stats = {"dj_ok": 0, "dj_err": 0, "nx_ok": 0, "nx_err": 0, "edits": 0}
lock = threading.Lock()
def client(base, paths, key):
    while time.monotonic() < stop:
        p = random.choice(paths)
        try:
            urllib.request.urlopen(base + p, timeout=10).read()
            with lock: stats[key + "_ok"] += 1
        except Exception:
            with lock: stats[key + "_err"] += 1
            time.sleep(0.2)
def editor():
    targets = [os.path.join(DJ, "hits/views.py"), os.path.join(NX, "app/page.js")]
    while time.monotonic() < stop:
        time.sleep(60)
        for t in targets:
            s = open(t).read()
            s += ("# edit %d\n" if t.endswith(".py") else "// edit %d\n") % stats["edits"]
            with open(t, "w") as f: f.write(s)      # an editor save: truncate, write
        stats["edits"] += 1
ts = [threading.Thread(target=client, args=("http://127.0.0.1:8765", ["/hit"] * 4 + ["/list"], "dj")) for _ in range(8)]
ts += [threading.Thread(target=client, args=("http://127.0.0.1:8766", ["/", "/api/hit", "/api/hit"], "nx")) for _ in range(4)]
ts.append(threading.Thread(target=editor))
for t in ts: t.start()
for t in ts: t.join()
print(json.dumps(stats))
