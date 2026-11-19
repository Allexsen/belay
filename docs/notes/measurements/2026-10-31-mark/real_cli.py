import os, resource, subprocess, sys, time, json, shutil
belay, tree, state = sys.argv[1], sys.argv[2], sys.argv[3]
shutil.rmtree(state, ignore_errors=True)
env = dict(os.environ, BELAY_STATE_DIR=state)
def run(*args):
    t = time.monotonic()
    p = subprocess.run([belay, *args, "--scope", tree, "--json"], env=env, capture_output=True, text=True)
    dt = time.monotonic() - t
    rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    if p.returncode: print(p.stderr); sys.exit(1)
    o = json.loads(p.stdout)
    return dt, o
def touch1pct():
    n = 0
    for root, dirs, files in os.walk(tree):
        dirs.sort(); files.sort()
        if '.git' in root.split(os.sep): continue
        for f in files:
            n += 1
            if n % 100 == 0:
                with open(os.path.join(root, f), 'ab') as h: h.write(b'\n')
rows = []
dt, o = run("check"); rows.append(("check (first, store filled)", dt, o))
for i in range(3):
    dt, o = run("check"); rows.append(("check", dt, o))
for i in range(3):
    dt, o = run("mark"); rows.append(("mark, nothing changed", dt, o))
touch1pct()
dt, o = run("mark"); rows.append(("mark, 1% changed", dt, o))
for name, dt, o in rows:
    pf = o["prefilter"]
    print(f"{name:30s} {dt:6.3f} s  entries {o['entries']}  trusted {pf['trusted']}  racy {pf['racy']}  used {pf['used']}")
