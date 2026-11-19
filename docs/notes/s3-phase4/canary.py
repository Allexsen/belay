#!/usr/bin/env python3
"""Kill rule: the named test prints `ok` on the unmutated tree, the mutant
builds, and the named test prints `FAIL` under it. usage: canary.py SHA SPEC"""
import importlib.util, os, re, shutil, subprocess, sys, tempfile
def sh(c, cwd):
    p = subprocess.run(c, cwd=cwd, shell=True, capture_output=True, text=True, errors='replace')
    return p.returncode, p.stdout + p.stderr
sha, spec = sys.argv[1], sys.argv[2]
m = importlib.util.spec_from_file_location('s', spec); mod = importlib.util.module_from_spec(m); m.loader.exec_module(mod)
base = tempfile.mkdtemp(prefix='canary.', dir=os.path.dirname(os.path.abspath(__file__)))
def tree():
    d = tempfile.mkdtemp(dir=base); subprocess.run('git -C /home/user/workspace/belay archive %s | tar -x -C %s' % (sha, d), shell=True, check=True); return d
env = dict(os.environ); env.pop('BELAY_SKIP_PROFILE', None)
bt = tree()
for c in mod.CANARIES:
    rc, out = sh('make -s build/test/%s >/dev/null 2>&1; BELAY_ACCOUNTING=test/accounting ./build/test/%s' % (c['bin'], c['bin']), bt)
    base_ok = re.search(r'^ok    %s$' % re.escape(c['test']), out, re.M) is not None
    mt = tree(); bad = None
    for f, old, new in c['edits']:
        p = os.path.join(mt, f); s = open(p).read()
        if s.count(old) != 1: bad = 'edit matched %d times in %s' % (s.count(old), f); break
        open(p, 'w').write(s.replace(old, new))
    if bad: print('| %s | NOT APPLIED: %s |' % (c['id'], bad)); continue
    brc, bout = sh('make -s build/test/%s' % c['bin'], mt)
    if brc: print('| %s | INVALID: mutant does not build |' % c['id']); continue
    rc2, out2 = sh('BELAY_ACCOUNTING=test/accounting ./build/test/%s' % c['bin'], mt)
    failed = re.search(r'^FAIL  %s$' % re.escape(c['test']), out2, re.M) is not None
    ev = [l.strip() for l in out2.split('\n') if l.startswith('      ')][:1]
    print('| %s | %s | %s |' % (c['id'], 'KILLED' if base_ok and failed else 'NOT KILLED (baseline %s)' % ('ok' if base_ok else 'not ok'), ev[0][:110] if ev else ''))
    shutil.rmtree(mt)
shutil.rmtree(base)
