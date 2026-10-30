#!/usr/bin/env python3
"""Checks that CI gates what it claims to (audit 2026-10, V4 / adversarial M7).

    check-ci.py               static checks of .github/workflows/ci.yml and scripts/
    check-ci.py --protection  also compare the required checks with main's branch
                              protection (needs `gh` authenticated with admin read:
                              run by hand; CI's token cannot read protection)
    check-ci.py --selftest    prove each rule rejects what it should

Rules:
  1. No `continue-on-error`, no `if:` (job or step), no `|| true` / `|| :` in a
     run block: each would let a check go red without failing its job.
  2. The jobs are exactly test/accounting/required-checks.txt, which is the
     list branch protection must require: a job that does not block a merge
     does not gate anything.
  3. Every step of every job is listed in test/accounting/checks.txt, as a
     `check` or as `setup`, and every listed check exists: a check step cannot
     disappear unnoticed.
  4. Hermetic harnesses (R10): no script links "every .o found".
The workflow is parsed by indentation (no YAML library: the docker and macOS
jobs run this without one); it understands the subset ci.yml uses.
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW = os.path.join(ROOT, '.github', 'workflows', 'ci.yml')
REQUIRED = os.path.join(ROOT, 'test', 'accounting', 'required-checks.txt')
CHECKS = os.path.join(ROOT, 'test', 'accounting', 'checks.txt')


def parse(text):
    """{job display name: {'if': bool, 'steps': [(step name, run text, flags)]}}"""
    jobs, job, step, in_jobs, block = {}, None, None, False, None
    for raw in text.split('\n'):
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        ind = len(line) - len(line.lstrip())
        s = line.strip()
        if block is not None:                   # inside a `run: |` block scalar
            if ind > block[0]:
                step['run'] += s + '\n'
                continue
            block = None
        if ind == 0:
            in_jobs = s == 'jobs:'
            continue
        if not in_jobs:
            continue
        if ind == 2 and s.endswith(':'):
            job = {'name': s[:-1], 'flags': set(), 'steps': []}
            jobs[s[:-1]] = job
            step = None
            continue
        if job is None:
            continue
        if ind == 4:
            key = s.split(':', 1)[0]
            if key == 'name':
                job['name'] = s.split(':', 1)[1].strip()
            if key in ('if', 'continue-on-error'):
                job['flags'].add(key)
            continue
        if ind == 6 and s.startswith('- '):
            step = {'name': None, 'run': '', 'uses': None, 'flags': set()}
            job['steps'].append(step)
            s = s[2:]
            ind = 8
        if step is not None and ind >= 8:
            key, _, val = s.partition(':')
            val = val.strip()
            if key in ('if', 'continue-on-error'):
                step['flags'].add(key)
            elif key == 'name' and step['name'] is None:
                step['name'] = val
            elif key == 'uses':
                step['uses'] = val
            elif key == 'run':
                if val in ('|', '>', '|-', '>-'):
                    block = (ind,)
                else:
                    step['run'] += val + '\n'
    out = {}
    for j in jobs.values():
        steps = []
        for st in j['steps']:
            label = st['name'] or (st['run'].strip().split('\n')[0] if st['run'] else st['uses'])
            steps.append((label, st['run'], st['flags']))
        out[j['name']] = {'flags': j['flags'], 'steps': steps}
    return out


def lines(path):
    return [l.strip() for l in open(path) if l.strip() and not l.lstrip().startswith('#')]


def check(text, required, checks, scripts):
    errs = []
    jobs = parse(text)
    for jn, j in jobs.items():
        for f in sorted(j['flags']):
            errs.append('job %s: `%s` (a job that can be skipped or fail softly gates nothing)' % (jn, f))
        for label, run, flags in j['steps']:
            for f in sorted(flags):
                errs.append('job %s, step "%s": `%s`' % (jn, label, f))
            if re.search(r'\|\|\s*(true|:)(\s|;|$)', run):
                errs.append('job %s, step "%s": `|| true` swallows the failure' % (jn, label))
    if set(jobs) != set(required):
        for j in sorted(set(jobs) - set(required)):
            errs.append('job %s is not in required-checks.txt (it would not block a merge)' % j)
        for j in sorted(set(required) - set(jobs)):
            errs.append('required check %s has no job in ci.yml' % j)
    listed = {}
    for c in checks:
        parts = [p.strip() for p in c.split('|')]
        if len(parts) != 3 or parts[2] not in ('check', 'setup'):
            errs.append('checks.txt: malformed line: %s' % c)
            continue
        listed[(parts[0], parts[1])] = parts[2]
    present = {(jn, label) for jn, j in jobs.items() for label, _, _ in j['steps']}
    for k in sorted(present - set(listed)):
        errs.append('step "%s" of job %s is not in checks.txt (check or setup?)' % (k[1], k[0]))
    for k in sorted(set(listed) - present):
        if listed[k] == 'check':
            errs.append('check "%s" of job %s is listed but no longer exists' % (k[1], k[0]))
        else:
            errs.append('setup step "%s" of job %s is listed but no longer exists' % (k[1], k[0]))
    for name, text_ in scripts:
        joined = re.sub(r'\\\n', ' ', text_)        # shell line continuations
        if re.search(r"find\b[^\n]*-name\s+['\"]?\*\.o", joined):
            errs.append('%s links "every .o found" -- link build/libbelay.a from a fresh BUILD' % name)
    return errs


def scripts_text():
    out = []
    for dp, _, fs in os.walk(os.path.join(ROOT, 'scripts')):
        for f in fs:
            if f.endswith(('.sh', '.py')) and f != 'check-ci.py':
                p = os.path.join(dp, f)
                out.append((os.path.relpath(p, ROOT), open(p, encoding='utf-8').read()))
    return out


def selftest():
    good = """jobs:
  a:
    name: one
    steps:
      - uses: actions/checkout@v5
      - name: build
        run: make check
"""
    req, chk = ['one'], ['one | actions/checkout@v5 | setup', 'one | build | check']
    cases = [
        ('accepts a correct workflow', good, req, chk, [], False),
        ('rejects continue-on-error', good.replace('        run: make check', '        run: make check\n        continue-on-error: true'), req, chk, [], True),
        ('rejects a step if:', good.replace('      - name: build', '      - name: build\n        if: false'), req, chk, [], True),
        ('rejects a job if:', good.replace('    name: one', '    name: one\n    if: false'), req, chk, [], True),
        ('rejects || true', good.replace('make check', 'make check || true'), req, chk, [], True),
        ('rejects a job not required', good, [], chk, [], True),
        ('rejects a required check with no job', good, req + ['two'], chk, [], True),
        ('rejects an unlisted step', good, req, chk[:1], [], True),
        ('rejects a listed check that vanished', good, req, chk + ['one | lint | check'], [], True),
        ('rejects find -name *.o', good, req, chk, [('x.sh', "objs=$(find build -name '*.o')")], True),
        ('rejects find -name *.o across a line continuation', good, req, chk,
         [('x.sh', "objs=$(find build/a \\\n    build/b -name '*.o')")], True),
    ]
    bad = 0
    for name, text, r, c, s, want_err in cases:
        got = bool(check(text, r, c, s))
        if got != want_err:
            print('check-ci selftest FAILED: %s' % name)
            bad = 1
    return bad


def protection():
    try:
        out = subprocess.run(['gh', 'api', 'repos/{owner}/{repo}/branches/main/protection',
                              '--jq', '[.required_status_checks.contexts[]]'],
                             cwd=ROOT, capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        return ['cannot read branch protection: %s' % e]
    have = set(json.loads(out))
    want = set(lines(REQUIRED))
    errs = ['branch protection does not require %s' % j for j in sorted(want - have)]
    errs += ['branch protection requires %s, which is not in required-checks.txt' % j
             for j in sorted(have - want)]
    return errs


def main():
    if '--selftest' in sys.argv:
        bad = selftest()
        print('check-ci selftest: %s' % ('FAILED' if bad else 'every rule rejects what it should'))
        return bad
    if selftest():
        print('check-ci: its own selftest failed; no verdict')
        return 1
    errs = check(open(WORKFLOW).read(), lines(REQUIRED), lines(CHECKS), scripts_text())
    if '--protection' in sys.argv:
        errs += protection()
    for e in errs:
        print('check-ci: ' + e)
    if errs:
        return 1
    print('check-ci: every job required, every step accounted for, nothing swallows a failure')
    return 0


if __name__ == '__main__':
    sys.exit(main())
