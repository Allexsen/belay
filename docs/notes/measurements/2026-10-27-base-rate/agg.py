import json, sys, collections
def agg(path):
    R = [json.loads(l) for l in open(path) if l.startswith('{')]
    ok = [d for d in R if d.get('rc') == 0]
    s = lambda k: sum(d.get(k, 0) for d in ok)
    flagged = {k: collections.Counter() for k in ('raced', 'unstable', 'unreadable')}
    for d in ok:
        for k in flagged:
            for p in d.get(k + '_paths', []): flagged[k][p] += 1
    eag = collections.Counter(p for d in ok for p in d.get('eagain_open_paths', []))
    eag_eof = collections.Counter(p for d in ok for p in d.get('eagain_eof_paths', []))
    steps = [d['clock_step'] for d in ok if abs(d.get('clock_step', 0)) > 0.5]
    return dict(path=path, runs=len(R), failed=len(R) - len(ok), entries=s('entries'),
        raced=s('raced'), unstable=s('unstable'), unreadable=s('unreadable'), vanished=s('vanished'),
        runs_with_raced=sum(1 for d in ok if d['raced']), runs_with_unstable=sum(1 for d in ok if d['unstable']),
        runs_with_vanished=sum(1 for d in ok if d['vanished']),
        hashed=s('files_opened'), hashed_MB=s('bytes_read') / 1e6, eagain_open=s('probe_eagain'),
        eagain_eof=s('eof_eagain'), eacces=s('probe_eacces'), other=s('probe_other'),
        runs_with_eagain=sum(1 for d in ok if d['probe_eagain'] or d['eof_eagain']),
        racy_entries=s('racy_entries'), racy_reg=s('racy_reg'),
        racy_pct_bytes=100 * s('racy_reg_bytes') / max(1, s('reg_bytes_hashable')),
        wall_med=sorted(d['wall'] for d in ok)[len(ok) // 2] if ok else 0,
        clock_steps=len(steps), clock_step_max=max(steps, key=abs) if steps else 0,
        flagged={k: v.most_common(8) for k, v in flagged.items()},
        eagain_paths=eag.most_common(10), eagain_eof_paths=eag_eof.most_common(10),
        errs=[d.get('err') for d in R if d.get('rc') != 0][:3])
for p in sys.argv[1:]:
    a = agg(p)
    print(json.dumps(a, indent=1))
