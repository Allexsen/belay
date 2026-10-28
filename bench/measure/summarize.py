#!/usr/bin/env python3
"""Summarize measure logs: one row per log.

usage: summarize.py <log.ndjson>...
"""
import collections, json, sys

def row(path):
    runs = [json.loads(l) for l in open(path) if l.startswith('{')]
    ok = [r for r in runs if r.get('rc') == 0]
    s = lambda k: sum(r.get(k, 0) for r in ok)
    sub = lambda k, f: sum(r[k][f] for r in ok)
    flagged = {k: collections.Counter() for k in ('raced', 'unstable', 'unreadable')}
    writers = collections.Counter()
    for r in ok:
        for k in flagged:
            flagged[k].update(r.get(k + '_paths', []))
        writers.update(r.get('writer_paths', []))
    hashed = s('files_hashed')
    reg_bytes = sub('racy', 'reg_bytes') if ok else 0
    return {
        'log': path, 'runs': len(runs), 'failed': len(runs) - len(ok),
        'entries': s('entries'), 'files_hashed': hashed,
        'raced': s('raced'), 'unstable': s('unstable'), 'unreadable': s('unreadable'),
        'vanished': s('vanished'),
        'runs_with_a_flag': sum(1 for r in ok if r['raced'] or r['unstable'] or r['vanished']),
        'writer_at_open': sub('writer_at_open', 'yes') if ok else 0,
        'writer_at_eof': sub('writer_at_eof', 'yes') if ok else 0,
        'writer_unknown': sub('writer_at_open', 'unknown') if ok else 0,
        'writer_rate_pct': round(100 * (sub('writer_at_open', 'yes') if ok else 0) / max(1, hashed), 4),
        'writer_outcome': {k: sum(r['writer_outcome'][k] for r in ok)
                           for k in (ok[0]['writer_outcome'] if ok else {})},
        'racy_extra_hash_pct': round(100 * (sub('racy', 'racy_reg_bytes') if ok else 0) / max(1, reg_bytes), 2),
        'clock_steps': sum(1 for r in ok if abs(r.get('clock_step_s', 0)) > 0.5),
        'wall_median_s': sorted(r['wall_s'] for r in ok)[len(ok) // 2] if ok else None,
        'top_flagged': {k: v.most_common(5) for k, v in flagged.items()},
        'top_writers': writers.most_common(5),
    }

for p in sys.argv[1:]:
    print(json.dumps(row(p), indent=1))
