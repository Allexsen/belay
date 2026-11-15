"""How did each file under <prefix> get its final content, per strace -f?
usage: write_pattern.py <trace> <prefix> [cwd]"""
import re, sys, collections, os
trace, prefix = sys.argv[1], sys.argv[2]
cwd = sys.argv[3] if len(sys.argv) > 3 else ''
def absp(p): return p if p.startswith('/') else os.path.normpath(os.path.join(cwd, p))
ev = collections.defaultdict(list)       # final path -> ordered events
rx_open = re.compile(r'^\d+\s+openat\(AT_FDCWD, "([^"]+)", ([A-Z_|]+)')
rx_ren = re.compile(r'^\d+\s+rename(?:at2?)?\((?:AT_FDCWD, )?"([^"]+)", (?:AT_FDCWD, )?"([^"]+)"')
rx_unl = re.compile(r'^\d+\s+unlink(?:at)?\((?:AT_FDCWD, )?"([^"]+)"')
for line in open(trace):
    m = rx_open.match(line)
    if m and ('O_WRONLY' in m.group(2) or 'O_RDWR' in m.group(2)) and '= -1' not in line:
        ev[absp(m.group(1))].append(('open-' + ('trunc' if 'O_TRUNC' in m.group(2) else 'notrunc') + ('-creat' if 'O_CREAT' in m.group(2) else '') + ('-excl' if 'O_EXCL' in m.group(2) else ''),))
        continue
    m = rx_ren.match(line)
    if m and '= -1' not in line:
        ev[absp(m.group(1))].append(('renamed-away',)); ev[absp(m.group(2))].append(('renamed-into', absp(m.group(1))))
        continue
    m = rx_unl.match(line)
    if m and '= -1' not in line:
        ev[absp(m.group(1))].append(('unlinked',))
pat = collections.Counter(); ex = {}
for p, es in ev.items():
    if not p.startswith(prefix): continue
    kinds = tuple(e[0] for e in es)
    if kinds and kinds[-1] == 'renamed-away' or (kinds and kinds[-1] == 'unlinked'): continue   # not a final file
    k = ' > '.join(kinds)
    pat[k] += 1; ex.setdefault(k, p)
for k, n in pat.most_common():
    print(f"{n:6}  {k}\n        e.g. {ex[k]}")
