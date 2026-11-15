"""Refactor-era mutants (b2c15e0's five), re-run clean at four commits.

Each mutant is applied in a fresh worktree, the tree is rebuilt from
`make clean`, the FULL suite runs, and the original file is written back
(fresh mtime) before the next one. Baseline first.
usage: refactor_mutants.py <worktree> <commit-label>
"""
import os, re, subprocess, sys
wt, label = sys.argv[1], sys.argv[2]
W, C, K, WK = "src/capture/manifest_write.c", "src/capture/capture.c", "src/capture/consistency.c", "src/capture/walk.c"
PRE = {  # e04186a: everything in manifest_write.c, no ident.c
 "A no end-of-walk re-check": (W, "static int recheck(struct spill *s, struct walk_ctx *wc, int root_fd) {\n",
     "static int recheck(struct spill *s, struct walk_ctx *wc, int root_fd) {\n    (void)s; (void)wc; (void)root_fd; if (1) return 0;\n"),
 "B empty link target accepted": (W, "    if (n == 0) return V_UNREADABLE;\n", "\n"),
 "C no directory identity check at open": (W, "    if (fstat(cfd, &cs) == -1 || cs.st_ino != st->st_ino || cs.st_dev != st->st_dev ||\n",
     "    if (fstat(cfd, &cs) == -1 ||\n"),
 "D incomplete or changed listing not flagged": (W, "        if (incomplete && !dir->unstable) {", "        if (0 && incomplete && !dir->unstable) {"),
 "E symlink re-stat ignored": (W, "    if (again.st_ino != st->st_ino || again.st_dev != st->st_dev ||\n        ts_ns(&again, 1) != ts_ns(st, 1) || (uint64_t)again.st_size != (uint64_t)n)\n        return V_RACED;\n", "\n"),
}
MID = {  # b2c15e0: ident.c and fsops exist, still one manifest_write.c
 "A no end-of-walk re-check": PRE["A no end-of-walk re-check"],
 "B empty link target accepted": PRE["B empty link target accepted"],
 "C no directory identity check at open": (W, "(ci = ident_of_stat(&cs), !ident_same(&ci, &ri, ID_OBJECT)) ||", "(ci = ident_of_stat(&cs), 0) ||"),
 "D incomplete or changed listing not flagged": PRE["D incomplete or changed listing not flagged"],
 "E symlink re-stat ignored": (W, "    if (!ident_same(&ai, &ri, ID_OBJECT | ID_CTIME) || ai.size != (uint64_t)n)\n        return V_RACED;\n", "    (void)ai; (void)ri;\n"),
}
POST = {  # fa319ff: the pipeline; HEAD: the same, validator in place of the window rule
 "A no end-of-walk re-check": (K, "const int v = !changed ? VERDICT_NONE : kind == RC_LISTING ? VERDICT_LISTING : VERDICT_ENTRY;",
     "const int v = VERDICT_NONE; (void)changed;"),
 "B empty link target accepted": (C, "    if (n == 0) return V_UNREADABLE;\n", "\n"),
 "C no directory identity check at open": (K, "    if (!ident_same(&o, &r, ID_OBJECT)) return OUT_DENIED;", "    if (0) return OUT_DENIED;"),
 "D incomplete or changed listing not flagged": (WK, "        if (r == W_INCOMPLETE || !cons_listing_held(wc, cfd, dir))", "        if (0)"),
 "E symlink re-stat ignored": (C, "    if (!cons_link_read(st, &again, (size_t)n)) return V_RACED;\n", "    (void)again;\n"),
}
HEADV = dict(POST)
HEADV["D incomplete or changed listing not flagged"] = (WK, "    if (r == W_INCOMPLETE) {\n        outcome_apply(dir, FACET_LISTING, OUT_CHANGED, &wc->tally);",
                                                    "    if (0) {\n        outcome_apply(dir, FACET_LISTING, OUT_CHANGED, &wc->tally);")
spec = {"e04186a": PRE, "b2c15e0": MID, "fa319ff": POST, "HEAD": HEADV}[label]

def run():
    subprocess.run("make -s clean", shell=True, cwd=wt, capture_output=True)
    out = subprocess.run("make test 2>&1", shell=True, cwd=wt, capture_output=True, text=True).stdout
    if re.search(r"error:", out) and "run, " not in out:
        return None, out[-600:]
    fails = re.findall(r"^FAIL\s+(\S+)", out, re.M)
    total = sum(int(m) for m in re.findall(r"^(\d+) run, ", out, re.M))
    return fails, total

f, t = run()
print(f"{label} baseline: {t} run, failing {f}", flush=True)
for name, (path, old, new) in spec.items():
    p = os.path.join(wt, path)
    src = open(p).read()
    assert src.count(old) == 1, (label, name, src.count(old))
    open(p, "w").write(src.replace(old, new))
    try:
        f, t = run()
        verdict = "BUILD FAILED " + t if f is None else ("KILLED by " + ", ".join(f) if f else "SURVIVED")
        print(f"{label} {name}: {verdict}", flush=True)
    finally:
        open(p, "w").write(src)          # fresh mtime; the next run rebuilds from clean anyway
