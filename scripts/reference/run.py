#!/usr/bin/env python3
"""Runs belay (through the driver) and the reference on every generated pair,
compares the dpkg, pip and git findings (HEAD, packed-refs, loose refs,
reflogs) and the pip, dpkg and git events byte for byte, every path's
outcome, and the header's
`before_excluded` and `after_excluded` (manifest-v2 pin, V2-R7), and gates on
coverage: every cell a builder declares must be hit at least once.

    run.py --driver build/reference/driver --work DIR [--n N] [--seed S] [--keep]

Exit 0 when every pair agrees and every cell was hit; 1 otherwise. A failing
case's directory is kept under DIR with a `report.txt` beside its manifests.

A pair that differs is run again under belay's readings where the documents
can be read two ways (ref.ALT_READINGS). When they remove every difference,
the pair is a listed disagreement, not a failure: the smallest set of
readings that explains it is counted, and its first difference (both
outputs) is written to DIR/disagreements.txt. A difference no listed reading
explains fails.
"""

import argparse
import base64
import collections
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen   # noqa: E402
import ref   # noqa: E402


# ---------------------------------------------------------------- belay's output

def parse_diff(fn):
    with open(fn, "rb") as f:
        lines = f.read().split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    header, trailer = json.loads(lines[0]), json.loads(lines[-1])
    records = {}
    events = []
    for line in lines[1:-1]:
        if line.startswith(b'{"event":'):
            events.append(line)
            continue
        if events:
            raise ValueError("a path record after an event record (E1)")
        o = json.loads(line)
        p = ref.entry_path(o)
        raw = None
        i = line.find(b',"findings":[')
        if i >= 0:
            raw = line[i + len(b',"findings":'):-1]
        records[p] = (o["outcome"], raw)
    return header, records, events, trailer


def compare(belay, mine):
    """The differences, as text lines; empty when they agree."""
    header, records, events, trailer = belay
    diffs = []
    # V2-R7: each manifest's `excluded` as its header writes it, null for v1
    for key, want in zip(("before_excluded", "after_excluded"), mine.excluded):
        if key not in header:
            diffs.append("header: no %s" % key)
        elif header[key] != want:
            diffs.append("header %s: belay %r, reference %r" % (key, header[key], want))
    if trailer.get("events") != len(events):
        diffs.append("trailer events %r, %d event records" % (trailer.get("events"), len(events)))
    for p in sorted(set(records) | set(mine.outcomes)):
        bo = records.get(p, ("unchanged", None))[0]
        mo = mine.outcomes.get(p, "unchanged")
        if bo != mo:
            diffs.append("outcome %r: belay %s, reference %s" % (p, bo, mo))
    for p, mf in sorted(mine.claims.items()):
        bf = records.get(p, (None, None))[1]
        rf = mine.findings.get(p)
        if bf != rf:
            diffs.append("findings %r (%s):\n    belay     %s\n    reference %s"
                         % (p, mf, bf.decode("utf-8", "replace") if bf else None,
                            rf.decode("utf-8", "replace") if rf else None))
    bev = [e for e in events if json.loads(e).get("interp") in ("pip", "dpkg", "git")]
    if bev != mine.events:
        i = 0
        while i < min(len(bev), len(mine.events)) and bev[i] == mine.events[i]:
            i += 1
        lo = max(0, i - 2)
        diffs.append("events differ (belay %d, reference %d; first difference at %d):"
                     % (len(bev), len(mine.events), i))
        for tag, lst in (("belay", bev), ("reference", mine.events)):
            diffs.append("  %s:" % tag)
            for e in lst[lo:i + 12]:
                diffs.append("    " + e.decode("utf-8", "replace"))
    return diffs


# ---------------------------------------------------------------- cells

def evs(mine):
    return [json.loads(e) for e in mine.events]


def kinds(mine, interp=None):
    return [e["event"] for e in evs(mine) if interp is None or e["interp"] == interp]


REASON_OF = {"no_store": "no_store", "missing_nostored": "missing", "missing_absent": "missing",
             "missing_unverified": "missing", "corrupt_content": "corrupt",
             "corrupt_symlink": "corrupt", "too_large": "too_large",
             "too_large_rows": "too_large"}


CNI = b"[" + ref.finding_json("could_not_interpret", {}) + b"]"

GIT_REASON_OF = {"too_large_nostored": "too_large", "too_large_unverified": "too_large",
                 "too_large_stored": "too_large", "missing_nostored_at_bound": "missing",
                 "missing_nostored": "missing", "missing_absent": "missing",
                 "corrupt_content": "corrupt"}


def git_records(mine):
    """The reference's findings on each reflog it claims: path -> list."""
    return {p: json.loads(mine.findings[p]) if mine.findings.get(p) else []
            for p, who in mine.claims.items() if who == "git"}


def cu(reason, side):
    return {"kind": "content_unavailable", "reason": reason, "side": side,
            "text": "content unavailable (%s): %s" % (side, reason)}


def check_git(cell, mine):
    R = git_records(mine)
    F = [f for fs in R.values() for f in fs]
    no_cu = not any(f["kind"] == "content_unavailable" for f in F)
    parts = cell.split(".")
    if parts[1] == "git" and parts[2] in GIT_REASON_OF:
        reason, side = GIT_REASON_OF[parts[2]], parts[3]
        want = [cu(reason, s) for s in (["before", "after"] if side == "both" else [side])]
        return list(R.values()) == [want]
    checks = {
        "cu.git.too_large_before_no_store":
            lambda: list(R.values()) == [[cu("too_large", "before"), cu("no_store", "after")]],
        "cu.git.missing_before_no_store":
            lambda: list(R.values()) == [[cu("missing", "before"), cu("no_store", "after")]],
        "git.reflog_appended": lambda: any(f["kind"] == "git_reflog_appended" for f in F),
        "git.reflog_move": lambda: any(f["kind"] == "git_reflog_move" for f in F),
        "git.ref_name_refs": lambda: any(f.get("ref") == "refs/heads/main" for f in F),
        "git.reflog_rewritten": lambda: [f["kind"] for f in F] == ["git_reflog_rewritten"] * 2,
        "git.reflog_added": lambda: any(f["kind"] == "git_reflog_appended"
                                        and f["entries"] == 5 for f in F),
        "git.reflog_removed_no_copy": lambda: R.get(gen.REFLOG_MAIN) == [
            {"kind": "git_reflog_rewritten", "ref": "refs/heads/main",
             "text": "refs/heads/main: reflog rewritten"}],
        "git.reflog_read_at_bound": lambda: no_cu and R.get(gen.REFLOG_HEAD, [{}])[0].get(
            "entries") == gen.reflog_of_size(ref.REFLOG_BOUND)[1],
        "git.reflog_over_store_max_bytes": lambda: no_cu and R.get(gen.REFLOG_MAIN, [{}])[0].get(
            "entries") == 1500,
    }
    return bool(checks[cell]())


def check_e12(cell, mine):
    """git's repository-level events (E12): each cell names what its case was
    built to show in the reference's own output."""
    E = [e for e in evs(mine) if e["interp"] == "git"]
    K = [e["event"] for e in E]
    N = [e for e in E if e["event"] not in ("content_unavailable", "could_not_interpret")]

    def ev(repo, kind=None, branch=None, **kw):
        out = [e for e in N if e.get("repo") == repo and (kind is None or e["event"] == kind)
               and (branch is None or e.get("branch", e.get("from")) == branch)
               and all(e.get(k) == v for k, v in kw.items())]
        return out[0] if len(out) == 1 else None

    def repo_events(repo):
        return [e for e in N if e.get("repo") == repo]

    def kinds_of(repo):
        return [(e["event"], e.get("branch", e.get("from"))) for e in repo_events(repo)]

    X, Y, Z, W = (gen.goid(c).decode() for c in "XYZW")
    P = "proj/.git"

    def created(repo, br, paths):
        e = ev(repo, "git_branch_created", br)
        return e is not None and e["paths"] == paths and "provisional" not in e

    def moved_no_from(repo, br):
        e = ev(repo, "git_branch_moved", br)
        return e is not None and "from" not in e and e["text"] == "%s now at %s" % (br, e["to"])

    def moved_from(repo, br, paths=None):
        e = ev(repo, "git_branch_moved", br)
        return (e is not None and e.get("from") == X and e["to"] == Y
                and (paths is None or e["paths"] == paths))

    def rewritten(br, how):
        e = ev(P, "git_history_rewritten", br)
        return e is not None and e["how"] == how and (e["from"], e["to"]) == (X, Y)

    def cu_only(reason=None):
        return E and all(e["event"] == "content_unavailable"
                         and (reason is None or e["reason"] == reason) for e in E)

    def rec(path):
        f = mine.findings.get(path.encode())
        return json.loads(f) if f else None

    checks = {
        "git.e12.created.reflog_zeros": lambda: K == ["git_branch_created"] and created(
            P, "topic", [P + "/logs/refs/heads/topic", P + "/refs/heads/topic"]),
        "git.e12.nostore_cu_only": lambda: K == ["content_unavailable"]
        and E[0]["reason"] == "no_store" and E[0]["side"] == "after",
        "git.e12.created.packed_absence": lambda: created(
            P, "feat", [P + "/packed-refs", P + "/refs/heads/feat"]),
        "git.e12.created.packed_line": lambda: created(P, "rel", [P + "/packed-refs"])
        and len(N) == 2,
        "git.e12.moved.no_from": lambda: moved_no_from("a/.git", "feat")
        and ev("a/.git", branch="feat")["paths"] == ["a/.git/refs/heads/feat"],
        "git.e12.moved.no_from_reflog_rewritten": lambda: moved_no_from("b/.git", "feat")
        and ev("b/.git", branch="feat")["paths"] == ["b/.git/logs/refs/heads/feat",
                                                     "b/.git/refs/heads/feat"],
        "git.e12.before_from_reflog": lambda: (ev("c/.git", "git_commits_added", "feat")
                                               or {}).get("count") == 1,
        "git.e12.deleted.loose": lambda: (ev("a/.git", "git_branch_deleted", "old")
                                          or {}).get("paths") == ["a/.git/refs/heads/old"],
        "git.e12.deleted.loose_and_packed": lambda: (ev("b/.git", "git_branch_deleted", "old")
                                                     or {}).get("was") == X,
        "git.e12.deleted.packed_only": lambda: (ev("c/.git", "git_branch_deleted", "gone")
                                                or {}).get("paths") == ["c/.git/packed-refs"],
        "git.e12.pack_refs_nothing": lambda: not repo_events("d/.git") and len(N) == 3,
        "git.e12.renamed": lambda: kinds_of(P) == [("git_head_switched", "a-old"),
                                                   ("git_branch_renamed", "a-old"),
                                                   ("git_commits_added", "m")]
        and (ev(P, "git_branch_renamed") or {}).get("to") == "z-new"
        and ev(P, "git_head_switched")["to"] == "z-new",
        "git.e12.same_commit_not_renamed": lambda: kinds_of(P) == [
            ("git_branch_deleted", "one"), ("git_branch_created", "two")]
        and ev(P, "git_branch_created")["paths"] == [P + "/logs/refs/heads/two",
                                                     P + "/refs/heads/two"],
        "git.e12.commits_added.counted": lambda: (ev(P, "git_commits_added", "counted")
                                                  or {}).get("count") == 5,
        "git.e12.commits_added.uncounted": lambda: all(
            ev(P, "git_commits_added", b) is not None and "count" not in ev(P, branch=b)
            for b in ("ff", "merge", "pull")),
        "git.e12.rewritten.reset": lambda: rewritten("r-reset", "reset"),
        "git.e12.rewritten.amend": lambda: rewritten("r-amend", "commit (amend)"),
        "git.e12.rewritten.rebase": lambda: rewritten("r-rebase", "rebase (finish)")
        and rewritten("r-rebase-i", "rebase -i (finish)")
        and rewritten("r-pull-rebase", "pull --rebase (finish)"),
        "git.e12.rewritten.branch_reset": lambda: rewritten("r-branch-reset", "branch"),
        "git.e12.rewritten.forced_update": lambda: rewritten("r-forced", "update by push"),
        "git.e12.rewritten.how_each_once": lambda: rewritten("r-mixed", "reset, commit (amend)"),
        "git.e12.not_chaining.first": lambda: moved_from(P, "n-first"),
        "git.e12.not_chaining.gap": lambda: moved_from(P, "n-gap"),
        "git.e12.not_chaining.last": lambda: moved_from(P, "n-last"),
        "git.e12.other_operation": lambda: moved_from(P, "n-other"),
        "git.e12.moved.no_reflog": lambda: moved_from(P, "n-none", [P + "/refs/heads/n-none"]),
        "git.e12.moved.reflog_rewritten": lambda: moved_from(
            P, "n-rewritten", [P + "/logs/refs/heads/n-rewritten", P + "/refs/heads/n-rewritten"]),
        "git.e12.head.switch": lambda: ev("h1/.git", "git_head_switched", None, **{
            "from": "main", "to": "topic"}) is not None,
        "git.e12.head.detach": lambda: ev("h2/.git", "git_head_switched", None, **{
            "from": "main", "to": X}) is not None,
        "git.e12.head.attach": lambda: ev("h3/.git", "git_head_switched", None, **{
            "from": X, "to": "main"}) is not None,
        "git.e12.head.detached_commits": lambda: kinds_of("h4/.git") == [
            ("git_commits_added", "HEAD")] and ev("h4/.git")["count"] == 1
        and ev("h4/.git")["paths"] == ["h4/.git/HEAD", "h4/.git/logs/HEAD"],
        "git.e12.head.detached_moved": lambda: kinds_of("h5/.git") == [
            ("git_branch_moved", "HEAD")] and ev("h5/.git")["from"] == X,
        "git.e12.head.detached_rewritten": lambda: kinds_of("h6/.git") == [
            ("git_history_rewritten", "HEAD")] and ev("h6/.git")["how"] == "reset",
        "git.e12.head.detached_no_reflog": lambda: kinds_of("h7/.git") == [
            ("git_branch_moved", "HEAD")] and ev("h7/.git")["paths"] == ["h7/.git/HEAD"],
        "git.e12.order.head_first": lambda: kinds_of("h1/.git") == [
            ("git_head_switched", "main"), ("git_branch_created", "A")],
        "git.e12.head.added_no_switch": lambda: kinds_of(P) == [("git_branch_created", "main")],
        "git.e12.checkout_b": lambda: kinds_of(P) == [("git_head_switched", "main"),
                                                      ("git_branch_created", "topic")]
        and ev(P, "git_branch_created")["at"] == Y,
        "git.e12.nested": lambda: [e["repo"] for e in N] == [
            r for r in (".git", "a-b/.git", "a/.git", "a/vendor/lib/.git", P) for _ in range(3)],
        "git.e12.branch_order": lambda: [e["branch"] for e in N[:3]] == ["a-b", "a/b", "z"],
        "git.e12.unknown.with_copy": lambda: (ev(P, "git_commits_added", "main2") or {}).get(
            "provisional") is True and rec(P + "/refs/heads/main2") is None
        and "provisional" not in ev(P, branch="plain"),
        "git.e12.unknown.reflog": lambda: (ev(P, "git_history_rewritten", "dev") or {}).get(
            "provisional") is True and rec(P + "/logs/refs/heads/dev") is None,
        "git.e12.unknown.no_store": lambda: K == ["content_unavailable"]
        and E[0].get("provisional") is True and E[0]["side"] == "both",
        "git.e12.unknown.no_copy": lambda: K == ["content_unavailable", "git_branch_moved"]
        and (E[0]["reason"], E[0]["side"], E[0].get("provisional")) == ("missing", "after", True)
        and E[0]["paths"] == [P + "/refs/heads/main2"] and rec(P + "/refs/heads/main2") is None
        and "provisional" not in E[1],
        "git.e12.unparseable_ref": lambda: any(
            e["event"] == "could_not_interpret" and e["paths"] == ["r/.git/refs/heads/bad"]
            for e in E) and kinds_of("r/.git") == [("git_branch_moved", "good")]
        and rec("r/.git/refs/heads/bad") == [{"kind": "could_not_interpret",
                                              "text": "could not interpret"}],
        "git.e12.unparseable_packed": lambda: any(
            e["event"] == "could_not_interpret" and e["paths"] == ["p/.git/packed-refs"]
            for e in E) and kinds_of("p/.git") == [("git_branch_moved", "loose-both")],
        "git.e12.unparseable_head": lambda: any(
            e["event"] == "could_not_interpret" and e["paths"] == ["q/.git/HEAD"] for e in E)
        and not repo_events("q/.git"),
        "git.e12.tags_remotes_nothing": lambda: not E and rec(P + "/packed-refs") is not None
        and rec(P + "/refs/tags/v2") is not None,
        "git.e12.cu.ref": lambda: any(
            e["event"] == "content_unavailable" and e["reason"] == "missing"
            and e["paths"] == ["r/.git/refs/heads/lost"] for e in E)
        and rec("r/.git/refs/heads/lost") == [cu("missing", "before")]
        and kinds_of("r/.git") == [("git_branch_moved", "fine")],
        "git.e12.cu.packed": lambda: any(
            e["event"] == "content_unavailable" and e["reason"] == "corrupt"
            and e["paths"] == ["p/.git/packed-refs"] for e in E)
        and kinds_of("p/.git") == [("git_branch_moved", "loose-both")],
        "git.e12.cu.reflog_classify": lambda: K == ["content_unavailable"]
        and E[0]["paths"] == [P + "/logs/refs/heads/dev"],
        "git.e12.e11": lambda: e11_silent(mine, 2) and kinds_of("other/.git") == [
            ("git_branch_created", "seen")] and not repo_events(P) and K == ["git_branch_created"],
        "git.e12.e11_nostore": lambda: e11_silent(mine, 2) and K == ["content_unavailable"]
        and all(p.startswith("other/") for p in E[0]["paths"]),
        "git.e12.e9_branch_not_utf8": lambda: K == ["invalid_finding", "git_branch_created"]
        and "paths_b64" in E[0] and E[1]["branch"] == "ok"
        and rec(P + "/refs/heads/ok") is not None,
        "git.e12.e9_nostore": lambda: K == ["content_unavailable"] and "paths_b64" in E[0],
        "git.e12.unparseable_tag_remote": lambda: K == ["could_not_interpret"] * 2
        + ["git_branch_moved"] and [E[0]["paths"], E[1]["paths"]] == [
            [P + "/refs/remotes/origin/main"], [P + "/refs/tags/v1"]]
        and rec(P + "/refs/tags/v1") == [{"kind": "could_not_interpret",
                                          "text": "could not interpret"}],
        "git.e12.cu_not_named": lambda: K == ["git_branch_deleted"]
        and E[0]["paths"] == [P + "/refs/heads/gone"]
        and rec(P + "/refs/tags/v1") == [cu("missing", "before")]
        and rec(P + "/refs/remotes/origin/main") == [cu("corrupt", "after")]
        and rec(P + "/logs/refs/remotes/origin/main") == [cu("missing", "after")]
        and rec(P + "/logs/refs/heads/gone")[0]["kind"] == "git_reflog_rewritten",
        "git.e12.cu_not_named_nostore": lambda: K == ["content_unavailable"]
        and E[0]["paths"] == [P + "/refs/heads/gone"] and E[0]["side"] == "before",
        "git.e12.ref_type_changed": lambda: kinds_of(P) == [("git_branch_deleted", "a"),
                                                            ("git_branch_moved", "a/b")]
        and moved_no_from(P, "a/b"),
    }
    return bool(checks[cell]())


def cni_records(mine):
    """How many records the reference gives could_not_interpret."""
    return sum(1 for f in mine.findings.values() if f == CNI)


def no_unknown_findings(mine):
    """An unknown path carries no path finding (P7)."""
    return all(mine.findings.get(p) is None for p, o in mine.outcomes.items()
               if o == "unknown" and p in mine.claims)


def event_paths(e):
    if "paths" in e:
        return [p.encode("utf-8") for p in e["paths"]]
    return [base64.b64decode(p) for p in e.get("paths_b64", [])]


def e11_silent(mine, n=1):
    """E11 holds for the pair: at least n claimed paths are unknown only as
    not_captured, each with its record (outcome unknown, no finding), and
    no event names any of them."""
    nc = {p for p in mine.not_captured if p in mine.claims}
    if len(nc) < n:
        return False
    if any(mine.outcomes.get(p) != "unknown" or mine.findings.get(p) is not None for p in nc):
        return False
    return not any(p in nc for e in evs(mine) for p in event_paths(e))


def check_cell(cell, mine, belay=None):
    """Did this pair's reference output show the cell it was built for?
    (belay's parsed diff is used by one probe only: a claim's edge.)"""
    E = evs(mine)
    K = kinds(mine)

    def has(kind, **kw):
        return any(e["event"] == kind and all(e.get(k) == v for k, v in kw.items()) for e in E)

    if cell.startswith("git.e12."):
        return check_e12(cell, mine)
    if cell.startswith("git.") or cell.startswith("cu.git."):
        return check_git(cell, mine)
    if cell.startswith("cu."):
        parts = cell.split(".")
        interp, variant, side = parts[1], parts[2], parts[-1]
        if variant in REASON_OF:
            return has("content_unavailable", interp=interp, reason=REASON_OF[variant], side=side)
        if variant == "one_path_both_sides":
            return has("content_unavailable", interp=interp, side="both")
        if variant == "one_path_two_reasons":
            return sum(1 for e in E if e["event"] == "content_unavailable") == 2
        return False
    simple = {
        "dpkg.installed": lambda: "dpkg_installed" in K,
        "dpkg.removed": lambda: "dpkg_removed" in K,
        "dpkg.upgraded": lambda: "dpkg_upgraded" in K,
        "dpkg.downgraded": lambda: "dpkg_downgraded" in K,
        "dpkg.state_changed.alone": lambda: any(
            e["event"] == "dpkg_state_changed" and not any(
                f["event"] in ("dpkg_upgraded", "dpkg_downgraded") and f["package"] == e["package"]
                and f["arch"] == e["arch"] for f in E) for e in E),
        "dpkg.state_changed.with_upgrade": lambda: any(
            e["event"] == "dpkg_state_changed" and any(
                f["event"] == "dpkg_upgraded" and f["package"] == e["package"]
                and f["arch"] == e["arch"] for f in E) for e in E),
        "dpkg.empty_arch": lambda: any(e.get("arch") == "" for e in E),
        "dpkg.key_repeated_first_wins": lambda: has("dpkg_upgraded", package="curl",
                                                    **{"from": "1.0-1", "to": "2.0-1"}),
        "dpkg.multi_arch": lambda: len({e["arch"] for e in E if e.get("package") == "libssl3"}) >= 3,
        "dpkg.status_added_all_installed": lambda: K and all(k == "dpkg_installed" for k in K),
        "dpkg.status_removed": lambda: "dpkg_removed" in K and "dpkg_state_changed" in K,
        "dpkg.status_short": lambda: has("dpkg_installed", package="curl")
        and has("dpkg_removed", package="wget"),
        "dpkg.continuation_multiline": lambda: has("dpkg_upgraded", package="curl"),
        "dpkg.two_status_files": lambda: len({tuple(e.get("paths", [])) for e in E
                                              if e["interp"] == "dpkg"}) >= 2,
        "pip.installed": lambda: "pip_installed" in K,
        "pip.removed": lambda: "pip_removed" in K,
        "pip.upgraded": lambda: "pip_upgraded" in K,
        "pip.downgraded": lambda: "pip_downgraded" in K,
        "pip.version_changed.pep440_equal": lambda: K.count("pip_version_changed") == 2,
        "pip.version_changed.non_pep440": lambda: K.count("pip_version_changed") == 2,
        "pip.reinstalled.files_added": lambda: any(e.get("files_added", 0) > 0 for e in E),
        "pip.reinstalled.files_removed": lambda: any(e.get("files_removed", 0) > 0 for e in E),
        "pip.reinstalled.changed_hash": lambda: any(e.get("files_changed", 0) > 0 for e in E),
        "pip.reinstalled.changed_size": lambda: any(e.get("files_changed", 0) > 0 for e in E),
        "pip.reinstalled.path_listed_twice": lambda: "pip_reinstalled" in K,
        "pip.diff_dirs_not_paired": lambda: "pip_installed" in K and "pip_removed" in K,
        "pip.normalize_equal_paired": lambda: "pip_upgraded" in K and "pip_downgraded" in K,
        "pip.name_split_first_dash": lambda: has("pip_installed", name="typing",
                                                 version="extensions-4.8.0"),
        # E10: the file's could_not_interpret first (no name), the rest stand
        "pip.E10.unnameable": lambda: K == ["could_not_interpret", "pip_upgraded", "pip_installed"]
        and len(E[0]["paths" if "paths" in E[0] else "paths_b64"]) == 1
        and cni_records(mine) == 1,
        # in that name's place, naming the RECORDs; their records carry nothing
        "pip.E10.ambiguous": lambda: ("pip_installed" in K or "pip_removed" in K)
        and any(e["event"] == "could_not_interpret" and len(e["paths"]) >= 3 for e in E)
        and cni_records(mine) == 0,
        # name, kind and directory equal: then the paths it lists
        "pip.events_tie_by_paths": lambda: K == ["pip_removed"] * 2 + ["pip_installed"] * 3
        and [e["paths"] for e in E[:2]] == sorted(e["paths"] for e in E[:2])
        and [e["paths"] for e in E[2:]] == sorted(e["paths"] for e in E[2:])
        and [e["version"] for e in E[2:]] == ["2.0", "3.0", "1.0"],
        "pip.E10.unparseable_record": lambda: K == ["could_not_interpret", "pip_reinstalled",
                                                    "pip_installed"]
        and cni_records(mine) == 1,
        "dpkg.E9.oversized_text": lambda: K == ["dpkg_upgraded", "invalid_finding",
                                                "dpkg_removed"],
        "dpkg.E9.nul_value": lambda: K == ["dpkg_upgraded", "invalid_finding",
                                           "dpkg_state_changed"],
        "dpkg.E9.non_utf8_value": lambda: K == ["dpkg_upgraded", "invalid_finding",
                                                "invalid_finding", "dpkg_removed"],
        "dpkg.E10.unparseable_status": lambda: K == ["could_not_interpret", "dpkg_installed",
                                                     "dpkg_upgraded"]
        and E[0]["paths"] == ["var/lib/dpkg/status"] and cni_records(mine) == 1,
        # P7
        "pip.P7.unknown_pairs": lambda: has("pip_upgraded", provisional=True)
        and has("pip_downgraded", provisional=True)
        and any(e["event"] == "pip_installed" and "provisional" not in e for e in E)
        and no_unknown_findings(mine),
        "pip.P7.unknown_unpaired": lambda: has("pip_installed", provisional=True)
        and sum(1 for e in E if e["event"] == "pip_removed" and e.get("provisional")) == 2
        and any(e["event"] == "pip_removed" and "provisional" not in e for e in E)
        and no_unknown_findings(mine),
        # a provisional reinstall, its counts absent, under the second
        # template; its copies not read (no content_unavailable without a store)
        "pip.P7.unknown_both_sides": lambda: K == ["pip_installed", "pip_reinstalled"]
        and "provisional" not in E[0] and E[1].get("provisional") is True
        and not any(f in E[1] for f in ("files_added", "files_removed", "files_changed"))
        and E[1]["text"] == "reinstalled six 1.16.0 (files not counted)"
        and list(E[1]) == ["event", "interp", "name", "version", "text", "provisional", "paths"]
        and "unknown" in mine.outcomes.values() and no_unknown_findings(mine),
        # unnamable: one provisional could_not_interpret, no record finding
        "pip.P7.unknown_unnameable_both_sides": lambda: K == ["could_not_interpret",
                                                             "pip_installed"]
        and E[0].get("provisional") is True and "provisional" not in E[1]
        and E[0]["paths"] == ["usr/lib/python3/dist-packages/nodash.dist-info/RECORD"]
        and cni_records(mine) == 0 and no_unknown_findings(mine),
        # E11: nothing from a path unknown only as not_captured; any other
        # unknown path still provisional (E2)
        "pip.E11.below_unreadable": lambda: e11_silent(mine, 4)
        and K == ["pip_installed"] and "provisional" not in E[0],
        "pip.E11.below_mount": lambda: e11_silent(mine, 4)
        and K == ["pip_installed"] and "provisional" not in E[0],
        "pip.E11.excluded_above": lambda: e11_silent(mine, 2)
        and any(p.startswith(gen.SITES[1] + b"/") for p in mine.not_captured)
        and K == ["pip_installed"] and E[0]["name"] == "requests",
        "pip.E11.excluded_path": lambda: e11_silent(mine, 2)
        and gen.dist(gen.SITES[2], b"wheel", b"0.41")[0] in mine.not_captured,
        "pip.E11.not_a_partner": lambda: e11_silent(mine, 2)
        and K == ["pip_installed", "pip_removed"]
        and not any(e.get("provisional") for e in E)
        and E[0]["version"] == "2.0" and E[1]["version"] == "1.15.0",
        "pip.E11.not_in_ambiguity": lambda: e11_silent(mine)
        and K == ["pip_upgraded"] and "provisional" not in E[0]
        and (E[0]["from"], E[0]["to"]) == ("1.15.0", "1.16.0"),
        "pip.E11.unnameable": lambda: e11_silent(mine, 2) and K == ["pip_installed"]
        and cni_records(mine) == 0,
        "pip.E11.with_raced": lambda: e11_silent(mine)
        and K == ["pip_reinstalled", "pip_installed", "pip_removed"]
        and all(e.get("provisional") is True for e in E),
        "pip.E11.first_rule_decides": lambda: e11_silent(mine, 2) and not K,
        "pip.E11.excluded_both_sides": lambda: not any(
            p.startswith(gen.SITES[1]) for p in mine.outcomes)
        and K == ["pip_installed"] and mine.excluded[0] and mine.excluded[1],
        "pip.E11.v1_against_v2": lambda: e11_silent(mine, 2) and K == ["pip_installed"]
        and None in mine.excluded and mine.excluded != (None, None),
        "dpkg.E11.below_unreadable": lambda: e11_silent(mine, 2) and not K,
        "dpkg.E11.below_mount": lambda: e11_silent(mine, 2) and not K,
        "dpkg.E11.excluded_above": lambda: e11_silent(mine, 2) and not K
        and b"var/lib/dpkg/status" in mine.not_captured,
        "dpkg.E11.excluded_path": lambda: e11_silent(mine, 2) and not K
        and b"x/var/lib/dpkg/status" in mine.not_captured,
        # E11 (decision 118): "no `could_not_interpret` (E10) nor
        # `content_unavailable` for it" -- the not-captured statuses cannot
        # be parsed, yet only the captured one is named
        "dpkg.E11.unparseable": lambda: e11_silent(mine, 2) and K == ["could_not_interpret"]
        and E[0]["paths"] == ["var/lib/dpkg/status"] and cni_records(mine) == 1,
        "dpkg.E11.unparseable_no_store": lambda: e11_silent(mine, 2)
        and K == ["content_unavailable"] and E[0]["paths"] == ["var/lib/dpkg/status"]
        and cni_records(mine) == 0,
        "dpkg.E11.with_raced": lambda: e11_silent(mine) and K
        and all(e.get("provisional") is True for e in E)
        and {p for e in E for p in event_paths(e)} == {
            b"var/lib/dpkg/status", b"chroot/old/var/lib/dpkg/status"},
        # a file mounted on one side of a path on both: reason `mount`, not E11
        "probe.pip.mounted_record_not_e11": lambda: K == ["pip_reinstalled"]
        and E[0].get("provisional") is True and "files_added" not in E[0]
        and not mine.not_captured and "unknown" in mine.outcomes.values(),
        # (without a store, before's copy is no_store too)
        "probe.dpkg.mounted_status_not_e11": lambda: K and set(K) == {"content_unavailable"}
        and ("missing", "after") in [(e["reason"], e["side"]) for e in E]
        and all(e.get("provisional") is True for e in E) and not mine.not_captured,
        "dpkg.P7.unknown_status_readable": lambda: any(e.get("provisional") for e in E)
        and "content_unavailable" not in K and no_unknown_findings(mine),
        "dpkg.P7.unknown_status_no_store": lambda: K == ["content_unavailable"]
        and E[0].get("provisional") is True and no_unknown_findings(mine),
        "dpkg.P7.unknown_and_proven_no_store": lambda: K == ["content_unavailable"]
        and E[0].get("provisional") is True and len(E[0]["paths"]) == 2
        and no_unknown_findings(mine) and any(mine.findings.values()),
        # no-name events first: could_not_interpret by path, content_unavailable by reason
        "order.dpkg.no_name_first": lambda: K == ["could_not_interpret", "could_not_interpret",
                                                  "content_unavailable", "content_unavailable",
                                                  "dpkg_upgraded", "dpkg_installed"]
        and E[0]["paths"][0] < E[1]["paths"][0]
        and [E[2]["reason"], E[3]["reason"]] == ["missing", "corrupt"],
        "order.pip.no_name_first": lambda: K == ["could_not_interpret", "could_not_interpret",
                                                 "content_unavailable", "pip_installed",
                                                 "could_not_interpret", "pip_installed"]
        and E[0]["paths"][0] < E[1]["paths"][0],
        "pip.metadata_changes_nothing": lambda: not K and not any(mine.findings.values()),
        "pip.events_order": lambda: len(set(K)) >= 3 and len(K) >= 5,
        "paths_b64": lambda: any("paths_b64" in e for e in E),
        "random": lambda: True,
        "probe.dpkg.E5_bound": lambda: K.count("dpkg_installed") == ref.EVENT_BOUND - 1
        and K[-1] == "and_more",
        "probe.dpkg.E10_line_not_a_field": lambda: K == ["could_not_interpret"]
        and cni_records(mine) == 1,
        "probe.dpkg.E9_value_not_string": lambda: K == ["invalid_finding"],
        "probe.dpkg.E9_value_over_1024": lambda: K == ["invalid_finding", "dpkg_installed"],
        "probe.dpkg.E9_version_over_1024": lambda: K == ["invalid_finding", "dpkg_installed"],
        "probe.dpkg.long_value_without_event": lambda: K == ["dpkg_installed"],
        "probe.dpkg.E10_names_the_file": lambda: K == ["could_not_interpret"]
        and E[0]["paths"] == ["var/lib/dpkg/status"],
        "probe.pip.E10_row_of_two_fields": lambda: K == ["could_not_interpret"],
        "probe.pip.E10_row_of_four_fields": lambda: K == ["could_not_interpret"],
        "probe.pip.E10_record_not_utf8": lambda: K == ["could_not_interpret"],
        "probe.dpkg.E9_event_text_over_1024": lambda: K == ["invalid_finding"],
        "probe.dpkg.unknown_E9_provisional": lambda: K == ["invalid_finding", "dpkg_installed"]
        and all(e.get("provisional") for e in E) and no_unknown_findings(mine),
        "probe.dpkg.unknown_E10_provisional": lambda: K == ["could_not_interpret",
                                                           "dpkg_upgraded"]
        and E[0].get("provisional") is True and "provisional" not in E[1]
        and cni_records(mine) == 0,
        "probe.pip.unknown_unnameable_one_side": lambda: K == ["could_not_interpret",
                                                              "pip_installed"]
        and E[0].get("provisional") is True and cni_records(mine) == 0,
        "probe.pip.ambiguous_with_unknown": lambda: K == ["could_not_interpret"]
        and E[0].get("provisional") is True and cni_records(mine) == 0,
        "probe.pip.E9_text_over_1024": lambda: K == ["pip_installed", "invalid_finding",
                                                     "pip_installed"],
        "probe.pip.unnameable_content_unavailable": lambda: K == ["could_not_interpret"]
        and cni_records(mine) == 1,
        # The claim's edge, seen in belay's records: an .md5sums outside
        # var/lib/dpkg/info/ is text (text_added), the one inside is dpkg's.
        "probe.dpkg.md5sums_outside_info": lambda: belay is not None
        and (belay[1].get(b"etc/foo.md5sums", (None, None))[1] or b"").startswith(
            b'[{"kind":"text_added"')
        and belay[1].get(b"var/lib/dpkg/info/curl.md5sums", (None, None))[1] is None,
    }
    if cell in simple:
        return bool(simple[cell]())
    if cell.startswith("probe."):
        return True
    raise KeyError("no check for cell " + cell)


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--driver", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--keep", action="store_true", help="keep every case's directory")
    ap.add_argument("--only", help="run only cases whose name contains this")
    a = ap.parse_args()

    t0 = time.time()
    if os.path.exists(a.work):
        shutil.rmtree(a.work)
    os.makedirs(a.work)
    cache = os.path.join(os.path.dirname(os.path.abspath(a.work)), "zero-digests.json")
    cases = gen.all_cases(a.n, a.seed)
    if a.only:
        cases = [c for c in cases if a.only in c.name]
    hits = collections.Counter()
    declared = set()
    failed = []
    pairs = 0
    seen_kinds = collections.Counter()
    e11 = collections.Counter()
    disagree = collections.Counter()
    disagree_eg = {}
    dlog = []
    for case in cases:
        d = os.path.join(a.work, case.name)
        gen.write_case(case, d, cache)
        before = os.path.join(d, "before.ndjson")
        after = os.path.join(d, "after.ndjson")
        store = os.path.join(d, "store")
        report = []
        for mode in case.modes:
            pairs += 1
            out = os.path.join(d, "diff-%s.ndjson" % mode)
            cmd = [a.driver] + (["--store", store] if mode == "store" else ["--no-store"])
            r = subprocess.run(cmd + [before, after, out], capture_output=True)
            mine = ref.interpret(before, after, store if mode == "store" else None)
            if r.returncode != 0:
                report.append("[%s] driver failed (%d): %s" % (mode, r.returncode,
                                                               r.stderr.decode(errors="replace")))
                continue
            for e in mine.events:
                o = json.loads(e)
                seen_kinds["%s %s" % (o["interp"], o["event"])] += 1
            if mine.not_captured & set(mine.claims):
                e11["E11: a claimed path not captured"] += 1
                if any(b'"provisional":true' in e for e in mine.events):
                    e11["E11 and E2: that, and a provisional event"] += 1
            v2 = sum(1 for x in mine.excluded if x is not None)
            if v2:
                e11["v2 manifests: %d of the two" % v2] += 1
            belay = parse_diff(out)
            diffs = compare(belay, mine)
            if diffs:
                st = store if mode == "store" else None
                every = frozenset(ref.ALT_READINGS)
                if not compare(belay, ref.interpret(before, after, st, every)):
                    need = set(every)
                    for name in sorted(every):
                        if not compare(belay, ref.interpret(before, after, st, need - {name})):
                            need.discard(name)
                    key = " + ".join(sorted(need))
                    disagree[key] += 1
                    disagree_eg.setdefault(key, "%s [%s]" % (case.name, mode))
                    dlog.append("%s [%s]: %s\n%s" % (case.name, mode, key,
                                                      "\n".join("  " + x for x in diffs)))
                    diffs = []
            if diffs:
                report.append("[%s]" % mode)
                report += ["  " + x for x in diffs]
            for cell in case.tags[mode]:
                declared.add(cell)
                if check_cell(cell, mine, belay):
                    hits[cell] += 1
                else:
                    report.append("[%s] cell %s not shown by the reference's output" % (mode, cell))
        if report:
            failed.append(case.name)
            with open(os.path.join(d, "report.txt"), "w") as f:
                f.write("\n".join(report) + "\n")
            print("FAIL %s (%s)" % (case.name, os.path.join(d, "report.txt")))
            for line in report[:40]:
                print("  " + line)
        elif not a.keep:
            shutil.rmtree(d)

    print("\nevent records the reference expected, over every pair:")
    for k, n in sorted(seen_kinds.items()):
        print("  %-48s %d" % (k, n))
    print("\npairs with:")
    for k, n in sorted(e11.items()):
        print("  %-48s %d" % (k, n))
    print("\ndisagreements -- pairs belay gives otherwise, each difference explained in full")
    print("by belay's reading of a sentence the two can read either way (ref.ALT_READINGS):")
    for k, n in sorted(disagree.items()):
        print("  %-60s %5d  (e.g. %s)" % (k, n, disagree_eg[k]))
    if not disagree:
        print("  none")
    with open(os.path.join(a.work, "disagreements.txt"), "w") as f:
        for name, text in sorted(ref.ALT_READINGS.items()):
            f.write("%s: belay's reading -- %s\n\n" % (name, text))
        f.write("\n\n".join(dlog) + "\n")
    print("\ncells (hits):")
    zero = []
    for cell in sorted(declared):
        print("  %-48s %d" % (cell, hits[cell]))
        if hits[cell] == 0:
            zero.append(cell)
    print("\n%d cases, %d pairs, %d failing cases, %d pairs disagreeing as listed, %.1f s"
          % (len(cases), pairs, len(failed), sum(disagree.values()), time.time() - t0))
    if zero:
        print("coverage gate: cells never hit: " + ", ".join(zero))
    if failed:
        print("failing: " + ", ".join(failed))
    return 1 if (failed or zero) else 0


if __name__ == "__main__":
    sys.exit(main())
