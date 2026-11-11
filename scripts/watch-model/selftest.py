#!/usr/bin/env python3
"""watch-model's self-test: model.py against cases taken from the pin's own examples and
sentences (test/expect/watch-v1.md). No binary is run. Exit 0 when every case holds."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import model  # noqa: E402

M = model.Model()
FAILS = []


def tree_of(spec):
    """{'a/b': 'f'} with the directories above each path added."""
    t = {}
    for p, ty in spec.items():
        comps = p.split("/")
        for k in range(1, len(comps)):
            t.setdefault("/".join(comps[:k]).encode(), "d")
        t[p.encode()] = ty
    return t


def check(what, got, want):
    if got != want:
        FAILS.append("%s: got %r, want %r" % (what, got, want))


def cls(path, etype="f", user=()):
    r = M.classify(path.encode(), etype, [u.encode() for u in user])
    return None if r is None else r[:3]


GIT = "git hooks and config"


def run():
    # The table itself.
    check("68 rows", len(M.rows), 68)
    check("row ids in order", [r.num for r in M.rows], list(range(1, 69)))
    check("kinds of rows, in FK's order", M.kind_order,
          [GIT, "agent rules", "loads on its own", "package source", "CI", "credentials"])
    seen = []
    for r in M.rows:                      # first row and first kind agree: kinds are contiguous
        if not seen or seen[-1] != r.kind:
            seen.append(r.kind)
    check("the table's kinds are contiguous and in FK's order", seen, M.kind_order)
    for r in M.rows:                      # BR-P1
        first = r.comps[0]
        ok = b"*" not in first or (first == b"**" and len(r.comps) > 1)
        check("BR-P1 %s" % r.id, ok, True)
    check("BR-4 limits", (M.rows[3].not_dir, M.rows[3].not_new_dir, M.rows[3].noted_modified), (True, True, True))
    check("BR-17 noted", (M.rows[16].noted, M.rows[16].noted_modified), (True, False))
    check("BR-2 except", M.rows[1].excepts, ["**/*.sample"])
    check("BR-18 except", M.rows[17].excepts, [".claude/worktrees"])

    # WD-1, PS-P2, PS-P3.
    mt = lambda p, n: model.match(model.split(p), model.split(n))
    cv = lambda p, n: model.covers(model.split(p), model.split(n))
    check("tests/** matches tests", mt(b"tests/**", b"tests"), True)
    check("tests/** matches below", mt(b"tests/**", b"tests/a/b"), True)
    check("test_*.py", mt(b"test_*.py", b"test_x.py"), True)
    check("test_*.py none included", mt(b"test_*.py", b"test_.py"), True)
    check("* stays in a component", mt(b"test_*.py", b"test_a/b.py"), False)
    check("PS-P4 off: tests/** and .cache", mt(b"tests/**", b"tests/.cache/x"), True)
    check("PS-P4 off: * and .env", mt(b"*", b".env"), True)
    check("? is itself", mt(b"a?", b"ab"), False)
    # WD-2.
    check("migrations covers migrations/0001.py", cv(b"migrations", b"migrations/0001.py"), True)
    check(".claude covers what is in it", cv(b".claude", b".claude/a/b"), True)
    check("migrations does not match migrations2", cv(b"migrations", b"migrations2/x"), False)
    # WD-3.
    check("*.lock top", cv(b"*.lock", b"a.lock"), True)
    check("*.lock not below", cv(b"*.lock", b"sub/a.lock"), False)
    check("**/*.lock top", cv(b"**/*.lock", b"a.lock"), True)
    check("**/*.lock deep", cv(b"**/*.lock", b"a/b/c.lock"), True)

    # WD-4.
    check("user pattern is case-sensitive", cls("Migrations/0001.py", user=["migrations"]), None)
    check("row is case-insensitive", cls(".ENV"), ("credentials", "flag", "credentials"))
    check("exception is case-sensitive", cls(".git/hooks/pre-commit.SAMPLE"), (GIT, "flag", "git hook"))

    # The pin's examples.
    check("example pre-push", cls(".git/hooks/pre-push"), (GIT, "flag", "git hook"))
    check("example .git/config", cls(".git/config"), (GIT, "note", "git config"))
    check("example .gitmodules", cls(".gitmodules"), (GIT, "flag", "git submodules"))
    check("example migrations", cls("migrations/0001.py", user=["migrations"]),
          ("don't-touch", "flag", "don't-touch"))
    check("example .husky/pre-commit", cls(".husky/pre-commit"), (GIT, "flag", "git hook manager"))
    check("example .env", cls(".env"), ("credentials", "flag", "credentials"))

    # Measured: what is still flagged under C.
    pth = ("loads on its own", "flag", "runs at every Python start")
    check("distutils-precedence.pth", cls("venv/lib/python3.12/site-packages/distutils-precedence.pth"), pth)
    check("__editable__ pth", cls("site-packages/__editable__.demo-0.1.pth"), pth)
    check(".devcontainer entry", cls("repo/.devcontainer/devcontainer.json"),
          ("loads on its own", "flag", "container setup"))
    check(".pre-commit-config.yaml", cls("repo/.pre-commit-config.yaml"), (GIT, "flag", "git hook manager"))
    check("submodule's .git/config", cls("sub/.git/config"), (GIT, "note", "git config"))
    # Measured: what C does not flag.
    check(".travis.yml in node_modules", cls("node_modules/pkg/.travis.yml"), None)
    check("workflows in node_modules", cls("node_modules/pkg/.github/workflows/ci.yml"), None)
    check("workflows in a clone below (BR-P2)", cls("clone/.github/workflows/ci.yml"), None)
    check("cacert.pem", cls("venv/lib/python3.12/site-packages/certifi/cacert.pem"), None)
    check("tornado test.key", cls("venv/lib/site-packages/tornado/test/test.key"), None)
    check(".yarnrc.yml in jupyterlab", cls("venv/lib/site-packages/jupyterlab/staging/.yarnrc.yml"), None)
    check(".gitattributes", cls(".gitattributes"), None)
    # Left out.
    check(".pypirc", cls(".pypirc"), None)
    check("sitecustomize.py outside site-packages", cls("sitecustomize.py"), None)
    check("*.pth outside site-packages", cls("x.pth"), None)
    check(".vscode/extensions.json", cls(".vscode/extensions.json"), None)

    # Limits.
    check("BR-L1: a virtualenv named .env", cls(".env", "d"), None)
    check("BR-L1: nothing below it", cls(".env/bin/python"), None)
    check("BR-L1: .git/hooks as a symlink (BR-1's probe)", cls(".git/hooks", "l"), (GIT, "flag", "git hook"))
    check("BR-L1: .git/hooks as a directory", cls(".git/hooks", "d"), None)
    check("BR-L2: at a directory named node_modules", cls("node_modules/.npmrc"), None)
    check("BR-L2: at any depth", cls("a/b/node_modules/c/d/.env"), None)
    check("BR-L2 is per row: .pth is in site-packages by its pattern", cls("site-packages/a.pth"), pth)
    check("BR-L4: *.sample", cls(".git/hooks/pre-commit.sample"), None)
    check("BR-L4: .claude/worktrees", cls(".claude/worktrees", "d"), None)
    check("BR-L4: below .claude/worktrees", cls(".claude/worktrees/x/file.c"), None)
    check("BR-L6 / BR-17", cls(".claude/settings.local.json"), ("agent rules", "note", "agent permissions"))
    check("BR-18", cls(".claude/settings.json"), ("agent rules", "flag", "agent rules"))
    check("BR-18 covers below", cls(".claude/hooks/x.sh"), ("agent rules", "flag", "agent rules"))
    check("BR-P3: .claude itself", cls(".claude", "d"), None)
    check("BR-P2: CODEOWNERS below the top", cls("sub/CODEOWNERS"), None)
    check("BR-P2: a repository below", cls("sub/.git/hooks/pre-commit"), (GIT, "flag", "git hook"))
    check("first kind wins", cls(".husky/.env"), (GIT, "flag", "git hook manager"))
    check("first row wins", cls(".claude/settings.local.json", "f"), ("agent rules", "note", "agent permissions"))

    # FK-1, FL-3.
    dt = ("don't-touch", "flag", "don't-touch")
    check(".belay-donttouch itself", cls(".belay-donttouch"), dt)
    check(".belay-donttouch below the top", cls("sub/.belay-donttouch"), None)
    check("a user's pattern comes first", cls(".git/config", user=[".git"]), dt)
    check("a user's pattern has no limits", cls("node_modules/a/x.pem", user=["**/*.pem"]), dt)
    check("a user's pattern flags a directory", cls(".env", "d", user=[".env"]), dt)

    check("the top: ** matches no components", M.classify_top([b"**"]), dt + (None,))
    check("the top: * needs a name", M.classify_top([b"*", b".*", b"*.", b"**/*", b"x/**"]), None)
    check("the top is counted by **", M.user_count(b"**", tree_of({"a/b": "f"})), 3)

    # DT-2 to DT-4.
    pd = model.parse_donttouch
    check("valid", pd(b"# c\n\nmigrations\n**/*.lock\n"), ("ok", [b"migrations", b"**/*.lock"]))
    check("no final LF", pd(b"a\nb"), ("ok", [b"a", b"b"]))
    check("empty", pd(b""), ("ok", []))
    check("CRLF", pd(b"a\r\nb\r\n")[:2], ("line", 1))
    for bad in (b"a\tb", b"a\x01b", b"a\x7fb", b"/a", b"a/", b"a//b", b".", b"..", b"a/./b", b"a/../b", b"a?",
                b"a[b]", b"a\\b", b"!a"):
        check("invalid %r" % bad, pd(b"# one\nok\n" + bad + b"\nok2\n")[:2], ("line", 3))
    for good in (b"a!b", b"...", b".a", b"a b", b"a#b", b"**", b"*"):
        check("valid %r" % good, pd(good + b"\n"), ("ok", [good]))
    check("a NUL in a pattern: cannot be read, no line", pd(b"ok\na\x00b\n")[0], "unreadable")
    check("a NUL in a comment: cannot be read", pd(b"# c\x00\nok\n")[0], "unreadable")
    check("a NUL alone on a line", pd(b"ok\n\x00\n")[0], "unreadable")
    check("a NUL beside an invalid line (READING 16)", pd(b"a?\n\x00\n")[0], "unreadable")
    check("a NUL: no list in force", model.list_in_force({b".belay-donttouch": "f"}, b"a\n#\x00\n"),
          (("unreadable",), []))
    check("a CR in a comment is not validated", pd(b"# c\r\nok\n"), ("ok", [b"ok"]))
    check("256 patterns", pd(b"".join(b"p%d\n" % i for i in range(256)))[0], "ok")
    check("257 patterns", pd(b"".join(b"p%d\n" % i for i in range(257)))[0], "limit")
    check("4096 bytes", pd(b"a" * 4096 + b"\n")[0], "ok")
    check("4097 bytes", pd(b"a" * 4097 + b"\n")[0], "limit")
    check("four **", pd(b"**/a/**/b/**/c/**\n")[0], "ok")
    check("five **", pd(b"**/a/**/b/**/c/**/d/**\n")[0], "limit")
    check("64 KiB", pd(b"#" + b"x" * 65534 + b"\n")[0], "ok")
    check("64 KiB + 1", pd(b"#" + b"x" * 65535 + b"\n")[0], "limit")

    # DT-1, DT-6 on a first step.
    t = tree_of({".belay-donttouch": "f", "a": "f"})
    check("no file is an empty list", model.list_in_force(tree_of({"a": "f"}), None), (("none",), []))
    check("valid list", model.list_in_force(t, b"a\n"), (("ok",), [b"a"]))
    check("invalid list: none in force", model.list_in_force(t, b"a?\n")[1], [])

    # Counts (WD-6).
    t = tree_of({"migrations/0001.py": "f", "migrations/0002.py": "f", ".env": "d", ".env/x": "f",
                 "node_modules/p/.env": "f", "src/.env": "f"})
    check("user count includes what is below", M.user_count(b"migrations", t), 3)
    env = [r for r in M.rows if r.pattern == "**/.env"]
    check("one **/.env row", len(env), 1)
    check("row count applies the limits", M.row_count(env[0], t), 1)


def main():
    run()
    for f in FAILS:
        print("FAIL " + f)
    print("watch-model self-test: %s" % ("%d failed" % len(FAILS) if FAILS else "passed"))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
