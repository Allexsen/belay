#!/usr/bin/env python3
"""watch-model's scenarios. Deterministic: a fixed seed, and the rows read from the pin.

A scenario is a dict:
  name      unique
  category  the line of run.py's table it is counted under
  tree      {path str: 'd' | 'f' | 'l'}, every directory above a path included
  links     {path str: target str} for the symlinks (default target: a name that is not there)
  dt        the bytes of `.belay-donttouch` when the tree has it as a regular file, else None

Names are printable ASCII (dot-names, case variants, spaces), so belay's escaping of a shown path
never comes into it; one user pattern holds bytes >= 0x80, no file name does. Case variants of
one name are put in one directory, so the scenarios need a case-sensitive file system.
"""

import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import model  # noqa: E402

SEED = 20261110


class Tree(object):
    def __init__(self):
        self.t = {}
        self.links = {}

    def add(self, path, etype="f", target=None):
        """Adds the entry and the directories above it. False when it cannot be (something
        above is not a directory, or the path is there with another type)."""
        comps = path.split("/")
        if any(c in ("", ".", "..") for c in comps):
            raise ValueError("bad path %r" % path)
        for k in range(1, len(comps)):
            if self.t.get("/".join(comps[:k]), "d") != "d":
                return False
        if path in self.t:
            return self.t[path] == etype
        for k in range(1, len(comps)):
            self.t["/".join(comps[:k])] = "d"
        self.t[path] = etype
        if etype == "l":
            self.links[path] = target or "nowhere"
        return True


def scenario(name, category, tree, dt=None):
    t = dict(tree.t)                                     # the Tree is not changed: it may be reused
    if dt is not None:
        if t.get(".belay-donttouch", "f") != "f":
            raise ValueError("%s: .belay-donttouch is there and not a file" % name)
        t[".belay-donttouch"] = "f"
    elif t.get(".belay-donttouch") == "f":
        raise ValueError("%s: .belay-donttouch is a file with no content given" % name)
    return {"name": name, "category": category, "tree": t, "links": dict(tree.links), "dt": dt}


# --------------------------------------------------------------------------- one row at a time

WHOLE_FILLS = ["pre-commit", ".dotname", "With Space"]
PART_FILLS = ["x", "", ".a.b"]
PRES = [[], ["sub"], ["a", "b"], [".hid", "d e"]]
MIDS = [[], ["m"], ["m", "n"]]


def instances(row):
    """Paths the row's pattern matches, as lists of components: (pre, path)."""
    pcs = row.pattern.split("/")
    out = []
    lead = pcs[0] == "**"
    body = pcs[1:] if lead else pcs
    for pre in (PRES if lead else [[]]):
        for mid in (MIDS if "**" in body else [[]]):
            for fi in range(3):
                comps = list(pre)
                for c in body:
                    if c == "**":
                        comps += mid
                    elif c == "*":
                        comps.append(WHOLE_FILLS[fi])
                    elif "*" in c:
                        comps.append(c.replace("*", PART_FILLS[fi]))
                    else:
                        comps.append(c)
                if "*" not in "".join(body).replace("**", "") and fi > 0:
                    continue
                p = "/".join(comps)
                if p not in out:
                    out.append(p)
    return out


def swap(s):
    return s.swapcase()


def row_scenarios(row):
    out = []
    inst = instances(row)
    top_only = row.pattern.split("/")[0] != "**"

    # Where it applies, and its near misses.
    t = Tree()
    for p in inst:
        t.add(p, "f")
    first = inst[0]
    t.add(first + "x", "f")                              # a longer last name
    t.add("x" + first, "f")                              # a longer first name
    t.add("zz/x" + first, "f")
    if top_only:
        t.add("below/" + first, "f")                     # WD-3, BR-P2
        t.add("below/deeper/" + first, "f")
    t.add("lnk/" + first, "l")
    out.append(scenario("%s applies" % row.id, "row applies (file, depths, near misses)", t))

    # The same paths as directories with things in them; one as a symlink.
    t = Tree()
    for i, p in enumerate(inst):
        if i == 1 and len(inst) > 2:
            t.add(p, "l")
            continue
        t.add(p, "d")
        t.add(p + "/child.txt", "f")
        t.add(p + "/deep/inner.txt", "f")
        t.add(p + "/deep/key.pem", "f")                  # another row's, when this one is off
        t.add(p + "/CLAUDE.md", "f")
        t.add(p + "/emptydir", "d")
    out.append(scenario("%s as a directory" % row.id, "row on a directory (BR-L1, WD-2)", t))

    # In a dependency, above and below the match.
    t = Tree()
    for i, p in enumerate(inst[:4]):
        t.add("node_modules/pkg/" + p, "f")
        t.add("site-packages/pkg/" + p, "f")
        t.add("deep/er/node_modules/" + p, "f")
        t.add("node_modules/" + p, "f")
        t.add("Node_Modules/pkg/" + p, "f")              # READING 2
        t.add("SITE-PACKAGES/" + p, "f")
        t.add("node_modules_x/" + p, "f")
        t.add("xsite-packages/" + p, "f")
        t.add("notdep/" + p, "f")
    t.add("filedep/node_modules", "f")                   # a file of that name is not a directory
    t.add(inst[0], "l")                                  # the row's own path as a symlink
    if not row.not_dir:
        t2 = Tree()
        p = inst[0]
        t2.add(p + "/node_modules/x.js", "f")
        t2.add(p + "/node_modules", "d")
        t2.add(p + "/site-packages", "f")                # READING 3
        t2.add(p + "/plain", "f")
        t2.add(p + "/vendor/site-packages/y", "f")
        out.append(scenario("%s dependency below the match" % row.id, "row in a dependency (BR-L2)", t2))
    out.append(scenario("%s in a dependency" % row.id, "row in a dependency (BR-L2)", t))

    # Case (WD-4): the row folds ASCII case, on every component.
    t = Tree()
    for i, p in enumerate(inst[:3]):
        t.add("u%d/" % i + p.upper(), "f")
        t.add("s%d/" % i + swap(p), "f")
        t.add("c%d/" % i + p.title(), "f")
    if top_only:
        t.add(first.upper(), "f")
        t.add(swap(first), "f")
    else:
        t.add(first.upper(), "f")
    out.append(scenario("%s case" % row.id, "row and case (WD-4)", t))

    # Exceptions (BR-L4).
    for ex in row.excepts:
        tag = "" if len(row.excepts) == 1 else " " + ex      # a row may carry more than one
        t = Tree()
        if ex.startswith("**/*"):
            suf = ex[4:]
            for p in inst:
                if p.endswith("/pre-commit"):
                    base = p[:-len("pre-commit")]
                    for nm in ("pre-commit" + suf, suf, "a.b" + suf, "x" + suf.upper(), "x" + suf + ".bak",
                               "x" + suf.title(), suf + "x", "x" + suf[1:]):
                        t.add(base + nm, "f")
                    t.add(base + "lnk" + suf, "l")
            t.add("proj" + suf + "/" + inst[0], "f")     # READING 4: below a match of the exception
            t.add("proj" + suf.upper() + "/" + inst[0], "f")
        else:
            t.add(ex, "d")
            t.add(ex + "/wt/file.c", "f")
            t.add(ex + "/wt/CLAUDE.md", "f")             # READING 5: BR-19 after BR-18 is off
            t.add(ex + "/wt/.env", "f")
            t.add(ex + "/wt/.claude/settings.json", "f")
            t.add(ex + "x", "f")
            t.add(ex + "x2/inner", "f")
            t.add(os.path.dirname(ex) + "/" + os.path.basename(ex).title() + "/wt/file.c", "f")
            t.add(os.path.dirname(ex) + "/" + os.path.basename(ex).upper(), "f")
            t.add(os.path.dirname(ex) + "/other/file", "f")
            t2 = Tree()
            t2.add(ex, "f")                              # the exception's path as a file
            t2.add(os.path.dirname(ex) + "/kept", "f")
            out.append(scenario("%s exception%s as a file" % (row.id, tag), "row exception (BR-L4)", t2))
            t3 = Tree()
            t3.add(ex, "l")
            out.append(scenario("%s exception%s as a symlink" % (row.id, tag), "row exception (BR-L4)", t3))
        out.append(scenario("%s exception%s" % (row.id, tag), "row exception (BR-L4)", t))
    return out


def table_scenarios(rows):
    out = []
    # Left out, BR-P2, BR-P3 and the pin's own sentences.
    t = Tree()
    for p in (".gitattributes", ".pypirc", "sitecustomize.py", "usercustomize.py", "x.pth",
              ".vscode/extensions.json", "lib/sitecustomize.py", "README.md", "src/main.c"):
        t.add(p)
    t.add(".claude", "d")
    out.append(scenario("left out; .claude alone", "the pin's sentences", t))
    t = Tree()
    t.add(".claude", "l", "elsewhere")
    t.add(".cursor", "l")
    t.add(".github", "l")
    t.add(".git", "f")                                   # a worktree's .git is a file
    t.add("wt/.git", "f")
    out.append(scenario("top directories as symlinks; .git as a file", "the pin's sentences", t))
    t = Tree()
    for p in ("clone/.github/workflows/ci.yml", "clone/.github/CODEOWNERS", "clone/.claude/settings.json",
              "clone/.mcp.json", "clone/.cursor/rules", "clone/.git/config", "clone/.git/hooks/pre-commit",
              "clone/.git/info/exclude", "clone/.circleci/config.yml", "clone/Jenkinsfile",
              "clone/CLAUDE.md", "clone/.env"):
        t.add(p)
    out.append(scenario("BR-P2: a repository below the top", "the pin's sentences", t))
    t = Tree()
    for p in (".env/bin/python", ".env/lib/python3.12/site-packages/a.pth", ".env/pyvenv.cfg",
              ".env/secrets.pem", "venv/lib/python3.12/site-packages/distutils-precedence.pth",
              "venv/lib/python3.12/site-packages/__editable__.demo-0.1.pth",
              "venv/lib/python3.12/site-packages/certifi/cacert.pem",
              "venv/lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem",
              "venv/lib/python3.12/site-packages/tornado/test/test.key",
              "venv/lib/python3.12/site-packages/jupyterlab/staging/.yarnrc.yml",
              "venv/lib/python3.12/site-packages/sitecustomize.py",
              "venv/lib/python3.12/site-packages/sub/b.pth",
              "venv/pip.conf", "node_modules/a/.travis.yml", "node_modules/a/.github/workflows/x.yml",
              "node_modules/a/.npmrc", "node_modules/.bin/tool", "node_modules/a/.husky/pre-commit",
              "node_modules/a/.git/hooks/pre-commit", "node_modules/a/.git/config",
              "node_modules/a/.gitmodules"):
        t.add(p)
    out.append(scenario("Measured: a virtualenv named .env, site-packages, node_modules", "the pin's sentences", t))
    t = Tree()
    for p in (".git/hooks/pre-push", ".git/config", ".gitmodules", ".husky/pre-commit", ".env",
              "migrations/0001.py", "bin/tool", "a.txt", "vendor/x/y", ".git/hooks/pre-commit.sample",
              ".git/modules/lib/config", ".git/modules/lib/hooks/pre-commit",
              ".git/modules/lib/hooks/pre-commit.sample", ".git/modules/a/modules/b/hooks/post-merge",
              ".git/worktrees/w1/config.worktree", ".git/config.worktree", ".git/info/attributes",
              ".git/modules/config", ".git/modules/hooks/x", ".git/HEAD", ".git/objects/ab/cd",
              ".git/worktrees/config.worktree", ".git/worktrees/a/b/config.worktree"):
        t.add(p)
    out.append(scenario("the examples' paths, with a list", "the pin's sentences", t, b"migrations\n"))
    # Every row at once, at the top, as files; and all as directories.
    t = Tree()
    t2 = Tree()
    for r in rows:
        p = instances(r)[0]
        t.add(p, "f")
        t2.add(p, "d")
        t2.add(p + "/in", "f")
    out.append(scenario("every row's first instance, files", "every row together", t))
    out.append(scenario("every row's first instance, directories", "every row together", t2))
    return out


# --------------------------------------------------------------------------- .belay-donttouch

def base_tree():
    t = Tree()
    for p in ("migrations/0001.py", "migrations/sub/0002.py", "Migrations/0001.py", "src/a.lock",
              "src/deep/b.lock", "x.lock", ".x.lock", ".env", ".git/config", ".git/hooks/pre-commit",
              "Makefile", ".hidden/x", ".hidden/.y", "docs/CODEOWNERS", "a b", "a!b", "a#b", "...",
              " ", "tests/.cache/x", "tests/unit/t.py", "node_modules/p/x.pem", ".claude/settings.json",
              "x", "sub/x", "sub/sub/x", "#note", " #note", "plain"):
        t.add(p)
    t.add("emptydir", "d")
    t.add("link.lock", "l")
    return t


def dt_scenario(name, category, content, extra=()):
    t = base_tree()
    for p in extra:
        t.add(p)
    return scenario(name, category, t, content)


def donttouch_scenarios():
    out = []
    V = "user list: valid, and what it covers"
    valid = [
        ("a directory covers what is below", b"migrations\n"),
        ("case-sensitive", b"MIGRATIONS\nmakefile\n.ENV\n"),
        ("top only vs any depth", b"*.lock\n"),
        ("any depth", b"**/*.lock\n"),
        ("** alone", b"**\n"),
        ("* alone: dot-names too", b"*\n"),
        ("*/* ", b"*/*\n"),
        ("dir/**", b"tests/**\nsrc/**\n"),
        ("**/name", b"**/x\n"),
        ("**/dir/**", b"**/sub/**\n"),
        ("** in the middle", b"sub/**/x\nmigrations/**/0002.py\n"),
        ("dot-names under * and **", b".*\n**/.*\n"),
        ("partial stars", b"M*e\n*a*\n**/*.l*k\n"),
        ("star matches none", b"x*\n*x\nMakefile*\n"),
        ("before a built-in row", b".git\n.env\n.claude\nnode_modules\n"),
        ("before a noted row", b".git/config\n"),
        ("one file inside a row's directory", b".claude/settings.json\n**/hooks/*\n"),
        ("comments and blank lines", b"# a comment\n\n\nmigrations\n   \n#x.lock\n\nx.lock\n"),
        ("no final LF", b"migrations\nx.lock"),
        ("empty file", b""),
        ("one LF", b"\n"),
        ("only comments", b"# nothing\n#\n# here ? [ \\ !\n"),
        ("a space-only line is a pattern (READING 7)", b" \n"),
        ("a line starting with a space then # is a pattern", b" #note\n"),
        ("# inside, ! inside, spaces", b"a#b\na!b\na b\n"),
        ("dots that are not . or ..", b"...\n.x.lock\n.hidden/.y\n"),
        ("the same pattern twice", b"x.lock\nx.lock\n"),
        ("matches nothing", b"nothing-here\n**/nope/**\n"),
        ("bytes >= 0x80 in a pattern", b"caf\xc3\xa9\n\xff\xfe\n"),
        ("the file names itself", b".belay-donttouch\n"),
        ("a pattern that is a file, not a directory", b"Makefile\nMakefile/x\n"),
        ("a**b is two stars in a component", b"**/a**b\nM**e\n"),
        ("consecutive **", b"**/**/x\n"),
        ("trailing spaces are part of the pattern", b"migrations \n x.lock\n"),
        ("a symlink and an empty directory", b"link.lock\nemptydir\n"),
    ]
    for name, content in valid:
        out.append(dt_scenario("valid: " + name, V, content))

    I = "user list: invalid by DT-3"
    bad = [
        ("CRLF", b"x.lock\r"), ("a tab", b"a\tb"), ("byte 0x01", b"a\x01b"), ("byte 0x1f", b"a\x1f"),
        ("DEL 0x7f", b"a\x7fb"), ("leading /", b"/migrations"),
        ("trailing /", b"migrations/"), ("empty component", b"src//a.lock"), (". alone", b"."),
        (".. alone", b".."), (". component", b"src/./a.lock"), (".. component", b"src/../x"),
        ("leading ./", b"./x"), ("trailing /..", b"src/.."), ("?", b"x.loc?"), ("[", b"x.[l]ock"),
        ("backslash", b"x\\.lock"), ("leading !", b"!x.lock"), ("/ alone", b"/"),
    ]
    for i, (name, line) in enumerate(bad):
        pre = [b"# c\n", b"migrations\n", b"\n"][: i % 4]
        content = b"".join(pre) + line + b"\n" + b"x.lock\n"
        out.append(dt_scenario("invalid: %s on line %d" % (name, len(pre) + 1), I, content))
    out.append(dt_scenario("invalid: CRLF throughout", I, b"# c\r\nmigrations\r\nx.lock\r\n"))
    out.append(dt_scenario("invalid: last line, no final LF", I, b"migrations\nx.lock\na?"))
    out.append(dt_scenario("invalid: two bad lines, the first is named", I, b"ok\n\na?\n/b\n"))
    E = "user list: DT-3's edges (readings)"
    out.append(dt_scenario("edge: a CR in a comment only (READING 8)", E, b"# c\r\nmigrations\n"))
    out.append(dt_scenario("edge: a tab in a comment only (READING 8)", E, b"#\tc\nmigrations\n"))
    out.append(dt_scenario("edge: ? [ \\ in a comment", E, b"#?[\\\nmigrations\n"))
    out.append(dt_scenario("edge: ! not leading", E, b"a!b\nmigrations/!x\n"))
    out.append(dt_scenario("edge: a blank CRLF line", E, b"migrations\n\r\n"))

    L = "user list: DT-4's limits, at and one past"
    pats = lambda n: b"".join(b"p%03d\n" % i for i in range(n))
    out.append(dt_scenario("limit: 256 patterns", L, pats(255) + b"migrations\n"))
    out.append(dt_scenario("limit: 257 patterns", L, pats(256) + b"migrations\n"))
    out.append(dt_scenario("limit: 256 patterns and 300 comments and blanks", L,
                           b"# c\n\n" * 150 + pats(255) + b"migrations\n"))
    out.append(dt_scenario("limit: 256 times the same pattern, and one more", L, b"x.lock\n" * 257))
    pad = lambda total, tail: b"#" + b"c" * (total - len(tail) - 2) + b"\n" + tail
    out.append(dt_scenario("limit: file of 65,536 bytes", L, pad(65536, b"migrations\n")))
    out.append(dt_scenario("limit: file of 65,537 bytes", L, pad(65537, b"migrations\n")))
    out.append(dt_scenario("limit: file of 65,536 bytes, no final LF", L, pad(65536, b"migrations")))
    long_pat = lambda n: (b"migrations/" + b"a/" * ((n - 11) // 2) + b"a" * 3)[:n - 1] + b"z"
    assert len(long_pat(4096)) == 4096 and len(long_pat(4097)) == 4097
    out.append(dt_scenario("limit: a pattern of 4,096 bytes", L, long_pat(4096) + b"\nx.lock\n"))
    out.append(dt_scenario("limit: a pattern of 4,097 bytes", L, long_pat(4097) + b"\nx.lock\n"))
    out.append(dt_scenario("limit: a component of 4,096 bytes", L, b"a" * 4096 + b"\nx.lock\n"))
    out.append(dt_scenario("limit: a comment of 5,000 bytes", L, b"#" + b"c" * 5000 + b"\nx.lock\n"))
    out.append(dt_scenario("limit: four **", L, b"**/sub/**/sub/**/x/**\nsrc/**/**/**/**/b.lock\n"))
    out.append(dt_scenario("limit: five **", L, b"x.lock\n**/sub/**/sub/**/x/**/**\n"))
    out.append(dt_scenario("limit: five ** in a row", L, b"**/**/**/**/**\n"))
    out.append(dt_scenario("limit: four ** and a**b (READING 10)", L, b"**/s**b/**/**/**/x\n"))
    out.append(dt_scenario("limit: four ** and ***", L, b"**/***/**/**/**/x\n"))

    U = "user list: cannot be read"
    out.append(dt_scenario("unreadable: a NUL in a pattern", U, b"migrations\na\x00b\nx.lock\n"))
    out.append(dt_scenario("unreadable: a NUL in a comment only", U, b"# c\x00\nmigrations\n"))
    out.append(dt_scenario("unreadable: a NUL alone on the last line, no final LF", U, b"migrations\n\x00"))
    out.append(dt_scenario("unreadable: a NUL is the whole file", U, b"\x00"))
    t = base_tree()
    t.add(".belay-donttouch", "d")
    t.add(".belay-donttouch/inner", "f")                 # READING 6
    out.append(scenario("unreadable: a directory", U, t))
    t = base_tree()
    t.add("list.txt", "f")
    t.add(".belay-donttouch", "l", "Makefile")
    out.append(scenario("unreadable: a symlink to a file", U, t))
    t = base_tree()
    t.add(".belay-donttouch", "l")
    out.append(scenario("unreadable: a dangling symlink", U, t))

    T = "the top itself (READING 15)"
    for pat in (b"**", b"**/**", b"*", b".*", b"*.", b".**", b"**/.*", b"*/**", b"**/*", b".", b"x/**",
                b"**/x", b"..*", b"*.*"):
        if pat == b".":
            continue                                     # invalid by DT-3; it is among the invalid
        out.append(dt_scenario("the top and the pattern %s" % pat.decode(), T, pat + b"\n"))

    X = "interplay: the user's list, the file itself, the rows"
    t = base_tree()
    t.add("sub/.belay-donttouch", "f")
    t.add(".BELAY-DONTTOUCH", "f")
    t.add(".belay-donttouchx", "f")
    out.append(scenario("the file itself: only at the top, only that name, no file at the top", X, t))
    t = base_tree()
    t.add("sub/.belay-donttouch", "f")
    t.add(".Belay-Donttouch", "f")
    out.append(scenario("the file itself with a valid list", X, t, b"# nothing\n"))
    out.append(dt_scenario("the file itself with an invalid list; the rows still apply", X, b"a?\nmigrations\n"))
    out.append(dt_scenario("the file itself past a limit; the rows still apply", X, b"x.lock\n" * 300))
    t = Tree()
    for p in (".env", ".ENV", "sub/.env", "sub/.ENV", ".git/config", ".GIT/config", ".claude/settings.local.json",
              ".claude/worktrees/w/x", "node_modules/p/.env", "k.pem", "K.PEM", ".git/hooks/pre-commit.sample",
              ".git/hooks/pre-commit", ".husky/_/h", "CODEOWNERS", "codeowners"):
        t.add(p)
    t.add("venv/.env", "d")
    t.add("venv/.env/x", "f")
    out.append(scenario("user first: case, limits and exceptions do not bind the user", X, t,
                        b".env\n**/.env\n.git/config\n.claude/worktrees\n**/*.pem\n**/*.sample\nCODEOWNERS\n"
                        b"node_modules\n.claude/settings.local.json\n"))
    out.append(scenario("the same tree, no list", X, t))
    out.append(scenario("the same tree, the list in another case", X, t,
                        b".ENV\n**/.Env\n.GIT/CONFIG\n.Claude/worktrees\n**/*.PEM\ncodeowners\n"))
    return out


# --------------------------------------------------------------------------- random

VOCAB = [".git", "hooks", "config", "modules", "info", "exclude", "node_modules", "site-packages", ".env",
         ".ENV", ".env.local", "x.pem", "X.PEM", ".claude", "settings.local.json", "settings.json", "worktrees",
         "CLAUDE.md", "claude.md", ".husky", ".vscode", "tasks.json", ".github", "workflows", "CODEOWNERS",
         "src", "a", "b", ".ssh", "id_rsa.pub", "pre-commit", "pre-commit.sample", "x.pth", ".npmrc", ".cargo",
         "config.toml", ".kube", "docs", "Jenkinsfile", ".devcontainer", "lefthook.yml", "a.lock", "With Space",
         ".aws", "attributes", "config.worktree", ".gitmodules", ".mcp.json", ".cursor", "pip.conf", "dependabot.yml",
         "actions", ".circleci", "copilot-instructions.md", ".netrc", "k.key", "AGENTS.md", ".hidden", "Node_Modules"]
SHAPES = [".git/hooks/%s", ".git/%s", ".git/info/%s", ".git/modules/%s/config", ".git/modules/%s/hooks/pre-push",
          ".git/worktrees/%s/config.worktree", ".claude/%s", ".claude/worktrees/%s", ".github/%s",
          ".github/workflows/%s", ".vscode/%s", ".cargo/%s", ".kube/%s", "site-packages/%s", "node_modules/%s",
          "%s", "%s/%s", "%s/%s/%s", "%s/%s/%s/%s", "docs/%s", "src/%s/%s"]
UPATS = ["*", "**", "**/%s", "%s", "%s/**", "%s/*", "*/%s", "**/%s/**", "%s/%s", "**/*.pem", "*.md", "**/.*",
         ".*", "**/%s/*", "%s*", "*%s", "**/config", ".git/**/config", "**/hooks/*", ".claude", "**/*.sample"]


def random_scenarios(n):
    rnd = random.Random(SEED)
    out = []
    for i in range(n):
        t = Tree()
        for _ in range(rnd.randint(15, 45)):
            shape = rnd.choice(SHAPES)
            path = shape % tuple(rnd.choice(VOCAB) for _ in range(shape.count("%s")))
            if rnd.random() < 0.3:
                path = rnd.choice(["sub/", "a/b/", "node_modules/p/", "x/site-packages/", "SUB/"]) + path
            if rnd.random() < 0.08:
                path = path.swapcase()
            t.add(path, rnd.choice("fffffdddl"))
        dt = None
        if i % 3:
            lines = []
            for _ in range(rnd.randint(1, 5)):
                shape = rnd.choice(UPATS)
                lines.append(shape % tuple(rnd.choice(VOCAB) for _ in range(shape.count("%s"))))
            dt = ("\n".join(lines) + "\n").encode()
        cat = "random trees, with a user list" if dt is not None else "random trees, no list"
        out.append(scenario("random %03d" % i, cat, t, dt))
    return out


def scenarios():
    rows, _ = model.parse_pin()
    out = []
    for r in rows:
        out += row_scenarios(r)
    out += table_scenarios(rows)
    out += donttouch_scenarios()
    out += random_scenarios(120)
    names = set()
    for s in out:
        if s["name"] in names:
            raise ValueError("two scenarios named %r" % s["name"])
        names.add(s["name"])
    return out


if __name__ == "__main__":
    scs = scenarios()
    cats = {}
    for s in scs:
        c = cats.setdefault(s["category"], [0, 0])
        c[0] += 1
        c[1] += len(s["tree"])
    for k, (a, b) in cats.items():
        print("%-58s %4d scenarios %6d entries" % (k, a, b))
    print("%d scenarios, %d entries" % (len(scs), sum(len(s["tree"]) for s in scs)))
