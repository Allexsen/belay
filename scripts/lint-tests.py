#!/usr/bin/env python3
"""Lint for the unit tests (audit 2026-10, R4 / adversarial H3).

Inside a TEST(...) body, `return` is an error unless it comes from SKIP() or
REQUIRE(): a test that returns early reports `ok` without having checked
anything, and when its early-return condition is the bug it guards, it can
never fail. Anywhere in a test file, printing "skipped" is an error too: a
helper that prints it and returns lets its TEST report `ok`; skips go
through SKIP(), which the runner counts.

    lint-tests.py <file.c>...      exit 1 and list every offending line
"""
import re
import sys

TEST_START = re.compile(r'^TEST\((\w+)\)\s*\{')


def strip(src):
    """Comments, string and char literals blanked, newlines kept."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith('/*', i):
            j = src.find('*/', i + 2)
            j = n if j == -1 else j + 2
            out.append(re.sub(r'[^\n]', ' ', src[i:j]))
            i = j
        elif src.startswith('//', i):
            j = src.find('\n', i)
            j = n if j == -1 else j
            out.append(' ' * (j - i))
            i = j
        elif c in '"\'':
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == '\\' else 1
            out.append(c + re.sub(r'[^\n]', ' ', src[i + 1:j]) + c)
            i = j + 1
        else:
            out.append(c)
            i += 1
    return ''.join(out)


def lint(path):
    src = strip(open(path, encoding='utf-8').read())
    lines = src.split('\n')
    bad = []
    i = 0
    while i < len(lines):
        m = TEST_START.match(lines[i])
        if not m:
            i += 1
            continue
        name, depth, j = m.group(1), 0, i
        while j < len(lines):
            depth += lines[j].count('{') - lines[j].count('}')
            for r in re.finditer(r'\breturn\b', lines[j]):
                bad.append('%s:%d: TEST(%s): bare `return` -- use SKIP(reason) or REQUIRE(expr)'
                           % (path, j + 1, name))
            if depth == 0 and j > i or (depth == 0 and '}' in lines[j] and j >= i and '{' in lines[i]
                                            and lines[i].count('{') == lines[i].count('}') and j == i):
                break
            j += 1
        i = j + 1
    raws = open(path, encoding='utf-8').read().split('\n')
    for k, raw in enumerate(raws):
        code = lines[k] if k < len(lines) else ''
        if 'printf' in code and 'skipped' in raw:
            bad.append('%s:%d: prints "skipped" -- use SKIP(reason) in the TEST' % (path, k + 1))
    return bad


def main():
    bad = []
    for p in sys.argv[1:]:
        bad += lint(p)
    for b in bad:
        print(b)
    if bad:
        print('lint-tests: %d bare return(s) in TEST bodies' % len(bad))
        return 1
    print('lint-tests: %d file(s), no bare return in a TEST body' % len(sys.argv[1:]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
