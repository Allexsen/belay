#!/bin/sh
# Proves the test harness and runner report failure (audit 2026-10, A4, M3, L2).
# `make test` runs this before any real test; if it fails, no test result counts.
#
#   selftest.sh <must_fail binary> <must_pass binary>
set -u
MF=$1 MP=$2
bad=0
die() { echo "selftest: $*"; bad=1; }

# 1. Every assertion kind, REQUIRE and SKIP are reported, and the binary fails.
out=$(env -u BELAY_ACCOUNTING -u BELAY_SKIP_PROFILE "$MF" 2>&1); rc=$?
[ "$rc" -eq 1 ] || die "must_fail exited $rc, not 1"
for t in assert_true_fails assert_false_fails assert_eq_int_fails assert_eq_str_fails \
         require_fails require_msg_fails; do
	printf '%s\n' "$out" | grep -qx "FAIL  $t" || die "must_fail: $t was not reported FAIL"
done
printf '%s\n' "$out" | grep -q '^SKIP  skip_is_reported (self-test)$' || die "must_fail: SKIP not reported"
printf '%s\n' "$out" | grep -q '^7 run, 6 failed, 1 skipped$' || die "must_fail: wrong summary"

# 2. The runner aggregates a failing binary as a failure.
scripts/run-tests.sh "$MF" >/dev/null 2>&1 && die "run-tests.sh reported success for must_fail"

# 3. Accounting: right lists pass; each kind of wrong list fails.
T=$(mktemp -d "${TMPDIR:-/tmp}/belay_selftest.XXXXXX")
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/tests" "$T/skips"
acct() {    # acct <tests list> <skips list> -> exit status of must_pass under them
	printf '%b' "$1" > "$T/tests/must_pass.txt"
	printf '%b' "$2" > "$T/skips/selftest.txt"
	BELAY_ACCOUNTING="$T" BELAY_SKIP_PROFILE=selftest "$MP" >/dev/null 2>&1
}
acct 'passes\nskips\n' 'must_pass skips\n'            || die "accounting rejected correct lists"
acct 'passes\n' 'must_pass skips\n'                   && die "accounting missed a test absent from the list"
acct 'passes\nskips\nvanished\n' 'must_pass skips\n'  && die "accounting missed a listed test that did not run"
acct 'passes\nskips\n' ''                             && die "accounting missed an undeclared skip"
acct 'passes\nskips\n' 'must_pass skips\nmust_pass passes\n' && die "accounting missed a declared skip that ran"

[ "$bad" -eq 0 ] && echo "selftest: harness, runner and accounting report failures"
exit $bad
