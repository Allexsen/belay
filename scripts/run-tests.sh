#!/bin/sh
# Runs test binaries; exits 1 if any of them failed (an assertion, a crash, or
# the accounting in test/belay_test.h). The one place `make test` and
# `make check-san` aggregate results, so scripts/selftest.sh can prove it
# reports a failing binary as failed (audit 2026-10, A4).
#
#   run-tests.sh <test binary>...
fail=0
for t in "$@"; do
	echo "== $t"
	"$t" || fail=1
done
exit $fail
