# belay build.
#
# Two trees, deliberately separated (BELAY_DESIGN.md §9.1):
#
#   CORE_SRC    portable POSIX C — capture/A, diff/, interp/, util/.
#               MUST build and pass tests on macOS as well as Linux.
#               It calls the OS only through the platform adapter
#               (src/capture/fsops.h): src/platform/fsops_posix.c plus the
#               one fsops_<os>.c for this host. No #ifdef in capture.
#   SESSION_SRC Linux-only — userns + mountns + overlayfs (M4).
#               Built only when the host is Linux.
#
# `make check` is what CI gates on, on every platform.

CC	?= cc
CFLAGS	?= -O2
# -Werror for the switch family: a missing case over a schema enum is a build
# failure, not a warning nobody reads (audit 2026-10, R1). Every rule uses
# WARN -- release, sanitizer, fuzz and tool builds alike.
WARN	= -Wall -Wextra -std=c11 -Werror=switch -Werror=switch-enum -Werror=implicit-fallthrough
INC	= -Iinclude -Isrc
BUILD	?= build
BIN	= bin/belay

UNAME_S	:= $(shell uname -s)

ifeq ($(UNAME_S),Linux)
PLATFORM_SRC	= src/platform/fsops_posix.c src/platform/fsops_linux.c
else
PLATFORM_SRC	= src/platform/fsops_posix.c src/platform/fsops_macos.c
endif
CORE_SRC	= $(wildcard src/util/*.c src/schema/*.c src/capture/*.c src/diff/*.c src/interp/*.c) $(PLATFORM_SRC)
CORE_OBJ	= $(CORE_SRC:src/%.c=$(BUILD)/%.o)
SAN_CORE_OBJ	= $(CORE_SRC:src/%.c=$(SAN_BUILD)/%.o)
SESSION_SRC	= $(wildcard src/session/*.c)
TOP_SRC		= $(wildcard src/*.c)
CLI_SRC		= $(wildcard src/cli/*.c)
CLI_OBJ		= $(CLI_SRC:src/%.c=$(BUILD)/%.o) $(BUILD)/utils.o
SAN_CLI_OBJ	= $(CLI_SRC:src/%.c=$(SAN_BUILD)/%.o) $(SAN_BUILD)/utils.o

# The session engine depends on Linux-only headers (sched.h CLONE_*,
# sys/mount.h, SYS_pivot_root), so it is excluded off Linux. On macOS the
# build produces the portable core only.
# The binary is the CLI and the core. The session engine is built on Linux
# but not linked (decision 2026-10-31, Q7: unwired until M4).
SRC	= $(TOP_SRC) $(CLI_SRC) $(CORE_SRC)
OBJ	= $(SRC:src/%.c=$(BUILD)/%.o)
ifeq ($(UNAME_S),Linux)
SESSION_OBJ	= $(SESSION_SRC:src/%.c=$(BUILD)/%.o)
endif

# One binary per test/test_*.c. The harness is header-only, so each test
# links only the units it exercises.
TEST_SRC	= $(wildcard test/test_*.c)

# Race tests (test/test_races.c) inject failures and changes through a
# decorated platform adapter, so they build and run on every platform.
# test_stress.c needs threads.
TEST_BIN	= $(TEST_SRC:test/%.c=$(BUILD)/test/%)

# Sanitizer builds (§0.4c). Separate object dir so a sanitized object is
# never linked into the release binary.
SAN_FLAGS	= -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1
SAN_BUILD	= $(BUILD)/san
SAN_TEST_BIN	= $(TEST_SRC:test/%.c=$(SAN_BUILD)/test/%)

.PHONY: e2e all clean test check check-san fuzz bench platform fs-scenarios gen gen-check measure oracle reference lib lint ci-check

all: $(BIN) $(SESSION_OBJ)

# Prints what this platform will build. Useful in CI logs.
platform:
	@echo "uname -s : $(UNAME_S)"
	@echo "core     : $(words $(CORE_SRC)) file(s)"
	@echo "session  : $(words $(SESSION_SRC)) file(s) $(if $(filter Linux,$(UNAME_S)),(built),(skipped: not Linux))"
	@echo "tests    : $(words $(TEST_SRC)) file(s)"

$(BIN): $(OBJ) | bin
	$(CC) $(CFLAGS) -o $@ $(OBJ)

$(BUILD)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(WARN) $(INC) -MMD -MP -c $< -o $@

# Tests: BELAY_TEST_BIN names the binary for the harness's accounting
# (test/belay_test.h); an unused static function is an error, so a TEST whose
# RUN() line was deleted fails the build instead of silently not running.
TEST_FLAGS	= -Itest -Werror=unused-function -DBELAY_TEST_BIN='"$(notdir $@)"'

$(BUILD)/test/%: test/%.c $(CORE_OBJ) $(CLI_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(WARN) $(INC) $(TEST_FLAGS) -MMD -MP -o $@ $< $(CORE_OBJ) $(CLI_OBJ) $(TEST_LDFLAGS)

# The harness's own failure and accounting paths (scripts/selftest.sh).
SELFTEST_BIN	= $(BUILD)/selftest/must_fail $(BUILD)/selftest/must_pass
$(BUILD)/selftest/%: test/selftest/%.c test/belay_test.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(WARN) $(INC) $(TEST_FLAGS) -o $@ $<

# Every harness links the core through this one archive, built in whatever
# BUILD directory it chooses (a fresh one): nothing links "every .o found".
lib: $(BUILD)/libbelay.a
$(BUILD)/libbelay.a: $(CORE_OBJ)
	@rm -f $@
	ar rcs $@ $(CORE_OBJ)

$(SAN_BUILD)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(SAN_FLAGS) $(WARN) $(INC) -MMD -MP -c $< -o $@

$(SAN_BUILD)/test/%: test/%.c $(SAN_CORE_OBJ) $(SAN_CLI_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(SAN_FLAGS) $(WARN) $(INC) $(TEST_FLAGS) -MMD -MP -o $@ $< $(SAN_CORE_OBJ) $(SAN_CLI_OBJ) $(TEST_LDFLAGS)

$(BUILD)/test/test_stress $(SAN_BUILD)/test/test_stress: TEST_LDFLAGS = -pthread

# mkdir_p lives beside the CLI (src/utils.c), outside the core archive; every
# test links it with the CLI's objects (CLI_OBJ).

# The self-test runs first: if the harness or the runner could not report a
# failure, no test result would mean anything. Accounting (test/accounting/):
# the tests each binary ran, and -- when CI sets BELAY_SKIP_PROFILE -- the
# tests it skipped, must match the lists exactly.
test: $(TEST_BIN) $(SELFTEST_BIN)
	@scripts/selftest.sh $(SELFTEST_BIN)
	@BELAY_ACCOUNTING=test/accounting scripts/run-tests.sh $(TEST_BIN)

# ASan + UBSan. halt_on_error so a sanitizer report fails the job rather than
# being buried in passing output.
check-san: $(SAN_TEST_BIN)
	@ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
	BELAY_ACCOUNTING=test/accounting scripts/run-tests.sh $(SAN_TEST_BIN)

# A bare `return` in a TEST body, or a helper printing "skipped", reports a
# test as passed without checking anything (scripts/lint-tests.py).
lint:
	@python3 scripts/lint-tests.py $(TEST_SRC)

# The CI workflow gates what it claims to (scripts/check-ci.py).
ci-check:
	@python3 scripts/check-ci.py

check: all lint ci-check gen-check measure test e2e

# M1's done criterion, end to end through the real binary, unprivileged
# (scripts/e2e.sh). Part of `check`, so every job running it runs this:
# docker (a non-root user) and macos-portable included.
e2e: $(BIN)
	@sh scripts/e2e.sh $(BIN)

# Generated from the schemas in src/schema/ (entry.c, diff_schema.c): the
# specs' tables and rules -- documentation, a freshness check only. `make gen`
# rewrites them; `make gen-check` (part of `check`) fails when one is stale.
# The fuzz target's invariants are hand-written from test/expect/manifest-v1.md
# instead (audit 2026-10, M4), so nothing that checks the code derives from it.
GEN_TOOL	= $(BUILD)/tools/gen_schema
GEN_SPEC	= docs/spec/manifest-v1.md docs/spec/diff-v1.md

$(GEN_TOOL): tools/gen_schema.c $(CORE_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(WARN) $(INC) -MMD -MP -o $@ $< $(CORE_OBJ)

gen: $(GEN_TOOL)
	for f in $(GEN_SPEC); do $(GEN_TOOL) spec $$f > $$f.tmp && mv $$f.tmp $$f || exit 1; done

gen-check: $(GEN_TOOL)
	@fail=0; \
	for f in $(GEN_SPEC); do \
		$(GEN_TOOL) spec $$f > $$f.gen || fail=1; diff -u $$f $$f.gen || fail=1; rm -f $$f.gen; \
	done; \
	if [ $$fail = 1 ]; then echo "gen-check: generated files are stale; run make gen"; exit 1; fi; \
	echo "gen-check: generated files are current"

# Fuzz targets (§0.4c). libFuzzer needs clang; `make fuzz CC=clang`.
# FUZZ_SECS bounds each target so CI stays fast.
FUZZ_SRC	= $(wildcard test/fuzz/fuzz_*.c)
FUZZ_BIN	= $(FUZZ_SRC:test/fuzz/%.c=$(BUILD)/fuzz/%)
FUZZ_SECS	?= 30

$(BUILD)/fuzz/%: test/fuzz/%.c $(CORE_SRC)
	@mkdir -p $(dir $@)
	$(CC) -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined -g -O1 $(WARN) $(INC) -o $@ $< $(CORE_SRC)

# Baseline timing (§10: measured, never a target). Not part of `check`.
BENCH_SRC	= $(wildcard bench/*.c)
BENCH_BIN	= $(BENCH_SRC:bench/%.c=$(BUILD)/bench/%)

$(BUILD)/bench/%: bench/%.c $(CORE_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(WARN) $(INC) -MMD -MP -o $@ $< $(CORE_OBJ) $(BENCH_LDFLAGS)

$(BUILD)/bench/spike_torn: BENCH_LDFLAGS = -pthread

# Filesystem scenarios (gap b): run by CI on loopback btrfs, FAT and NFS.
FS_SCEN		= $(BUILD)/fs_scenarios
$(FS_SCEN): test/fs/fs_scenarios.c $(CORE_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(WARN) $(INC) -o $@ $< $(CORE_OBJ)
fs-scenarios: $(FS_SCEN)

# The measurement driver (bench/measure/README.md). Built by `check`, so it
# keeps compiling on every platform.
MEASURE		= $(BUILD)/bench/measure
$(MEASURE): bench/measure/measure.c $(CORE_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(WARN) $(INC) -MMD -MP -o $@ $< $(CORE_OBJ)
measure: $(MEASURE)

# The diff core against a naive reference on a generated corpus of manifest
# pairs (scripts/oracle/). ORACLE_BASES scales the corpus (~15 pairs each).
ORACLE_BASES	?= 200
oracle: all
	scripts/oracle/run.sh $(ORACLE_BASES)

# The dpkg and pip interpreters against an independent Python reference on a
# generated corpus (scripts/reference/). The driver sees public headers only.
# REFERENCE_N random cases besides the required cells; REFERENCE_SEED seeds them.
REF_DRIVER	= $(BUILD)/reference/driver
REFERENCE_N	?= 300
REFERENCE_SEED	?= 1
$(REF_DRIVER): scripts/reference/driver.c $(CORE_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(WARN) -Iinclude -o $@ $< $(CORE_OBJ)
reference: $(REF_DRIVER)
	BUILD=$(BUILD) scripts/reference/run.sh $(REFERENCE_N) $(REFERENCE_SEED)

bench: $(BENCH_BIN)
	@echo "built: $(BENCH_BIN)"

# A target's seeds, written from the formats' documentation, are in
# test/fuzz/seeds/<target>/ when it has any; the run's own finds go to a
# scratch corpus, never back into the tree.
fuzz: $(FUZZ_BIN)
	@for f in $(FUZZ_BIN); do \
		n=$$(basename $$f); seeds=test/fuzz/seeds/$$n; corpus=$(BUILD)/fuzz/corpus-$$n; \
		mkdir -p $$corpus; \
		echo "== $$f ($(FUZZ_SECS)s)"; \
		if [ -d $$seeds ]; then set -- $$corpus $$seeds; else set -- $$corpus; fi; \
		$$f -max_total_time=$(FUZZ_SECS) -print_final_stats=1 "$$@" || exit 1; \
	done

bin:
	mkdir -p $@

clean:
	rm -rf $(BUILD) $(BIN)

-include $(shell find $(BUILD) -name '*.d' 2>/dev/null)
