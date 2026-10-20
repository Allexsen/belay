# belay build.
#
# Two trees, deliberately separated (BELAY_DESIGN.md §9.1):
#
#   CORE_SRC    portable POSIX C — capture/A, diff/, interp/, util/.
#               MUST build and pass tests on macOS as well as Linux.
#               Linux-only fast paths go behind #ifdef inside these files.
#   SESSION_SRC Linux-only — userns + mountns + overlayfs (M4).
#               Built only when the host is Linux.
#
# `make check` is what CI gates on, on every platform.

CC	?= cc
CFLAGS	?= -O2
WARN	= -Wall -Wextra -std=c11
INC	= -Iinclude -Isrc
BUILD	= build
BIN	= bin/belay

UNAME_S	:= $(shell uname -s)

CORE_SRC	= $(wildcard src/util/*.c src/capture/*.c src/diff/*.c src/interp/*.c)
CORE_OBJ	= $(CORE_SRC:src/%.c=$(BUILD)/%.o)
SAN_CORE_OBJ	= $(CORE_SRC:src/%.c=$(SAN_BUILD)/%.o)
SESSION_SRC	= $(wildcard src/session/*.c)
TOP_SRC		= $(wildcard src/*.c)

# The session engine depends on Linux-only headers (sched.h CLONE_*,
# sys/mount.h, SYS_pivot_root), so it is excluded off Linux. On macOS the
# build produces the portable core only.
ifeq ($(UNAME_S),Linux)
SRC	= $(TOP_SRC) $(CORE_SRC) $(SESSION_SRC)
else
SRC	= $(TOP_SRC) $(CORE_SRC)
endif

OBJ	= $(SRC:src/%.c=$(BUILD)/%.o)

# One binary per test/test_*.c. The harness is header-only, so each test
# links only the units it exercises.
TEST_SRC	= $(wildcard test/test_*.c)
TEST_BIN	= $(TEST_SRC:test/%.c=$(BUILD)/test/%)

# Sanitizer builds (§0.4c). Separate object dir so a sanitized object is
# never linked into the release binary.
SAN_FLAGS	= -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1
SAN_BUILD	= $(BUILD)/san
SAN_TEST_BIN	= $(TEST_SRC:test/%.c=$(SAN_BUILD)/test/%)

.PHONY: all clean test check check-san core platform

all: $(BIN)

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

$(BUILD)/test/%: test/%.c $(CORE_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(WARN) $(INC) -Itest -MMD -MP -o $@ $< $(CORE_OBJ)

$(SAN_BUILD)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(SAN_FLAGS) $(WARN) $(INC) -MMD -MP -c $< -o $@

$(SAN_BUILD)/test/%: test/%.c $(SAN_CORE_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(SAN_FLAGS) $(WARN) $(INC) -Itest -MMD -MP -o $@ $< $(SAN_CORE_OBJ)

test: $(TEST_BIN)
	@fail=0; \
	for t in $(TEST_BIN); do \
		echo "== $$t"; \
		$$t || fail=1; \
	done; \
	exit $$fail

# ASan + UBSan. halt_on_error so a sanitizer report fails the job rather than
# being buried in passing output.
check-san: $(SAN_TEST_BIN)
	@fail=0; \
	for t in $(SAN_TEST_BIN); do \
		echo "== $$t (asan+ubsan)"; \
		ASAN_OPTIONS=detect_leaks=1 \
		UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
		$$t || fail=1; \
	done; \
	exit $$fail

check: all test

bin:
	mkdir -p $@

clean:
	rm -rf $(BUILD) $(BIN)

-include $(shell find $(BUILD) -name '*.d' 2>/dev/null)
