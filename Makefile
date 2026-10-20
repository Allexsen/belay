CC	?= cc
CFLAGS	?= -O2
WARN	= -Wall -Wextra -std=c11
INC	= -Isrc
BIN	= bin/belay
BUILD	= build

SRC	= $(wildcard src/*.c)
OBJ	= $(SRC:src/%.c=$(BUILD)/%.o)

# One binary per test/test_*.c. The harness is header-only, so a test links
# only the units it exercises.
TEST_SRC	= $(wildcard test/test_*.c)
TEST_BIN	= $(TEST_SRC:test/%.c=$(BUILD)/test/%)

.PHONY: all clean test check fmt-check

all: $(BIN)

$(BIN): $(OBJ) | bin
	$(CC) $(CFLAGS) -o $@ $(OBJ)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) $(WARN) $(INC) -MMD -MP -c $< -o $@

# Tests compile against src/ headers and the harness in test/.
$(BUILD)/test/%: test/%.c | $(BUILD)/test
	$(CC) $(CFLAGS) $(WARN) $(INC) -Itest -MMD -MP -o $@ $<

# Builds every test binary, runs each, and fails on the first non-zero exit.
test: $(TEST_BIN)
	@fail=0; \
	for t in $(TEST_BIN); do \
		echo "== $$t"; \
		$$t || fail=1; \
	done; \
	exit $$fail

# What CI gates on: the product builds and the tests pass.
check: all test

$(BUILD) $(BUILD)/test bin:
	mkdir -p $@

clean:
	rm -rf $(BUILD) $(BIN)

-include $(OBJ:.o=.d)
-include $(TEST_BIN:%=%.d)
