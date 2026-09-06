CC	= gcc
CFLAGS	= -Wall -Wextra -std=c11 -Isrc -MMD -MP
BIN	= bin/belay
BUILD	= build
SRC	= $(wildcard src/*.c)
OBJ	= $(SRC:src/%.c=$(BUILD)/%.o)

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJ) | bin
	$(CC) -o $@ $(OBJ)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD) bin:
	mkdir -p $@

clean:
	rm -rf $(BUILD) $(BIN)

-include $(OBJ:.o=.d)
