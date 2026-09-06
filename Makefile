CC	= gcc
CFLAGS	= -Wall -Wextra -std=c11 -Isrc -MMD -MP
BIN	= bin/belay
SRC	= $(wildcard src/*.c)
OBJ	= $(SRC:.c=.o)

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJ) | bin
		$(CC) -o $@ $(OBJ)

src/%.o: src/%.c
		$(CC) $(CFLAGS) -c $< -o $@

bin:
	mkdir -p bin

clean:
	rm -f $(OBJ) $(OBJ:.o=.d) $(BIN)

-include $(OBJ:.o=.d)