CC = gcc

CFLAGS = -Wall -Werror -w -std=c11 -march=native -O3

BIN = hashmap

SRC = src/main.c              \
      lib/hash.c              \
	  lib/hashmap.c

OBJS = src/main.o             \
	   lib/hash.o             \
	   lib/hashmap.o

.SUFFIXES: .o .c

$(BIN): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o $(BIN)

.c.o:
	$(CC) -Iinclude -c $< -o $@ $(CFLAGS)


run: $(BIN)
	@$(MAKE) && ./$(BIN)

clean:
	rm -f $(OBJS) $(BIN)
