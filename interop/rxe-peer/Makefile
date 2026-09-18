CC ?= cc
CFLAGS ?= -O2 -g
WARNINGS = -std=c11 -Wall -Wextra -Wpedantic -Werror -Wconversion -Wshadow
LDLIBS = -libverbs

.PHONY: all clean sanitize test
all: rxe-peer
rxe-peer: peer.c protocol.h
	$(CC) $(CFLAGS) $(WARNINGS) peer.c -o $@ $(LDFLAGS) $(LDLIBS)
test: rxe-peer
	./rxe-peer --self-test
sanitize:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined" LDFLAGS="-fsanitize=address,undefined"
clean:
	rm -f rxe-peer
