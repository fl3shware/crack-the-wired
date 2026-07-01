CC = gcc
CFLAGS = -O2 -s -fno-asynchronous-unwind-tables -fno-ident

all: clean main

main:
	$(CC) $(CFLAGS) main.c -o thewired

clean:
	rm -f thewired
