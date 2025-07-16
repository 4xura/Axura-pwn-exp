CC = gcc
CFLAGS = -nostdlib -static -Iminilib

OBJS = exploit.o mmio.o syscall64.o puts.o puthex.o

all: exploit

exploit: $(OBJS)
	$(CC) -o xpl $(OBJS)

clean:
	rm -f *.o *.o xpl
