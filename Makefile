CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g -Iinclude
TARGET  = exploit

SRCS    = $(wildcard *.c)
OBJS    = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@

static:
	$(MAKE) LDFLAGS=-static

debug:
	$(MAKE) CFLAGS="-Wall -Wextra -Og -g3 -Iinclude -DDEBUG"

clean:
	rm -f $(TARGET) *.o

help:
	@echo "Available targets:"
	@echo "  make            - Build the default exploit binary"
	@echo "  make static     - Build statically-linked exploit"
	@echo "  make debug      - Build with -DDEBUG and no optimization"
	@echo "  make clean      - Remove build artifacts"

.PHONY: all clean
