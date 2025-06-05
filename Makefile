CC       = gcc
CFLAGS 	?= -Wall -Wextra -O2 -Iinclude
LDFLAGS ?=

TARGET ?= xpl
BUILD   = build

ROOT_SRCS := $(wildcard *.c)
SRC_SRCS  := $(wildcard src/*.c)
SRCS      := $(ROOT_SRCS) $(SRC_SRCS)

OBJS := $(patsubst %.c,      $(BUILD)/%.o, $(notdir $(ROOT_SRCS))) \
        $(patsubst src/%.c,  $(BUILD)/%.o, $(notdir $(SRC_SRCS)))

all: $(BUILD) $(TARGET)

$(BUILD):
	mkdir -p $(BUILD)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(BUILD)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

debug:
	$(MAKE) CFLAGS="-Wall -Wextra -Og -g -DDEBUG -Iinclude" LDFLAGS=

static:
	$(MAKE) CFLAGS="$(CFLAGS)" LDFLAGS="-static"

release:
	$(MAKE) CFLAGS="-Wall -Wextra -O2 -Iinclude" LDFLAGS="-static"

strip:
	strip $(TARGET)

clean:
	rm -rf $(BUILD) $(TARGET)

help:
	@echo "Available targets:"
	@echo "  make            - Build the default exploit binary"
	@echo "  make static     - Build statically-linked exploit"
	@echo "  make debug      - Build with debug symbols and no optimization"
	@echo "  make release    - Optimized, static binary (no debug info)"
	@echo "  make strip      - Strip symbol table from final binary"
	@echo "  make clean      - Remove build artifacts"

.PHONY: all clean debug static release strip help
