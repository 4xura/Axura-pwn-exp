CC      = gcc
AR      = ar
CFLAGS ?= -Wall -Wextra -O0 -Iinclude
LDFLAGS ?=

TARGET   ?= xpl
OBJDIR    = obj
LIBDIR    = lib
LIBNAME   = $(LIBDIR)/libxpl.a

ROOT_SRCS := $(wildcard *.c)
SRC_SRCS  := $(wildcard src/*.c)
ROOT_OBJS := $(patsubst %.c,      $(OBJDIR)/%.o, $(notdir $(ROOT_SRCS)))
MOD_OBJS  := $(patsubst src/%.c,  $(OBJDIR)/%.o, $(SRC_SRCS))

all: $(OBJDIR) $(LIBDIR) $(LIBNAME) $(TARGET)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(LIBDIR):
	mkdir -p $(LIBDIR)

# Static library from src/*.c modules
$(LIBNAME): $(MOD_OBJS)
	$(AR) rcs $@ $^

# Link root .o and libxpl.a into the final binary
$(TARGET): $(ROOT_OBJS) $(LIBNAME)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(ROOT_OBJS) $(LIBNAME)

# Compile .c from root/
$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Compile .c from src/
$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

debug:
	$(MAKE) CFLAGS="-Wall -Wextra -O0 -g -DDEBUG -Iinclude" LDFLAGS=

static:
	$(MAKE) CFLAGS="$(CFLAGS)" LDFLAGS="-static"

release:
	$(MAKE) CFLAGS="-Wall -Wextra -O2 -Iinclude" LDFLAGS="-static"

strip:
	strip $(TARGET)

clean:
	rm -rf $(OBJDIR) $(LIBDIR) $(TARGET)

help:
	@echo "Available targets:"
	@echo "  make            - Build the main binary using only needed modules"
	@echo "  make static     - Statically link final binary"
	@echo "  make debug      - With debug symbols, no optimization"
	@echo "  make release    - Optimized static binary"
	@echo "  make strip      - Strip symbol table"
	@echo "  make clean      - Remove build artifacts"

.PHONY: all clean debug static release strip help

