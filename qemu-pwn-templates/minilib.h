#pragma once
#include <stdint.h>
#include <stddef.h>

// Extern environment pointer
extern size_t environ;

// Syscall
void syscall64(uint64_t syscall_num, ...);

// Basic I/O
void puts(const char *s);
void puthex(size_t val);
