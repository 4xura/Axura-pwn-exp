#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>     // Integer types: uint64_t, int32_t, ...
#include <stddef.h>     // Standard definitions: size_t, NULL, ptrdiff_t, ...
#include <stdio.h>      // Input/output: printf(), fprintf(), perror(), ...
#include <stdlib.h>     // General utilities: exit(), malloc(), free(), ...
#include <string.h>     // Memory functions: memset(), memcpy(), memcmp(), ...
#include <fcntl.h>      // File control: open(), O_RDONLY, O_RDWR, ...
#include <sys/types.h>
#include <unistd.h>     // POSIX API: read(), write(), close(), lseek(), ...
#include <sys/ioctl.h>  // ioctl() system call and macros: _IO, _IOR, _IOW, ...
#include <errno.h>      // Standard error codes and errno handling
#include <inttypes.h>   // Format macros for printing fixed-width types (e.g., PRIu64)

/* Device interaction */
int open_dev(const char *path, int flags);

/* Data manipulation */
void hexdump(const char *label, const void *addr, size_t len); 
uintptr_t deref_rax(const char *label);

/* Self defined functions */
void get_shell(const char *mode);


/* Logging & Debugging */
#define INFO(fmt, ...)      fprintf(stdout, "\033[34m[*] " fmt "\033[0m\n", ##__VA_ARGS__)
#define SUCCESS(fmt, ...)   fprintf(stdout, "\033[32m[+] " fmt "\033[0m\n", ##__VA_ARGS__)
#define FAILURE(fmt, ...)   fprintf(stderr, "\033[31m[-] " fmt "\033[0m\n", ##__VA_ARGS__)
#define PA(sym)             fprintf(stdout, "\033[34m[Addr] %s: %p\033[0m\n", #sym, (void *)(sym))
#define DIE(...) do { \
    fprintf(stderr, "\033[31m[!!] " __VA_ARGS__); \
    fprintf(stderr, "\033[0m\n"); \
    exit(EXIT_FAILURE); \
} while (0)


/* Normalization */
#define __stringify(x) #x
#define stringify(x) __stringify(x)


/* Pointer & Memory Utilities */

// Byte-offset pointer addition and subtraction
#define PTR_ADD(ptr, off) ((void *)((uint8_t *)(ptr) + (off)))
#define PTR_SUB(ptr, off) ((void *)((uint8_t *)(ptr) - (off)))

// Check if pointer is aligned to given byte boundary
#define IS_ALIGNED(ptr, align) (((uintptr_t)(ptr) & ((align)-1)) == 0)

// Align up/down
#define ALIGN_UP(x, a)    (((x) + ((a)-1)) & ~((a)-1))
#define ALIGN_DOWN(x, a)  ((x) & ~((a)-1))

// Calculate byte distance between two pointers
#define DISTANCE(ptr1, ptr2) ((ptrdiff_t)((uint8_t *)(ptr1) - (uint8_t *)(ptr2)))
/* Assertions & Checks */
#define ASSERT(x) do { if (!(x)) { FAILURE("[x] Assert failed: %s", #x); exit(1); } } while (0)
#define IN_RANGE(addr, base, len) \
    ((uintptr_t)(addr) >= (uintptr_t)(base) && (uintptr_t)(addr) < (uintptr_t)(base) + (len))


/* Syscall Helpers */
#define SYSCALL_ERR(name) do { perror(name); exit(errno); } while (0)

#endif // UTILS.H
