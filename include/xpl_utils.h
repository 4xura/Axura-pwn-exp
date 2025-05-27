#ifndef XPL_UTILS_H
#define XPL_UTILS_H


#include <stdint.h>     // Integer types: uint64_t, int32_t, ...
#include <stddef.h>     // Standard definitions: size_t, NULL, ptrdiff_t, ...
#include <stdio.h>      // Input/output: printf(), fprintf(), perror(), ...
#include <stdlib.h>     // General utilities: exit(), malloc(), free(), ...
#include <string.h>     // Memory functions: memset(), memcpy(), memcmp(), ...
#include <fcntl.h>      // File control: open(), O_RDONLY, O_RDWR, ...
#include <unistd.h>     // POSIX API: read(), write(), close(), lseek(), ...
#include <sys/ioctl.h>  // ioctl() system call and macros: _IO, _IOR, _IOW, ...
#include <errno.h>      // Standard error codes and errno handling
#include <inttypes.h>   // Format macros for printing fixed-width types (e.g., PRIu64)


/* ===============================
 * Pointer & Memory Utilities
 * =============================== */

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

/* ===============================
 * Logging & Debugging
 * =============================== */

#define INFO(fmt, ...)      fprintf(stderr, "[*] " fmt "\n", ##__VA_ARGS__)
#define FAILURE(fmt, ...)   fprintf(stderr, "[-] " fmt "\n", ##__VA_ARGS__)
#define SUCCESS(fmt, ...)   fprintf(stderr, "[+] " fmt "\n", ##__VA_ARGS__)
#define DIE(msg)            do { perror(msg); exit(EXIT_FAILURE); } while (0)

// Print a hex dump of memory
static inline void hexdump(const char *label, const void *addr, size_t len) {
    const unsigned char *p = (const unsigned char *)addr;
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", p[i]);
        if ((i + 1) % 16 == 0) putchar('\n');
    }
    if (len % 16 != 0) putchar('\n');
}

/* ===============================
 * Assertions & Checks
 * =============================== */

#define ASSERT(x) do { if (!(x)) { FAILURE("[x] Assert failed: %s", #x); exit(1); } } while (0)
#define IN_RANGE(addr, base, len) \
    ((uintptr_t)(addr) >= (uintptr_t)(base) && (uintptr_t)(addr) < (uintptr_t)(base) + (len))

/* ===============================
 * I/O Helpers
 * =============================== */

int open_dev(const char *path, int flags);

/* ===============================
 * Syscall Helpers
 * =============================== */

#define SYSCALL_ERR(name) do { perror(name); exit(errno); } while (0)

#endif // XPL_UTILS.H
