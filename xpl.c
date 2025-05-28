#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h> 
#include <unistd.h>
#include "xpl_utils.h"

/* Configurations */
#define DEVICE_PATH     "/dev/vulndev"

/* IOCTLs */
#define VULN_IOCTL_READ  _IOR(0x1337, 1, char *)
#define VULN_IOCTL_WRITE _IOW(0x1337, 2, char *)
#define VULN_IOCTL_EXEC  _IO(0x1337, 3)

int open_dev(const char *path, int flags) {
    int fd = open(path, flags);
    if (fd < 0) {
        FAILURE("Failed to open %s: %s", path, strerror(errno));
        DIE("open_dev");
    }

    SUCCESS("Opened device: %s (fd=%d)", path, fd);
    return fd;
}

int main() {
    int fd = open_dev(DEVICE_PATH, O_RDWR);


    close(fd);
    printf("[+] Done\n");
    return 0;
}
