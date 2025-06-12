#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h> 
#include <stddef.h>
#include <fcntl.h>
#include <errno.h>
#include "include/utils.h"
#include "include/rop.h"
#include "include/ret2user.h"

/* Configuration */
#define DEVICE_PATH     "/dev/vulndev"

/* IOCTL Codes */
#define VULN_IOCTL_READ  _IOR(0x1337, 1, char *)
#define VULN_IOCTL_WRITE _IOW(0x1337, 2, char *)
#define VULN_IOCTL_EXEC  _IO(0x1337, 3)

/* Exploit Entry */
int main(void)
{
    int fd = open_dev(DEVICE_PATH, O_RDWR);


    close(fd);
    printf("[✓] Done\n");
    return 0;
}

