#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/io.h>
#include "xmio.h"

#define MAP_SIZE    0x1000UL 
#define MAP_MASK    (MAP_SIZE - 1)

#define MMIO_REGS 65
#define MMIO_SIZE (MMIO_REGS * sizeof(uint32_t))

#define PMIO_ADDR 0
#define PMIO_DATA 4
#define PMIO_REGS STRNG_MMIO_REGS
#define PMIO_SIZE 8

#define PCI_DEVICE "/sys/devices/pci0000:00/0000:00:04.0/resource0" // const char *pci_resource_path

#define leak(label, value) \
    printf("\033[36m%s:\033[0m \033[1;33m0x%lx\033[0m\n", label, (size_t)(value))

int main(int argc, char **argv, char **envp)
{

    return 0;
}

