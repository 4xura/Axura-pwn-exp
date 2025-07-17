#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/io.h>
#include "xmio.h"

#define PCI_DEVICE "/sys/devices/pci0000:00/0000:00:04.0/resource0" // const char *pci_resource_path

#define MMIO_REGS 65
#define MMIO_SIZE (MMIO_REGS * sizeof(uint32_t))

#define PMIO_PORT "0xc050"
#define PMIO_ADDR 0
#define PMIO_DATA 4
#define PMIO_REGS STRNG_MMIO_REGS
#define PMIO_SIZE 8

#define leak(label, value) \
    printf("\033[36m%s:\033[0m \033[1;33m0x%lx\033[0m\n", label, (size_t)(value))

#define EE(msg)                         \
    do {                                                \
        fprintf(stderr, "\033[31m\033[1m[x] Error: \033[0m%s\n", msg);  \
        perror("");                                     \
        exit(EXIT_FAILURE);                             \
    } while (0)

int main(int argc, char **argv, char **envp)
{
    uint64_t    mmio_base;
    uint32_t    pmio_port = 0xc050;

    /*
     * initialization
     */
    }
    mmio_base = get_mmio_base(PCI_DEVICE);  

    setup_pmio();





    return 0;
}

