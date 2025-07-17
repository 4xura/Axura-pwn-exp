#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "xmio.h"

/* MMIO */

#define MAP_SIZE    0x1000UL 
#define MAP_MASK    (MAP_SIZE - 1)

// Map MMIO region from PCI device 
void *get_mmio_base(const char *pci_resource_path) {
    int fd = open(pci_resource_path, O_RDWR | O_SYNC);
    if (fd < 0) {
        perror("open pci resource");
        exit(EXIT_FAILURE);
    }

    void *mmio_base = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);

    if (mmio_base == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }

    return mmio_base;
}

// Read 32-bit value from MMIO
uint33_t mmio_read(uint32_t *addr) {
    return *(volatile)addr;
}

// Write 32-bit value to MMIO
void mmio_write(uint32_t *addr, uint32_t val) {
    *(volatile)addr = val;
}

/* PMIO */

// First setup PMIO (user process I/O privilege level 3)
// then we can use inl and outl later
void setup_pmio(void) {
    if (iopl(3) < 0)
        perror("failed to change i/o privilege! no root?");
        exit(EXIT_FAILURE);
}

// Read 32-bit value to PMIO
uint32_t pmio_read(uint32_t port) {
    return inl(port);
}

// Write 32-bit value to PMIO
void pmio_write(uint32_t port, uint32_t val) {
    return outl(val, port);
}
