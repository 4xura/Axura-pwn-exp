#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "xmio.h"

/* MMIO */

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

// Read 32-bit value to PMIO
uint32_t pmio_read(uint32_t port) {
    return inl(port);
}

// Write 32-bit value to PMIO
void pmio_write(uint32_t port, uint32_t val) {
    return outl(val, port);
}
