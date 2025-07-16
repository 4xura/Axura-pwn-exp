#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "mmio.h"

#define MAP_SIZE    0x1000UL 
#define MAP_MASK    (MAP_SIZE - 1)

/* Path to MMIO region exposed by the PCI device */
const char *pci_resource_path = "/sys/devices/pci0000:00/0000:00:04.0/resource0";

/* Global MMIO base pointer */
static volatile uint8_t *mmio_base = NULL;

/* Map MMIO region from PCI device */
void *get_mmio_base() {
    int fd = open(pci_resource_path, O_RDWR | O_SYNC);
    if (fd < 0) {
        perror("open pci resource");
        exit(EXIT_FAILURE);
    }

    mmio_base = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);

    if (mmio_base == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }

    return (void *)mmio_base;
}

/* Write 64-bit value to MMIO */
void mmio_write64(uint64_t offset, uint64_t value) {
    if (!mmio_base) {
        fprintf(stderr, "MMIO base not initialized!\n");
        exit(EXIT_FAILURE);
    }
    *((volatile uint64_t *)(mmio_base + offset)) = value;
}

/* Write 32-bit value to MMIO */
void mmio_write32(uint64_t offset, uint32_t value) {
    if (!mmio_base) {
        fprintf(stderr, "MMIO base not initialized!\n");
        exit(EXIT_FAILURE);
    }
    *((volatile uint32_t *)(mmio_base + offset)) = value;
}

/* Read 64-bit value from MMIO */
uint64_t mmio_read64(uint64_t offset) {
    if (!mmio_base) {
        fprintf(stderr, "MMIO base not initialized!\n");
        exit(EXIT_FAILURE);
    }
    return *((volatile uint64_t *)(mmio_base + offset));
}
/* Read 32-bit value from MMIO */
uint32_t mmio_read32(uint64_t offset) {
    if (!mmio_base) {
        fprintf(stderr, "MMIO base not initialized!\n");
        exit(EXIT_FAILURE);
    }
    return *((volatile uint32_t *)(mmio_base + offset));
}


