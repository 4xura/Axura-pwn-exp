#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/io.h>

#define leak(sym) \
    printf("[*] Leak %-20s addr: \033[1;33m0x%lx\033[0m\n", #sym, (size_t)(sym))

#define leak64(sym) \
    printf("[*] Leak %-20s addr: \033[1;33m0x%llx\033[0m\n", #sym, (uint64_t)(sym))

#define die(msg)                         \
    do {                                                \
        fprintf(stderr, "\033[31m\033[1m[x] Error: \033[0m%s\n", msg);  \
        perror("");                                     \
        exit(EXIT_FAILURE);                             \
    } while (0)

/* 
 * MMIO 
 */
#define MMIO_REGS   64
#define MMIO_SIZE   (MMIO_REGS * sizeof(uint32_t))

#define MAP_SIZE    0x1000UL 
#define MAP_MASK    (MAP_SIZE - 1)
#define PCI_DEVICE  "/sys/devices/pci0000:00/0000:00:04.0/resource0" 

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
uint32_t mmio_read(uint32_t *addr) {
    return *(volatile uint32_t *)addr;
}

// Write 32-bit value to MMIO
void mmio_write(uint32_t *addr, uint32_t val) {
    *(volatile uint32_t *)addr = val;
}

/* 
 * PMIO 
 */
#define PMIO_ADDR   0
#define PMIO_DATA   4
#define PMIO_REGS   STRNG_MMIO_REGS
#define PMIO_SIZE   8
#define PMIO_PORT   0xc050

// Require CAP_SYS_RAWIO
void setup_pmio(void) {
    if (iopl(3) < 0) {
        perror("failed to change I/O privilege level (need root?)");
        exit(EXIT_FAILURE);
    }
}

// Read 32-bit value to PMIO
uint32_t pmio_read(uint32_t port) {
    return inl(port);
}

// Write 32-bit value to PMIO
void pmio_write(uint32_t port, uint32_t val) {
    outl(val, port);
}

/*
 * Exploit
 */
int main(int argc, char **argv, char **envp)
{
    /*
     * initialization
     */
    void *mmio_base
    mmio_base = get_mmio_base(PCI_DEVICE);  

    setup_pmio();





    return 0;
}

