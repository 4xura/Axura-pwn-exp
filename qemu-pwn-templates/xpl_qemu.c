#include <stdint.h>
#include <stddef.h>
#include "mmio.h"
#include "minilib.h"

#define PCI_DEVICE "/sys/devices/pci0000:00/0000:00:04.0/resource0"

#define leak(label, value) do { \
    puts(label ": 0x"); puthex((size_t)(value)); puts("\n"); \
} while (0)

void do_main() 
{
    get_mmio_base(PCI_DEVICE);

    // === Exploit logic goes here ===
    // ...
}

void _start() 
{
    size_t env[0];
    environ = (size_t)&env[4];
    do_main();
    syscall64(60, 0); 
}

