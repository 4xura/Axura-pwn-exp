#pragma once
#include <stdint.h>
#include <stddef.h>

void *get_mmio_base(const char *pci_resource_path);
uint32_t mmio_read(uint32_t *addr);
void mmio_write(uint32_t *addr, uint32_t val);

uint32_t pmio_read(uint32_t port);
void pmio_write(uint32_t port, uint32_t val);
