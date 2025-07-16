#pragma once
#include <stdint.h>
#include <stddef.h>

void *get_mmio_base(const char *device_path);
uint32_t mmio_read32(uint64_t offset);
void mmio_write32(uint64_t offset, uint32_t value);
uint64_t mmio_read64(uint64_t offset);
void mmio_write64(uint64_t offset, uint64_t value);
