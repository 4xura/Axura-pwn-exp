#ifndef STACK_PIVOT_H
#define STACK_PIVOT_H

#include "rop.h"

/* ============= Stash Fake Stack ============= 
 * When we use gadgets like `mov rsp, ...` or `mov esp, ...`
 *      to pivot stack in kernel space
 *      Mmap a memory region to on where RSP points
 *      Serve it as a fake stack and place ROP chain on it.
 *
 * Mmap with a specified guard page size to
 *      ensure safe stack pivoting in kernel-space exploits. 
 *      The first page is touched to avoid a double fault on lazy page allocation 
 *      (that CPU or kernel touches an unmapped page before the ROP chain is executed
 *      e.g., functions like prepare_kernel_cred() and commit_creds() make calls to other functions inside them, causing the stack to grow).
 *      Write something (COW) to make sure that page is created and accessible
 *
 * Parameters:
 *   pivot_stack_addr - address where the ROP chain should begin
 *   pivot_stack_size - size of usable fake stack (must be page-aligned)
 *   guard_size      - size of preceding memory to be touched/mapped as a guard, usually 0x1000
 *   rop             - pointer to the ROP chain structure to be placed at pivot_stack_addr
 */
void stash_mmap_stack(void *pivot_stack_addr,
                    size_t pivot_stack_size,
                    size_t guard_size,
                    rop_buffer_t *rop); 










#endif  // STACK_PIVOT_H
