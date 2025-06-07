#ifndef RET2USER_H
#define RET2USER_H

#include <stdint.h>  

/* ============= 1 =============
 * Return to userland with
 *      iretq
 *
 * Namely, swapgs ... iretq
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
 * */

/* Userland context for iretq */
typedef struct iretq_user_ctx {
    uintptr_t ss;
    uintptr_t rsp;
    uintptr_t rflags;
    uintptr_t cs;
    uintptr_t rip;  // Top of stack frame
} iretq_user_ctx;

extern struct iretq_user_ctx g_iretq_user_ctx;

/* Save userland state for iretq transition */
struct iretq_user_ctx
save_iretq_user_ctx(void (*rip_func)(void));

/* Prepare a stack frame to store
 *      the required values beforre returning to user space
 *      in order
 *
 * The values on this stack frame
 *      will be pushed onto the corresponding registers:
 *      RIP, CS, RFLAGS, RSP, SS
 * */
extern __attribute__((aligned(16))) uintptr_t g_iretq_frame[5];

/* Populate iretq user context into fake stack frame */
void
prepare_iretq_frame(uintptr_t frame[5], iretq_user_ctx ctx);

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
 * But here we use a trick to fake a stackframe,
 *      and pass its address to rsp directly,
 *      to avoid register clobbers in the asm
 * */
void
ret2user_iretq(void) __attribute__((noreturn));  

/* Dump iretq user context like a virtual stack layout */
void
dump_iretq_user_ctx(struct iretq_user_ctx *ctx);

#endif  // RET2USER_H

