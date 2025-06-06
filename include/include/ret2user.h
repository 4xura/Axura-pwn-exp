#ifndef RET2USER_H
#define RET2USER_H
#include <stdint.h>  // for uintptr_t

/* Return to userland using iretq */

// Userland context for iretq
struct iretq_user_ctx {
    uintptr_t ss;
    uintptr_t rsp;
    uintptr_t rflags;
    uintptr_t cs;
    uintptr_t rip;
};

// Save userland state for iretq transition
struct iretq_user_ctx save_iretq_user_ctx(void (*rip_func)(void));

// Perform iretq back to userland 
void ret2user_trampoline(struct iretq_user_ctx *ctx) __attribute__((noreturn));

// Dump it like a virtual stack layout 
void dump_iretq_user_ctx(struct iretq_user_ctx *ctx);

/* Optional: ret2user wrapper (for global context use) */
void ret2user(void) __attribute__((noreturn));

#endif  // RET2USER_H

