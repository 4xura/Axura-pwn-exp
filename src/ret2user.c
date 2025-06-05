#include "ret2user.h"
#include "xpl_utils.h"

/* Save required registers & flags for iretq transition */
struct iretq_user_ctx save_iretq_user_ctx(void (*rip_func)(void))
{
    struct iretq_user_ctx ctx;

    __asm__ volatile(
        ".intel_syntax noprefix;"
        "mov %0, cs;"
        "mov %1, ss;"
        "mov %2, rsp;"
        "pushf;"
        "pop %3;"
        ".att_syntax;"
        : "=r"(ctx.cs), "=r"(ctx.ss), "=r"(ctx.rsp), "=r"(ctx.rflags)
        :
        : "memory"
    );

    ctx.rip = (uintptr_t)rip_func;

    SUCCESS("Saved userland state: cs=0x%lx ss=0x%lx rsp=0x%lx rflags=0x%lx rip=0x%lx",
            ctx.cs, ctx.ss, ctx.rsp, ctx.rflags, ctx.rip);

    return ctx;
}

/* return2user via iretq */
void ret2user_trampoline(struct iretq_user_ctx *ctx)
{
    __asm__ __volatile__ (
        ".intel_syntax noprefix;"
        "swapgs;"
        "mov r15, %0;"
        "push r15;"         // user_ss
        "mov r15, %1;"
        "push r15;"         // user_rsp
        "mov r15, %2;"
        "push r15;"         // user_rflags
        "mov r15, %3;"
        "push r15;"         // user_cs
        "mov r15, %4;"
        "push r15;"         // user_rip
        "iretq;"
        ".att_syntax;"
        :
        : "r"(ctx->ss), "r"(ctx->rsp), "r"(ctx->rflags), "r"(ctx->cs), "r"(ctx->rip)
        : "memory", "r15"
    );
}

