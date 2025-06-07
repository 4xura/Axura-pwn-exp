#include <stdio.h>
#include <stdint.h>
#include "ret2user.h"
#include "utils.h"

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
__attribute__((noreturn))
void _ret2user_trampoline(struct iretq_user_ctx *ctx)
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

    __builtin_unreachable();
}

__attribute__((noreturn))
void ret2user_trampoline(void)
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
        : "r"(g_iretq_user_ctx.ss), "r"(g_iretq_user_ctx.rsp), "r"(g_iretq_user_ctx.rflags), "r"(g_iretq_user_ctx.cs), "r"(g_iretq_user_ctx.rip)
        : "memory", "r15"
    );

    __builtin_unreachable();
}

/* Dump iretq user context as a virtual stack layout */
void dump_iretq_user_ctx(struct iretq_user_ctx *ctx) {
    puts("\n+--------------------------------------------+");
    printf("| RIP (return address)  = 0x%016lx |\n", ctx->rip);
    puts("+--------------------------------------------+");
    printf("| CS  (code segment)    = 0x%04lx             |\n", ctx->cs);
    puts("+--------------------------------------------+");
    printf("| RFLAGS               = 0x%016lx  |\n", ctx->rflags);
    puts("+--------------------------------------------+");
    printf("| RSP (user stack ptr) = 0x%016lx  |\n", ctx->rsp);
    puts("+--------------------------------------------+");
    printf("| SS  (stack segment)  = 0x%04lx               |\n", ctx->ss);
    puts("+--------------------------------------------+\n");
}
