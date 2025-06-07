#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
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

/* Prepare a stackframe before returning from iretq */
void
prepare_iretq_frame(uintptr_t frame[5], iretq_user_ctx ctx)
{
    frame[0] = ctx.rip;
    frame[1] = ctx.cs;
    frame[2] = ctx.rflags;
    frame[3] = ctx.rsp;
    frame[4] = ctx.ss;
}

/* Call iretq to return to user spacea 
 *      Either we pass a global fake stack frame (suggest)
 *      or pass the iretq ctx structure for the required regs
 *          - which may raise clobbers in asm
 * */

/* Passing a global fake stack frame for iretq call */
__attribute__((noreturn))
void ret2user_iretq(void)
{
    __asm__ __volatile__ (
        ".intel_syntax noprefix;"
        "swapgs;"
        /*"lea rsp, g_iretq_frame;"*/
        "lea rsp, g_iretq_frame;"
        "iretq;"
        ".att_syntax;"
    );

    __builtin_unreachable();
}

/* Passing iretq ctx members as arguments */
__attribute__((noreturn))
void _ret2user_iretq(iretq_user_ctx ctx) {
    __asm__ __volatile__ (
        ".intel_syntax noprefix;"
        "swapgs;"
        "mov r15, %[ss]; push r15;"
        "mov r15, %[rsp]; push r15;"
        "mov r15, %[rf]; push r15;"
        "mov r15, %[cs]; push r15;"
        "mov r15, %[rip]; push r15;"
        "iretq;"
        ".att_syntax;"
        :
        : [ss]  "r"(ctx.ss),
          [rsp] "r"(ctx.rsp),
          [rf]  "r"(ctx.rflags),
          [cs]  "r"(ctx.cs),
          [rip] "r"(ctx.rip)
        : "r15", "rax", "rdi", "rsi", "rdx", "rcx"
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
    printf("| SS  (stack segment)  = 0x%04lx              |\n", ctx->ss);
    puts("+--------------------------------------------+\n");
}
