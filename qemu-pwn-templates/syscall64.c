#pragma once
#include <stdint.h>

__attribute__((naked))
void syscall64(uint64_t syscall_num, ...) {
    __asm__ volatile (
        "movq %rdi, %rax\n"
        "movq %rsi, %rdi\n"
        "movq %rdx, %rsi\n"
        "movq %rcx, %rdx\n"
        "movq %r8,  %r10\n"
        "movq %r9,  %r8\n"
        "movq 8(%rsp), %r9\n"
        "syscall\n"
        "ret\n"
    );
}
