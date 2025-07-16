#pragma once
#include <stdint.h>

__attribute__((naked))
void syscall64(uint64_t syscall_num, ...) {
    __asm__ volatile (
        ".intel_syntax noprefix\n"
        "mov rax, rdi\n"        // syscall number
        "mov rdi, rsi\n"        // arg1
        "mov rsi, rdx\n"        // arg2
        "mov rdx, rcx\n"        // arg3
        "mov r10, r8\n"         // arg4
        "mov r8,  r9\n"         // arg5
        "mov r9,  [rsp + 8]\n"  // arg6
        "syscall\n"
        "ret\n"
        ".att_syntax prefix\n"
    );
}
