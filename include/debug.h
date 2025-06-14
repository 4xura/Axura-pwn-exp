#ifndef DEBUG_H
#define DEBUG_H

/*
 * Debug if the return address on kernel stack 
 *  is successfully hijacked.
 *
 * Success if the int 3 (break) instruction is executed
 *  (Inspect dmsg log output)
 */
void test_user_space_asm(void);

/*
 * Test a user space function on a kernel stack return
 *      to see if it can be executed
 *      after bypassing KPTI
 *
 * Message will be printed on a success
 */
void test_user_space_func(void);


#endif  // DEBUG_H
