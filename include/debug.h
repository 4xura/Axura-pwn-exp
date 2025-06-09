#ifndef DEBUG_H
#define DEBUG_H

/* Debug if the return address on kernel stack 
 *  is successfully hijacked.
 *
 * Success if the int 3 (break) instruction is executed
 *  (Inspect dmsg log output)
*/
void test_ret_addr(void);


#endif  // DEBUG_H
