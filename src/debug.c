#include "debug.h"
#include "utils.h"
#include <stdlib.h>

/* For debugging use on kernel stack return */
void test_user_space_asm(void) {
    __asm__ __volatile__ (
        ".intel_syntax noprefix;\n"
        "int3;\n"
        ".att_syntax;\n"
    );
}

/* 
 * For debugging use to see if user space code can be executed
 *      after bypassing KPTI
 */
void test_user_space_func(void) {
    SUCCESS("[DEBUG] User space function is executed on a return from kernel stack");
    exit(0);
}

