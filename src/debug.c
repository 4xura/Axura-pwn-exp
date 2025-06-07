#include "debug.h"

/* For debugging use */
void test_ret_addr(void) {
    __asm__ __volatile__ (
        ".intel_syntax noprefix;\n"
        "int3;\n"
        ".att_syntax;\n"
    );
}

