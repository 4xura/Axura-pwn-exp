#include "ret2asm.h"
#include "utils.h"


/* Retrive value from rax */
uintptr_t deref_rax(const char *label)
{
    uintptr_t val;
    __asm__ volatile (
        ".intel_syntax noprefix;"
        "mov %[out], rax;"
        ".att_syntax;"
        : [out] "=r" (val)
        :
        : "memory"
    );
    SUCCESS("Retrive value from rax: 0x%016x for \"%s\"", val, label);
    return val;
}
