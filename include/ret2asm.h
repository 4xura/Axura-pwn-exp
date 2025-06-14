#ifndef RET2ASM_H
#define RET2ASM_H

#include <stdint.h>
#include <stddef.h>

/* Globals */
extern uintptr_t DEREF_VAL;

/* Retrive value from rax and store in TMP_STORE */
uintptr_t deref_rax(const char *label);



#endif  // RET2ASM_H
