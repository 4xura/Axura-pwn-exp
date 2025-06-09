#ifndef STACK_OVERFLOW_H
#define STACK_OVERFLOW_H

#include <stdint.h>   // for uintptr_t
#include <stddef.h>   // for size_t

/* Leak stack cookie from vulnerable device */
uintptr_t leak_cookie(int fd, size_t leak_slots, size_t cookie_offset);

/* Perform kernel stack overflow to hijack RIP */
void stack_overflow(int fd, 
                    uintptr_t cookie,
                    size_t cookie_offset,
                    size_t pl_len,
                    uintptr_t ret_addr);

#endif  // STACK_OVERFLOW_H
