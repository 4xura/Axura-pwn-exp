[toc]

**Arch**: amd64



## (struct _IO_FILE_plus *) _IO_list_all

**Children**: 

- `FILE file` (aka `struct _IO_FILE`)
- `struct _IO_jump_t *vtable`

```c
struct _IO_FILE_plus {
    struct _IO_FILE {                    // Offset: 0x00, Size: 0xD8 (216 bytes)
        int _flags;                      // Offset: 0x00, Size: 0x04
        char *_IO_read_ptr;              // Offset: 0x08, Size: 0x08
        char *_IO_read_end;              // Offset: 0x10, Size: 0x08
        char *_IO_read_base;             // Offset: 0x18, Size: 0x08
        char *_IO_write_base;            // Offset: 0x20, Size: 0x08
        char *_IO_write_ptr;             // Offset: 0x28, Size: 0x08
        char *_IO_write_end;             // Offset: 0x30, Size: 0x08
        char *_IO_buf_base;              // Offset: 0x38, Size: 0x08
        char *_IO_buf_end;               // Offset: 0x40, Size: 0x08
        char *_IO_save_base;             // Offset: 0x48, Size: 0x08
        char *_IO_backup_base;           // Offset: 0x50, Size: 0x08
        char *_IO_save_end;              // Offset: 0x58, Size: 0x08
        struct _IO_marker *_markers;     // Offset: 0x60, Size: 0x08
        struct _IO_FILE *_chain;         // Offset: 0x68, Size: 0x08
        int _fileno;                     // Offset: 0x70, Size: 0x04
        int _flags2;                     // Offset: 0x74, Size: 0x04
        __off_t _old_offset;             // Offset: 0x78, Size: 0x08
        unsigned short _cur_column;      // Offset: 0x80, Size: 0x02
        signed char _vtable_offset;      // Offset: 0x82, Size: 0x01
        char _shortbuf[1];               // Offset: 0x83, Size: 0x01
        /* Hole: 4 bytes */              // Offset: 0x84 (4-byte padding)
        _IO_lock_t *_lock;               // Offset: 0x88, Size: 0x08
        __off64_t _offset;               // Offset: 0x90, Size: 0x08
        struct _IO_codecvt *_codecvt;    // Offset: 0x98, Size: 0x08
        struct _IO_wide_data *_wide_data;    // Offset: 0xA0, Size: 0x08
        struct _IO_FILE *_freeres_list;  // Offset: 0xA8, Size: 0x08
        void *_freeres_buf;              // Offset: 0xB0, Size: 0x08
        size_t __pad5;                   // Offset: 0xB8, Size: 0x08
        int _mode;                       // Offset: 0xC0, Size: 0x04
        char _unused2[20];               // Offset: 0xC4, Size: 0x14
    } file;
    const struct _IO_jump_t *vtable;     // Offset: 0xD8, Size: 0x08
    /* Total size: 0xE0 (224 bytes) */
};
```

### struct _IO_FILE

**Father**: `struct _IO_FILE_plus _IO_list_all`

**Members**: 

- `file`
- `struct _IO_wide_data _wide_data`
- `struct _IO_FILE *_chain`

```c
struct _IO_FILE {                    // Offset: 0x00, Size: 0xD8 (216 bytes)
    int _flags;                      // Offset: 0x00, Size: 0x04
    char *_IO_read_ptr;              // Offset: 0x08, Size: 0x08
    char *_IO_read_end;              // Offset: 0x10, Size: 0x08
    char *_IO_read_base;             // Offset: 0x18, Size: 0x08
    char *_IO_write_base;            // Offset: 0x20, Size: 0x08
    char *_IO_write_ptr;             // Offset: 0x28, Size: 0x08
    char *_IO_write_end;             // Offset: 0x30, Size: 0x08
    char *_IO_buf_base;              // Offset: 0x38, Size: 0x08
    char *_IO_buf_end;               // Offset: 0x40, Size: 0x08
    char *_IO_save_base;             // Offset: 0x48, Size: 0x08
    char *_IO_backup_base;           // Offset: 0x50, Size: 0x08
    char *_IO_save_end;              // Offset: 0x58, Size: 0x08
    struct _IO_marker *_markers;     // Offset: 0x60, Size: 0x08
    struct _IO_FILE *_chain;         // Offset: 0x68, Size: 0x08
    int _fileno;                     // Offset: 0x70, Size: 0x04
    int _flags2;                     // Offset: 0x74, Size: 0x04
    __off_t _old_offset;             // Offset: 0x78, Size: 0x08
    unsigned short _cur_column;      // Offset: 0x80, Size: 0x02
    signed char _vtable_offset;      // Offset: 0x82, Size: 0x01
    char _shortbuf[1];               // Offset: 0x83, Size: 0x01
    /* Hole: 4 bytes */              // Offset: 0x84 (4-byte padding)
    _IO_lock_t *_lock;               // Offset: 0x88, Size: 0x08
    __off64_t _offset;               // Offset: 0x90, Size: 0x08
    struct _IO_codecvt *_codecvt;    // Offset: 0x98, Size: 0x08
    struct _IO_wide_data *_wide_data;    // Offset: 0xA0, Size: 0x08
    struct _IO_FILE *_freeres_list;  // Offset: 0xA8, Size: 0x08
    void *_freeres_buf;              // Offset: 0xB0, Size: 0x08
    size_t __pad5;                   // Offset: 0xB8, Size: 0x08
    int _mode;                       // Offset: 0xC0, Size: 0x04
    char _unused2[20];               // Offset: 0xC4, Size: 0x14
} file;
```

#### (struct \_IO_wide_data *) _wide_data

There's **NO `_flag`** field in this struct compared to `FILE` struct, and the offset of vtable is different.

**Father**: `FILE file` (aka `struct _IO_FILE`)

```c
struct _IO_wide_data {
    wchar_t *_IO_read_ptr;       // Offset: 0x00, Size: 0x08
    wchar_t *_IO_read_end;       // Offset: 0x08, Size: 0x08
    wchar_t *_IO_read_base;      // Offset: 0x10, Size: 0x08
    wchar_t *_IO_write_base;     // Offset: 0x18, Size: 0x08
    wchar_t *_IO_write_ptr;      // Offset: 0x20, Size: 0x08
    wchar_t *_IO_write_end;      // Offset: 0x28, Size: 0x08
    wchar_t *_IO_buf_base;       // Offset: 0x30, Size: 0x08
    wchar_t *_IO_buf_end;        // Offset: 0x38, Size: 0x08
    wchar_t *_IO_save_base;      // Offset: 0x40, Size: 0x08
    wchar_t *_IO_backup_base;    // Offset: 0x48, Size: 0x08
    wchar_t *_IO_save_end;       // Offset: 0x50, Size: 0x08
    __mbstate_t _IO_state;       // Offset: 0x58, Size: 0x08
    __mbstate_t _IO_last_state;  // Offset: 0x60, Size: 0x08
    struct _IO_codecvt {         // Offset: 0x68, Size: 0x70 (112 bytes)
        _IO_iconv_t __cd_in;     // Offset: 0x68, Size: 0x38 (56 bytes)
        _IO_iconv_t __cd_out;    // Offset: 0xA0, Size: 0x38 (56 bytes)
    } _codecvt;                  // Total size: 0x70 (112 bytes)
    wchar_t _shortbuf[1];        // Offset: 0xD8, Size: 0x04
    /* Hole: 4 bytes */          // Offset: 0xDC (4-byte padding)
    const struct _IO_jump_t *_wide_vtable;  // Offset: 0xE0, Size: 0x08
    /* Total size: 0xE8 (232 bytes) */
};
```

##### (struct _IO_jump_t *) _wide_vtable

**Father**: `(struct _IO_wide_data *) _wide_data`

```c
struct _IO_jump_t {
    size_t __dummy;              // Offset: 0x00, Size: 0x08
    size_t __dummy2;             // Offset: 0x08, Size: 0x08
    _IO_finish_t __finish;       // Offset: 0x10, Size: 0x08
    _IO_overflow_t __overflow;   // Offset: 0x18, Size: 0x08
    _IO_underflow_t __underflow; // Offset: 0x20, Size: 0x08
    _IO_underflow_t __uflow;     // Offset: 0x28, Size: 0x08
    _IO_pbackfail_t __pbackfail; // Offset: 0x30, Size: 0x08
    _IO_xsputn_t __xsputn;       // Offset: 0x38, Size: 0x08
    _IO_xsgetn_t __xsgetn;       // Offset: 0x40, Size: 0x08
    _IO_seekoff_t __seekoff;     // Offset: 0x48, Size: 0x08
    _IO_seekpos_t __seekpos;     // Offset: 0x50, Size: 0x08
    _IO_setbuf_t __setbuf;       // Offset: 0x58, Size: 0x08
    _IO_sync_t __sync;           // Offset: 0x60, Size: 0x08
    _IO_doallocate_t __doallocate; // Offset: 0x68, Size: 0x08
    _IO_read_t __read;           // Offset: 0x70, Size: 0x08
    _IO_write_t __write;         // Offset: 0x78, Size: 0x08
    _IO_seek_t __seek;           // Offset: 0x80, Size: 0x08
    _IO_close_t __close;         // Offset: 0x88, Size: 0x08
    _IO_stat_t __stat;           // Offset: 0x90, Size: 0x08
    _IO_showmanyc_t __showmanyc; // Offset: 0x98, Size: 0x08
    _IO_imbue_t __imbue;         // Offset: 0xA0, Size: 0x08
};
```

### (struct _IO_jump_t *) vtable

**Father**: `(struct _IO_FILE_plus *) _IO_list_all`

**Members**: 

- `_IO_file_jumps`: for `stdin`, `stdout`, `stderr`.
- `_IO_wfile_jumps` , `_IO_wfile_jumps_mmap`, `_IO_wfile_jumps_maybe_mmap`:  for wide-character stream).
- `_IO_cookie_jumps`: for use in House of Emma.

```c
struct _IO_jump_t {
    size_t __dummy;              // Offset: 0x00, Size: 0x08
    size_t __dummy2;             // Offset: 0x08, Size: 0x08
    _IO_finish_t __finish;       // Offset: 0x10, Size: 0x08
    _IO_overflow_t __overflow;   // Offset: 0x18, Size: 0x08
    _IO_underflow_t __underflow; // Offset: 0x20, Size: 0x08
    _IO_underflow_t __uflow;     // Offset: 0x28, Size: 0x08
    _IO_pbackfail_t __pbackfail; // Offset: 0x30, Size: 0x08
    _IO_xsputn_t __xsputn;       // Offset: 0x38, Size: 0x08
    _IO_xsgetn_t __xsgetn;       // Offset: 0x40, Size: 0x08
    _IO_seekoff_t __seekoff;     // Offset: 0x48, Size: 0x08
    _IO_seekpos_t __seekpos;     // Offset: 0x50, Size: 0x08
    _IO_setbuf_t __setbuf;       // Offset: 0x58, Size: 0x08
    _IO_sync_t __sync;           // Offset: 0x60, Size: 0x08
    _IO_doallocate_t __doallocate; // Offset: 0x68, Size: 0x08
    _IO_read_t __read;           // Offset: 0x70, Size: 0x08
    _IO_write_t __write;         // Offset: 0x78, Size: 0x08
    _IO_seek_t __seek;           // Offset: 0x80, Size: 0x08
    _IO_close_t __close;         // Offset: 0x88, Size: 0x08
    _IO_stat_t __stat;           // Offset: 0x90, Size: 0x08
    _IO_showmanyc_t __showmanyc; // Offset: 0x98, Size: 0x08
    _IO_imbue_t __imbue;         // Offset: 0xA0, Size: 0x08
};
```

#### (struct _IO_jump_t  _IO_wfile_jumps *) vtable

This particular vtable is named `_IO_wfile_jumps` and uses the struct `_IO_jump_t`. The function pointers inside are initialized via the `JUMP_INIT` macro, and each corresponds to a specific operation in the vtable.

```c
const struct _IO_jump_t _IO_wfile_jumps libio_vtable = {
  JUMP_INIT_DUMMY,                                    // Offset: 0x00, Size: 0x10 (Dummy entry)
  JUMP_INIT(finish, _IO_new_file_finish),             // Offset: 0x10, Size: 0x08
  JUMP_INIT(overflow, (_IO_overflow_t) _IO_wfile_overflow), // Offset: 0x18, Size: 0x08
  JUMP_INIT(underflow, (_IO_underflow_t) _IO_wfile_underflow), // Offset: 0x20, Size: 0x08
  JUMP_INIT(uflow, (_IO_underflow_t) _IO_wdefault_uflow), // Offset: 0x28, Size: 0x08
  JUMP_INIT(pbackfail, (_IO_pbackfail_t) _IO_wdefault_pbackfail), // Offset: 0x30, Size: 0x08
  JUMP_INIT(xsputn, _IO_wfile_xsputn),                // Offset: 0x38, Size: 0x08
  JUMP_INIT(xsgetn, _IO_file_xsgetn),                 // Offset: 0x40, Size: 0x08
  JUMP_INIT(seekoff, _IO_wfile_seekoff),              // Offset: 0x48, Size: 0x08
  JUMP_INIT(seekpos, _IO_default_seekpos),            // Offset: 0x50, Size: 0x08
  JUMP_INIT(setbuf, _IO_new_file_setbuf),             // Offset: 0x58, Size: 0x08
  JUMP_INIT(sync, (_IO_sync_t) _IO_wfile_sync),       // Offset: 0x60, Size: 0x08
  JUMP_INIT(doallocate, _IO_wfile_doallocate),        // Offset: 0x68, Size: 0x08
  JUMP_INIT(read, _IO_file_read),                     // Offset: 0x70, Size: 0x08
  JUMP_INIT(write, _IO_new_file_write),               // Offset: 0x78, Size: 0x08
  JUMP_INIT(seek, _IO_file_seek),                     // Offset: 0x80, Size: 0x08
  JUMP_INIT(close, _IO_file_close),                   // Offset: 0x88, Size: 0x08
  JUMP_INIT(stat, _IO_file_stat),                     // Offset: 0x90, Size: 0x08
  JUMP_INIT(showmanyc, _IO_default_showmanyc),        // Offset: 0x98, Size: 0x08
  JUMP_INIT(imbue, _IO_default_imbue)                 // Offset: 0xA0, Size: 0x08
};
```

#### (struct _IO_jump_t  _IO_cookie_jumps *) vtable

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



## struct _IO_cookie_file

This structure is a special case of `_IO_FILE` designed to hold user-defined I/O operations. Normally, it is used when `fopencookie` is called to create a custom I/O stream with user-specified read, write, seek, and close operations. It is part of the extension to `_IO_FILE` to support the **cookie I/O** mechanism.

**Ext**: It's an extent of `struct _IO_FILE_plus`

```c
struct _IO_cookie_file {
    struct _IO_FILE_plus {                  // Offset: 0x00, Size: 0xE0 (224 bytes)
        struct FILE {                       // Offset: 0x00, Size: 0xD8 (216 bytes)
            /* file structure details */
        } file;
        const struct _IO_jump_t *vtable;    // Offset: 0xD8, Size: 0x08
    } __fp;
    void *__cookie;                         // Offset: 0xE0, Size: 0x08
    cookie_io_functions_t __io_functions;   // Offset: 0xE8, Size: 0x20
    /* Total size: 0x108 (264 bytes) */
};
```

### (struct cookie_io_functions_t *)  __io_functions

In the `_IO_cookie_file` structure, the actual function pointers of `__io_functions` start at offset `0xE8` and have a total size of `0x20` bytes (32 bytes). This means these function pointers are at offset 0xE8, 0xF0, 0xF8, 0x100, for functions related to `read`, `write`, `seek`, and `close` respectively.

**Father**: `(struct _IO_cookie_file *) fp`

```c
type = struct _IO_cookie_io_functions_t {
    cookie_read_function_t *read;		// Offset: 0x00, 0xE8 in _IO_cookie_file 
    cookie_write_function_t *write;		// Offset: 0x08, 0xF0 in _IO_cookie_file 
    cookie_seek_function_t *seek;		// Offset: 0x10, 0xF8 in _IO_cookie_file 
    cookie_close_function_t *close;		// Offset: 0x18, 0x100 in _IO_cookie_file 
}
```













