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

**Father**: `struct _IO_FILE_plus _IO_list_all`

**Members**: 

- `_IO_file_jumps`: for `stdin`, `stdout`, `stderr`.
- `_IO_wfile_jumps` , `_IO_wfile_jumps_mmap`, `_IO_wfile_jumps_maybe_mmap`:  for wide-character stream).

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

