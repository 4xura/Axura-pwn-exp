import sys
import inspect
from pwn import *


s       = lambda data                 :p.send(data)
sa      = lambda delim,data           :p.sendafter(delim, data)
sl      = lambda data                 :p.sendline(data)
sla     = lambda delim,data           :p.sendlineafter(delim, data)
r       = lambda num=4096             :p.recv(num)
ru      = lambda delim, drop=True     :p.recvuntil(delim, drop)
l64     = lambda                      :u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
uu64    = lambda data                 :u64(data.ljust(8, b"\0"))


def g(gdbscript: str = ""):
    if mode["local"]:
        gdb.attach(p, gdbscript=gdbscript)

    elif mode["remote"]:
        gdb.attach((remote_ip_addr, remote_port), gdbscript)
        if gdbscript == "":
            raw_input()


def pa(addr: int) -> None:
    frame = inspect.currentframe().f_back
    variables = {k: v for k, v in frame.f_locals.items() if v is addr}
    desc = next(iter(variables.keys()), "unknown")
    success(f"[LEAK] {desc} ---> {addr:#x}")


class ROPGadgets:
    def __init__(self, libc: ELF, libc_base: int): 
        self.rop = ROP(libc)
        self.addr = lambda x: libc_base + self.rop.find_gadget(x)[0] if self.rop.find_gadget(x) else None

        self.ggs = {
            'p_rdi_r'       : self.addr(['pop rdi', 'ret']),
            'p_rsi_r'       : self.addr(['pop rsi', 'ret']),
            'p_rdx_rbx_r'   : self.addr(['pop rdx', 'pop rbx', 'ret']),
            'p_rax_r'       : self.addr(['pop rax', 'ret']),
            'p_rsp_r'       : self.addr(['pop rsp', 'ret']),
            'leave_r'       : self.addr(['leave', 'ret']),
            'ret'           : self.addr(['ret']),
            'syscall_r'     : self.addr(['syscall', 'ret']),
        }

    def __getitem__(self, k: str) -> int:
        return self.ggs.get(k)


class PointerGuard:
    def __init__(self, guard: int, shift: int = 0x11, bit_size: int = 64):
        self.guard = guard
        self.shift = shift
        self.bits = bit_size
        self.mask = (1 << bit_size) - 1

    def rol(self, val: int) -> int:
        return ((val << self.shift) | (val >> (self.bits - self.shift))) & self.mask

    def ror(self, val: int) -> int:
        return ((val >> self.shift) | (val << (self.bits - self.shift))) & self.mask

    def mangle(self, ptr: int) -> int:
        return self.rol(ptr ^ self.guard)

    def demangle(self, mangled: int) -> int:
        return self.ror(mangled) ^ self.guard


class SafeLinking:
    def __init__(self, heap_base: int):
        self.heap_base = heap_base

    def encrypt(self, fd: int) -> int:
        return fd ^ (self.heap_base >> 12)

    def decrypt(self, enc_fd: int) -> int:
        key = 0
        plain = 0
        for i in range(1, 6):
            bits = 64 - 12 * i
            if bits < 0:
                bits = 0
            plain = ((enc_fd ^ key) >> bits) << bits
            key = plain >> 12
        return plain


def itoa(a: int) -> bytes:
    return str(a).encode()


def menu(n: int):
    opt = itoa(n)
    pass


def add():
    pass


def free():
    pass


def edit():
    pass


def show():
    pass


def xpl():


    pause()
    p.interactive()


if __name__ == '__main__':

    FILE_PATH = ""
    LIBC_PATH = ""

    context(arch="amd64", os="linux", endian="little")
    context.log_level = "debug"
    context.terminal  = ['tmux', 'splitw', '-h']    # ['<terminal_emulator>', '-e', ...]

    e    = ELF(FILE_PATH, checksec=False)
    mode = {"local": False, "remote": False, }
    env  = None

    print("Usage: python3 xpl.py [<ip> <port>]\n"
                "  - If no arguments are provided, runs in local mode (default).\n"
                "  - Provide <ip> and <port> to target a remote host.\n")

    if len(sys.argv) == 3:
        if LIBC_PATH:
            libc = ELF(LIBC_PATH)
        p = remote(sys.argv[1], int(sys.argv[2]))
        mode["remote"] = True
        remote_ip_addr = sys.argv[1]
        remote_port    = int(sys.argv[2])

    elif len(sys.argv) == 1:
        if LIBC_PATH:
            libc = ELF(LIBC_PATH)
            env = {
                "LD_PRELOAD": os.path.abspath(LIBC_PATH),
                "LD_LIBRARY_PATH": os.path.dirname(os.path.abspath(LIBC_PATH))
            }
        p   = process(FILE_PATH, env=env)
        mode["local"] = True
    else:
        print("[-] Error: Invalid arguments provided.")
        sys.exit(1)

    xpl()
