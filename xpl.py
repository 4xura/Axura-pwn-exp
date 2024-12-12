from pwn import *
import inspect


def g(gdbscript=''):
    if mode['local']:
        sysroot = None
        if libc_path != '':
            sysroot = os.path.dirname(libc_path)
        gdb.attach(p, gdbscript=gdbscript, sysroot=sysroot)
        if gdbscript == '':
            raw_input()
    
    elif mode['remote']:
        gdb.attach((remote_ip_addr, remote_port), gdbscript)
        if gdbscript == '':
            raw_input


def pa(addr):
    frame = inspect.currentframe().f_back
    variables = {k: v for k, v in frame.f_locals.items() if v is addr}
    desc = next(iter(variables.keys()), "unknown")
    info('@{} ---> %#x'.format(desc), addr)
    

s       = lambda data                 :p.send(data)
sa      = lambda delim,data           :p.sendafter(delim, data)
sl      = lambda data                 :p.sendline(data)
sla     = lambda delim,data           :p.sendlineafter(delim, data)
r       = lambda num=4096             :p.recv(num)
ru      = lambda delim, drop=True     :p.recvuntil(delim, drop)
l64     = lambda                      :u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
uu64    = lambda data                 :u64(data.ljust(8, b'\0'))


def rol(xor, shift, bit_size):
    """Performs a bitwise left rotate (ROL) on the enc."""
    return ((xor << shift) | (xor >> (bit_size - shift))) & ((1 << bit_size) - 1)

def PTR_MANGLE(ptr, ptr_guard, shift, bit_size):
    xor = ptr ^ ptr_guard
    return rol(xor, shift, bit_size)

def ror(enc, shift, bit_size):
    """Performs a bitwise right rotate (ROR) on the enc."""
    return ((enc >> shift) | (enc << (bit_size - shift))) & ((1 << bit_size) - 1)

def PTR_DEMANGLE(enc, ptr_guard, shift, bit_size):
    var = ror(enc, shift, bit_size)
    return var ^ ptr_guard


def decrypt_fd(enc_fd):
    key = 0
    plain = 0
    for i in range(1, 6):
        bits = 64 - 12 * i
        if bits < 0:
            bits = 0
        plain = ((enc_fd ^ key) >> bits) << bits
        key = plain >> 12
        print(f"Round {i}:")
        print(f"Key:    {key:#016x}")      
        print(f"Plain:  {plain:#016x}")    
        print(f"Cipher: {enc_fd:#016x}\n") 
    return plain


def encrypt_fd(fd, heap_base):
    enc_ptr = fd ^ (heap_base >> 12)
    return enc_ptr


def toBytes(d):
    return str(d).encode()


def ROL(xor, cnt):
    tmp = bin(xor)[2:].rjust(64, '0')
    enc = int(tmp[cnt:] + tmp[:cnt], 2)
    return enc


def menu(choice):
    pass


def add():
    pass


def free():
    pass


def edit():
    pass


def show():
    pass


def exp():

    pause()
    p.interactive()
    
    
if __name__ == '__main__':
    
    file_path = ''
    libc_path = ''
    ld_path   = ''
    
    context(arch='amd64', os='linux', endian='little')
    context.log_level='debug'
    
    e    = ELF(file_path, checksec=False)
    mode = {'local': False, 'remote': False, }
    env  = None
    
    if len(sys.argv) > 1:
        if libc_path != '':
            libc = ELF(libc_path)
        p = remote(sys.argv[1], int(sys.argv[2]))
        mode['remote'] = True
        remote_ip_addr = sys.argv[1]
        remote_port    = int(sys.argv[2])
    else:
        if libc_path != '':
            libc = ELF(libc_path)
            env  = {'LD_PRELOAD': libc_path}
        if ld_path != '':
            cmd = [ld_path, '--library-path', os.path.dirname(os.path.abspath(libc_path)), file_path]
            p   = process(cmd, env=env)
        else:
            p = process(file_path, env=env)
        mode['local'] = True
        
    exp()
