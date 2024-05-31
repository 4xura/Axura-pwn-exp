from pwn import *


def g(gdbscript=""):
    if mode["local"]:
        sysroot = None
        if libc_path != '':
            sysroot = os.path.dirname(libc_path)
        gdb.attach(p, gdbscript=gdbscript, sysroot=sysroot)
        if gdbscript == "":
            raw_input()
    
    elif mode["remote"]:
        gdb.attach((remote_ip_addr, remote_port), gdbscript)
        if gdbscript == "":
            raw_input


def pa(desc, addr):
    info("@{}--->: %#x".format(desc), addr)
    
 
def exploit():


    
    
    
    
    p.interactive()
    
    
    

if __name__ == '__main__':
    
    file_path = ''
    libc_path = ''
    ld_path   = ''
    
    context(arch="amd64", os="linux", endian="little")
    context.log_level="debug"
    
    e    = ELF(file_path, checksec=False)
    mode = {"local": False, "remote": False, }
    env  = None
    
    if len(sys.argv) > 1:
        if libc_path != '':
            libc = ELF(libc_path)
        p = remote(sys.argv[1], int(sys.argv[2]))
        mode["remote"] = True
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
        mode["local"] = True
        
    exploit()