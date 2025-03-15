# ----------------- INTEGER TO ANY -----------------
def int_to_hex(n: int) -> str:
    return hex(n)

def int_to_bin(n: int) -> str:
    return bin(n)

def int_to_oct(n: int) -> str:
    return oct(n)

def int_to_bytes(n: int, length: int = 4) -> bytes:
    return n.to_bytes(length, 'little')

def int_to_str(n: int, length: int = 4) -> str:
    return n.to_bytes(length, 'little').decode(errors='ignore')

# ----------------- ANY TO INTEGER -----------------
def hex_to_int(h: str) -> int:
    return int(h, 16)

def bin_to_int(b: str) -> int:
    return int(b, 2)

def oct_to_int(o: str) -> int:
    return int(o, 8)

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'little')

def str_to_int(s: str) -> int:
    return int.from_bytes(s.encode(), 'little')

# ----------------- BYTES TO ANY -----------------
def bytes_to_str(b: bytes) -> str:
    return b.decode()

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'little')

def bytes_to_hex(b: bytes) -> str:
    return b.hex()

def bytes_to_bin(b: bytes) -> str:
    return bin(int.from_bytes(b, 'big'))

# ----------------- ANY TO BYTES -----------------
def str_to_bytes(s: str) -> bytes:
    return s.encode()

def int_to_bytes(n: int, length: int = 4) -> bytes:
    return n.to_bytes(length, 'little')

def hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h.lstrip("0x"))

def bin_to_bytes(b: str) -> bytes:
    return int(b, 2).to_bytes((len(b) + 7) // 8, 'big')

# ----------------- STRING TO ANY -----------------
def str_to_bytes(s: str) -> bytes:
    return s.encode()

def str_to_int(s: str) -> int:
    return int.from_bytes(s.encode(), 'little')

# ----------------- ANY TO STRING -----------------
def bytes_to_str(b: bytes) -> str:
    return b.decode()

def int_to_str(n: int, length: int = 4) -> str:
    return n.to_bytes(length, 'little').decode(errors='ignore')

# ----------------- BINARY TO ANY -----------------
def bin_to_int(b: str) -> int:
    return int(b, 2)

def bin_to_bytes(b: str) -> bytes:
    return int(b, 2).to_bytes((len(b) + 7) // 8, 'big')

# ----------------- ANY TO BINARY -----------------
def int_to_bin(n: int) -> str:
    return bin(n)

def bytes_to_bin(b: bytes) -> str:
    return bin(int.from_bytes(b, 'big'))

# ----------------- EXAMPLE USAGE -----------------
if __name__ == "__main__":
    print("Integer to Hex:", int_to_hex(255))   # 0xff
    print("Hex to Integer:", hex_to_int("0xff"))    # 255
    print("Integer to Binary:", int_to_bin(42)) # 0b101010
    print("Binary to Integer:", bin_to_int("0b101010")) # 42
    print("Integer to Octal:", int_to_oct(64))  # 0o100
    print("Octal to Integer:", oct_to_int("0o100")) # 64
    print("String to Integer:", str_to_int("ABCD")) # 1145258561
    print("Integer to String:", int_to_str(0x44434241))  # ABCD
    print("Bytes to Integer:", bytes_to_int(b'\x41\x42\x43\x44'))   # 1145258561
    print("Integer to Bytes:", int_to_bytes(0x44434241))    # b'ABCD'
    print("Hex to Bytes:", hex_to_bytes("41424344"))    # b'ABCD'
    print("Bytes to Hex:", bytes_to_hex(b"ABCD"))   # 41424344
    print("Binary to Bytes:", bin_to_bytes("0b01000001010000100100001101000100"))   # B'\x00ABCD'
    print("Bytes to Binary:", bytes_to_bin(b"ABCD"))    # 0b1000001010000100100001101000100
    