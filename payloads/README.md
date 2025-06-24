[toc]

## 🔧 Usage: Build and Dump Payload Binaries (`*.S`)

This project includes handcrafted assembly payloads (like `shell.S`, `dropper.S`) that need to be:

1. Assembled into raw binaries
2. Dumped into hex format for embedding (in `.S` or `.c`)

Below are the commands we’ll use **for both `shell.S` and `dropper.S`**, and what they do.

----

### 1. `nasm -f bin -o <output> <input.S>`

**Use it like:**

```bash
nasm -f bin -o payloads/shell payloads/shell.S
nasm -f bin -o payloads/dropper payloads/dropper.S
```

**What it does:**

* Compiles the `.S` file into a **raw binary** (not ELF object).
* `-f bin` → flat binary format (no linker, no sections).

**Use when:**

* We finish editing `shell.S` or `dropper.S` and want to compile it into a binary we can embed.

---

### 2. `hexdump -v -e '16/1 "0x%02x, " "\n"' <binary>`

**Use it like:**

```bash
hexdump -v -e '16/1 "0x%02x, " "\n"' shell
hexdump -v -e '16/1 "0x%02x, " "\n"' dropper
```

**What it does:**

* Dumps the binary as a list of `0x..` hex values.
* One line = 16 bytes.
* Use output in NASM like:

```nasm
sc: db 0x7f, 0x45, 0x4c, 0x46, ...
scLen: equ $ - sc
```

**Use when:**

* We want to embed the compiled binary bytes directly into `.S`.

----

### 3. `xxd -i <binary> > <output.h>`

**Use it like:**

```bash
# cd payloads
xxd -i shell > shell.h
xxd -i dropper > dropper.h
```

**What it does:**

* Converts a binary into a C-style array.
* Example output:

  ```c
  unsigned char dropper[] = { 0x7f, 0x45, ... };
  unsigned int dropper_len = 160;
  ```

**Use when:**

* We want to embed the binary in a C file instead of `.S`.
* Used in `fwrite(dropper, 1, dropper_len, fp);`.

---

### 4. Python one-liner

```bash
python3 -c 'print(", ".join(f"0x{b:02x}" for b in open("shell","rb").read()))'
```

Or:

```bash
python3 -c 'print(", ".join(f"0x{b:02x}" for b in open("dropper","rb").read()))'
```

**What it does:**

* Reads the binary and prints all bytes as a single line of `0x..` hex.

**Use when:**

* We want fast inline hex to paste into `db` in NASM.
* Useful for quick debug or replacing hardcoded `sc:` payloads.

---

## ✅ Examples: Full Workflow 

```bash
# cd payloads

# Assemble raw binary
nasm -f bin -o shell shell.S
nasm -f bin -o dropper dropper.S

# Dump to hex for NASM
hexdump -v -e '16/1 "0x%02x, " "\n"' shell > shell.hex
hexdump -v -e '16/1 "0x%02x, " "\n"' dropper > dropper.hex

# OR: Dump to C header
xxd -i shell > shell.h
xxd -i dropper > dropper.h
```

