## Project file structure

```c
project-root/
├── xpl.py              // Exploit script for userland pwn (Python)
│
├── xpl.c               // Kernel exploit entry point (C)
│
├── Makefile            // Build options: default, debug, static, release
│
├── include/                // Shared headers
│   └── xpl_utils.h         // Common macros & helpers (e.g., DIE(), hexdump(), etc.)
│   └── privesc.h           // Common macros & helpers (e.g., DIE(), hexdump(), etc.)
│   └── stack_overflow.h    // Common macros & helpers (e.g., DIE(), hexdump(), etc.)
│   └── ret2user.h          // Common macros & helpers (e.g., DIE(), hexdump(), etc.)
│
├── src/                // Modular exploit components (optional)
│   ├── (xpl.c)         // (Alternative) prefer to place main exploit script under src/
│   ├── privesc.c 
│   └── stack_overflow.c
│   └── ret2user.c
│
├── build/              // Auto-generated object files
│   ├── xpl.o           // From root xpl.c or src/xpl.c
│   ├── privesc.o        // From src/helper.c
│   └── ...            
│
├── scripts/                    // Helper automation and debugging scripts
│   ├── extract-image.sh        // Extract contents from kernel image (vmlinuz, bzImage, etc.)
│   ├── extract-initramfs.sh    // Unpack initramfs for modification or inspection
│   ├── comp-initramfs.sh       // Compile exploit binary and repackage it into initramfs.cpio.gz
│   ├── run-serial.sh           // Launch QEMU with serial terminal
│   ├── run-ret2user.sh         // Boot QEMU for ret2user-style kernel exploit testing\
│   └── patch-alarm.py          // Patch alarm syscall
│
├── xpl                 // Final compiled exploit binary
│
├── flag.txt            // Fake flags used for local testing
└── flag
```

### Userland pwn:

- **`xpl.py`**: Exploit script for userland challenges interfacing with `pwntools`, GDB, glibc, etc.

### Kernel pwn:

- **`xpl.c`**: This main exploit entry point (`main()`), typically crafted to trigger a vulnerability in a kernel module.
- **`include/xpl-utils.h`**: Centralized header for shared macros (`DIE()`, `SUCCESS()`), helper functions (`hexdump()`), etc.
- **`src/*.c`**: Optional for organizing auxiliary components here, e.g.:
  - `leaker.c` – leak kernel pointers
  - `payload.c` – ROP chain construction
  - `resolve.c` – parse `/proc/kallsyms` or gadget resolution
  - …
- **`build/`**: Auto-generated directory for `.o` files (one per `.c` file). Keeps root clean and build artifacts separated.
- **`Makefile`**: Flexible build system supporting different modes:
  - `make` – Default build for local testing (optimized, no debug info)
  - `make debug` – Adds debug symbols (`-g`) and disables optimizations (`-Og`) for easier GDB analysis
  - `make static` – Statically links everything (e.g., for isolated environments or remote kernel testing)
  - `make release` – Fully optimized and statically linked for final delivery or deployment
  - `make strip` – Removes symbol tables and debug info from the compiled binary
  - `make clean` – Cleans all generated artifacts

### Scripts

Suggest run scripts under project root directory, namely for example:

```sh
bash scripts/run-serial.sh
```

The `scripts/` folder contains utility scripts used to assist with compiling, extracting, and booting pwn lab environment:

- **`extract-image.sh`** – Extracts a raw disk image (e.g. `vmlinux`) for manual patching or inspection from a compressed kernel (e.g. `vmlinuz`).
- **`extract-initramfs.sh`** – Unpacks a gzipped `initramfs.cpio.gz` for manual modifications.
- **`comp-initramfs.sh`** – Compiles exploit (statically), moves it into the extracted `initramfs/`, and repacks it into `initramfs.cpio.gz`.
- **`run-serial.sh`** – Starts a QEMU guest with kernel serial output (good for debugging with `-nographic`).
- **`run-ret2user.sh`** – Starts a preconfigured QEMU instance for local kernel ret2usr-style exploitation.
- **`patch-alarm.py`** – Custom patch ELF script to bypass the annoying alarm syscall for debugging.

