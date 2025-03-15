## struct malloc_state

```c
/* offset      |   size */  type = struct malloc_state {
/*   0x000     |   0x04 */    __libc_lock_t mutex;               
/*   0x004     |   0x04 */    int flags;                        
/*   0x008     |   0x04 */    int have_fastchunks;              
/*   0x00C     |   0x04 */    (4-byte hole due to alignment)    
/*   0x010     |   0x50 */    mfastbinptr fastbinsY[10];        // 10 fast bins
/*   0x060     |   0x08 */    mchunkptr top;                    
/*   0x068     |   0x08 */    mchunkptr last_remainder;         
/*   0x070     |  0x7F0 */    mchunkptr bins[254];              // 2032 bytes (254 bins)
/*   0x860     |   0x10 */    unsigned int binmap[4];           // 16 bytes (binmap)
/*   0x870     |   0x08 */    struct malloc_state *next;        // next arena
/*   0x878     |   0x08 */    struct malloc_state *next_free;   // next free arena
/*   0x880     |   0x08 */    size_t attached_threads;          // attached threads
/*   0x888     |   0x08 */    size_t system_mem;                // total system memory
/*   0x890     |   0x08 */    size_t max_system_mem;            // max system memory
                              /* Total size: 0x898 bytes (2200 decimal) */
};
```

## Arena

```
# arena
# p &main_arena
p *(struct malloc_state *)&main_arena
```

## Bin[254]

The `bins` array begins at offset `0x70` in the `malloc_state` structure.

| **Bin Type**     | **Bin Index** | **bins[254] Range**       |
| ---------------- | ------------- | ------------------------- |
| **Unsorted bin** | 1             | `bins[0]` - `bins[1]`     |
| **Small bins**   | 2 - 63        | `bins[2]` - `bins[63]`    |
| **Large bins**   | 64 - 126      | `bins[127]` - `bins[253]` |

### Clarification:

- **Unsorted bin**: Index 1 corresponds to `bins[0]` and `bins[1]`.
- **Small bins**: 
  - **Bin 2** handles 32-byte chunks.
  - **Bin 3** handles 48-byte chunks, and so on up to **Bin 63**, which handles 1008-byte
  - The formula for small bin index is: `index = size >> 4`
- **Large bins**: 
  - **Bin 64** starts at chunks of size 1024 bytes and the bins increase in size by powers of 2, with each bin managing chunks of increasing sizes.

**Constants:**

1. **`SIZE_SZ = 8`**: The size of the `size_t` type in bytes, which represents the size of a memory chunk.
2. **`MALLOC_ALIGNMENT = 16`**: The alignment of allocated chunks in memory.
3. **`MIN_CHUNK_SIZE = 32`**: The smallest chunk size allowed in the heap (including metadata).
4. **`MINSIZE = 32`**: The minimum size a chunk can be, due to alignment and metadata requirements.
5. **`NBINS = 128`**: The total number of bins (including small and large bins).
6. **`NSMALLBINS = 64`**: The number of small bins (these manage smaller chunks of fixed size).
7. **`SMALLBIN_WIDTH = 16`**: The width or granularity of small bins; each small bin handles chunks in increments of 16 bytes.
8. **`MIN_LARGE_SIZE = 1024`**: The minimum chunk size managed by large bins.

### Unsorted bin

```
p main_arena.bins[0]	<main_arena+96
p main_arena.bins[1]	<main_arena+96
```

### Large bin

1st Largebin:

```
p main_arena.bins[126]
p main_arena.bins[127]
```


