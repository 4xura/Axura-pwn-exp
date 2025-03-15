[toc]

**Blog: https://4xura.com/pwn/pwn-heap-exploitation-house-of-banana/**

## **struct** **rtld_global**

There's a pointer inside `ld.so` pointing to this structure `rtld_global`:

```c
struct rtld_global
{
#endif
  /* Don't change the order of the following elements.  'dl_loaded'
     must remain the first element.  Forever.  */

/* Non-shared code has no support for multiple namespaces.  */
#ifdef SHARED
# define DL_NNS 16
#else
# define DL_NNS 1
#endif
  EXTERN struct link_namespaces
  {
    /* A pointer to the map for the main map.  */
    struct link_map *_ns_loaded;
    /* Number of object in the _dl_loaded list.  */
    unsigned int _ns_nloaded;
    /* Direct pointer to the searchlist of the main object.  */
    struct r_scope_elem *_ns_main_searchlist;
    /* This is zero at program start to signal that the global scope map is
       allocated by rtld.  Later it keeps the size of the map.  It might be
       reset if in _dl_close if the last global object is removed.  */
    unsigned int _ns_global_scope_alloc;

    /* During dlopen, this is the number of objects that still need to
       be added to the global scope map.  It has to be taken into
       account when resizing the map, for future map additions after
       recursive dlopen calls from ELF constructors.  */
    unsigned int _ns_global_scope_pending_adds;

    /* Once libc.so has been loaded into the namespace, this points to
       its link map.  */
    struct link_map *libc_map;

    /* Search table for unique objects.  */
    struct unique_sym_table
    {
      __rtld_lock_define_recursive (, lock)
      struct unique_sym
      {
    uint32_t hashval;
    const char *name;
    const ElfW(Sym) *sym;
    const struct link_map *map;
      } *entries;
      size_t size;
      size_t n_elements;
      void (*free) (void *);
    } _ns_unique_sym_table;
    /* Keep track of changes to each namespace' list.  */
    struct r_debug _ns_debug;
  } _dl_ns[DL_NNS];
  /* One higher than index of last used namespace.  */
  EXTERN size_t _dl_nns;

  ...
      
};
```























https://www.anquanke.com/post/id/222948

https://xz.aliyun.com/t/15256?time__1311=GqjxnD0D2GYYqGNeWxU2xRxQTKw%3DKqDcioD