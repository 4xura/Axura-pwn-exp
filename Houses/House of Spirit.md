## Tcache

```py
fake_chunks[10]
fake_chunks[1] = 0x40
a = &fake_chunks[2]
free(a)
b = malloc(0x30)
```



