# Project for creating libc env via Docker images
pwnDockerAll: https://github.com/PIG-007/pwnDockerAll

# Custom function in xpl.py to attack GDB
Run with command:
```
dockerPwnRun [pwnfileDir] [docker_images_name] -g 30001
```
In exploit script:
```
def dockerDbg():
	myGdb = remote("127.0.0.1",30001)
	myGdb.close()
	pause()
```
