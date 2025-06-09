### RISC-V (RV64I) shellcode

```
- execve("/bin/sh", NULL, NULL) 64 bytes shellcode
- execve("/usr/bin/cat", ["/usr/bin/cat", "/etc/passwd", NULL], NULL) 144 bytes shellcode
- chmod 0777 /etc/passwd 136 bytes shellcode
```
